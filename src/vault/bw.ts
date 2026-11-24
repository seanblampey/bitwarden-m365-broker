import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { delimiter, join } from 'node:path';
import { BrokerError } from '../errors.js';
import { Redactor } from '../redact.js';

export type Runner = (
  args: string[],
  env: Record<string, string>,
) => Promise<{ code: number; stdout: string; stderr: string }>;

export interface BwItem {
  id: string;
  name: string;
  login?: { username?: string; password?: string; totp?: string };
  fields?: { name: string; value: string }[];
}

const MAX_ERROR_LENGTH = 500;
const TIMEOUT_MS = 60_000;
const NO_INTERACTION = '--nointeraction';
const UNEXPECTED = 'Bitwarden CLI returned unexpected output.';

/** Finds bw.exe, then bw.cmd, on PATH (Windows only). */
function resolveWindowsBw(env: NodeJS.ProcessEnv): string | null {
  const dirs = (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean);
  for (const name of ['bw.exe', 'bw.cmd']) {
    for (const dir of dirs) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
  }
  return null;
}

function quoteCmdArg(arg: string): string {
  return `"${arg.replace(/"/g, '""')}"`;
}

export const nodeRunner: Runner = (args, env) =>
  new Promise((resolve, reject) => {
    const fullEnv = { ...process.env, ...env };
    let command = 'bw';
    let spawnArgs = args;
    const options: Parameters<typeof spawn>[2] = {
      env: fullEnv,
      shell: false,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    };
    if (process.platform === 'win32') {
      const resolved = resolveWindowsBw(fullEnv);
      if (resolved) command = resolved;
      if (command.toLowerCase().endsWith('.cmd')) {
        // .cmd files cannot be spawned directly; no secret is ever in args.
        spawnArgs = ['/d', '/s', '/c', `"${[command, ...args].map(quoteCmdArg).join(' ')}"`];
        command = process.env.ComSpec ?? 'cmd.exe';
        options.windowsVerbatimArguments = true;
      }
    }
    const child = spawn(command, spawnArgs, options);
    let stdout = '';
    let stderr = '';
    child.stdout?.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr?.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    const timer = setTimeout(() => {
      child.kill();
      reject(new BrokerError('bw_failed', 'Bitwarden CLI timed out.'));
    }, TIMEOUT_MS);
    child.on('error', (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(
        e.code === 'ENOENT'
          ? new BrokerError('bw_not_found', 'Bitwarden CLI (bw) was not found on PATH.')
          : new BrokerError('bw_failed', 'Could not start the Bitwarden CLI.'),
      );
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout, stderr });
    });
  });

export class BwClient {
  constructor(private readonly run: Runner) {}

  async status(): Promise<'unauthenticated' | 'locked' | 'unlocked'> {
    const r = await this.exec(['status'], {}, []);
    const parsed = parseJson(r.stdout);
    const status = (parsed as { status?: unknown } | null)?.status;
    if (status === 'unauthenticated' || status === 'locked' || status === 'unlocked') return status;
    throw new BrokerError('bw_failed', UNEXPECTED);
  }

  async unlock(masterPassword: string): Promise<string> {
    const r = await this.run(['unlock', '--passwordenv', 'BW_BROKER_MASTER', '--raw', NO_INTERACTION], {
      BW_BROKER_MASTER: masterPassword,
    });
    if (r.code !== 0) {
      if (/invalid master password/i.test(r.stderr)) {
        throw new BrokerError('wrong_master_password', 'Bitwarden rejected the master password.');
      }
      throw failure(r.stderr, [masterPassword]);
    }
    const session = r.stdout.trim();
    if (!session) throw new BrokerError('bw_failed', UNEXPECTED);
    return session;
  }

  async sync(session: string): Promise<void> {
    await this.exec(['sync'], { BW_SESSION: session }, [session]);
  }

  async folderId(session: string, name: string): Promise<string | null> {
    const r = await this.exec(['list', 'folders', '--search', name], { BW_SESSION: session }, [session]);
    const folders = parseJson(r.stdout);
    if (!Array.isArray(folders)) throw new BrokerError('bw_failed', UNEXPECTED);
    const match = folders.find(
      (f): f is { id: string; name: string } =>
        !!f && typeof f === 'object' && f.name === name && typeof f.id === 'string',
    );
    return match ? match.id : null;
  }

  async listItems(session: string, folderId: string): Promise<BwItem[]> {
    const r = await this.exec(['list', 'items', '--folderid', folderId], { BW_SESSION: session }, [session]);
    const items = parseJson(r.stdout);
    if (!Array.isArray(items)) throw new BrokerError('bw_failed', UNEXPECTED);
    return items as BwItem[];
  }

  async lock(): Promise<void> {
    await this.exec(['lock'], {}, []);
  }

  private async exec(args: string[], env: Record<string, string>, secrets: string[]) {
    const r = await this.run([...args, NO_INTERACTION], env);
    if (r.code !== 0) throw failure(r.stderr, secrets);
    return r;
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new BrokerError('bw_failed', UNEXPECTED);
  }
}

function failure(stderr: string, secrets: string[]): BrokerError {
  const redactor = new Redactor();
  for (const s of secrets) redactor.add(s);
  const clean = redactor.scrub(stderr).trim().slice(0, MAX_ERROR_LENGTH);
  return new BrokerError('bw_failed', clean || 'Bitwarden CLI failed.');
}
