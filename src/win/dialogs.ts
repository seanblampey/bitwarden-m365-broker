import { spawn } from 'node:child_process';
import { assetPath } from '../assets.js';
import { BrokerError } from '../errors.js';

export interface ApprovalRequest {
  tenant: string;
  account: string;
  action: string;
}

/** `timedOut` is set when the runner killed the dialog because nobody answered in time. */
export type PsScriptRunner = (
  scriptPath: string,
  stdin: string,
) => Promise<{ code: number; stdout: string; timedOut?: boolean }>;

/** How long a dialog may stay open before it is closed and treated as a failure (password) or No (confirm). */
export const DIALOG_TIMEOUT_MS = 5 * 60_000;

// -WindowStyle Hidden hides the console window only. windowsHide must stay false: Node maps it to
// SW_HIDE, which Windows applies to the process's first ShowWindow call (the WinForms dialog).
export const PS_ARGS = ['-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass', '-File'];

export interface PsSpawnSpec {
  command: string;
  args: string[];
  timeoutMs: number;
}

/** Spawns the dialog script with stdio piped (stdin written then closed) and kills it after `timeoutMs`. */
export function createPsRunner(spec: PsSpawnSpec): PsScriptRunner {
  return (scriptPath, stdin) =>
    new Promise((resolve) => {
      let settled = false;
      const finish = (r: { code: number; stdout: string; timedOut?: boolean }) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(r);
      };
      const child = spawn(spec.command, [...spec.args, scriptPath], {
        windowsHide: false,
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      const timer = setTimeout(() => {
        child.kill();
        finish({ code: -1, stdout: '', timedOut: true });
      }, spec.timeoutMs);
      const out: Buffer[] = [];
      child.stdout.on('data', (d: Buffer) => out.push(d));
      child.stderr.on('data', () => {}); // drain; never surfaced
      child.stdin.on('error', () => {}); // child may exit before reading
      child.on('error', () => finish({ code: -1, stdout: '' })); // cannot spawn
      child.on('close', (code) => finish({ code: code ?? -1, stdout: Buffer.concat(out).toString('utf8') }));
      child.stdin.end(stdin, 'utf8');
    });
}

export const defaultPsRunner: PsScriptRunner = createPsRunner({
  command: 'powershell.exe',
  args: PS_ARGS,
  timeoutMs: DIALOG_TIMEOUT_MS,
});

function scriptPath(name: string): string {
  return assetPath(`win/${name}`);
}

export type DialogOutcome =
  | { kind: 'ok'; stdout: string }
  | { kind: 'cancelled' }
  | { kind: 'failed'; code: number }
  | { kind: 'timeout' };

/** Runs a dialog script; exit 0 = OK/Yes, 1 = Cancel/No, anything else (or a throw) = failed. */
export async function runDialog(run: PsScriptRunner, path: string, stdin: string): Promise<DialogOutcome> {
  let r: { code: number; stdout: string; timedOut?: boolean };
  try {
    r = await run(path, stdin);
  } catch {
    return { kind: 'failed', code: -1 };
  }
  if (r.timedOut) return { kind: 'timeout' };
  if (r.code === 0) return { kind: 'ok', stdout: r.stdout };
  if (r.code === 1) return { kind: 'cancelled' };
  return { kind: 'failed', code: r.code };
}

function dialogFailed(o: DialogOutcome): BrokerError {
  if (o.kind === 'failed') process.stderr.write(`dialog script exited with unexpected code ${o.code}\n`);
  return new BrokerError('dialog_failed', 'The Windows dialog could not be shown or timed out.');
}

/**
 * Returns the password, or null if the user cancelled (or entered nothing).
 * Throws BrokerError('dialog_failed') if the dialog could not be shown or timed out.
 */
export async function promptPassword(run: PsScriptRunner = defaultPsRunner): Promise<string | null> {
  const o = await runDialog(run, scriptPath('password.ps1'), '');
  if (o.kind === 'ok') {
    const pw = o.stdout.replace(/[\r\n]+$/, '');
    return pw === '' ? null : pw;
  }
  if (o.kind === 'cancelled') return null;
  throw dialogFailed(o);
}

/**
 * Returns true only if the user explicitly chose Yes; false for No or no answer within the timeout.
 * Throws BrokerError('dialog_failed') if the dialog could not be shown.
 */
export async function confirmAction(
  req: ApprovalRequest,
  run: PsScriptRunner = defaultPsRunner,
): Promise<boolean> {
  const o = await runDialog(run, scriptPath('confirm.ps1'), JSON.stringify(req));
  if (o.kind === 'ok') return true;
  if (o.kind === 'cancelled' || o.kind === 'timeout') return false;
  throw dialogFailed(o);
}
