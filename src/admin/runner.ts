import { spawn } from 'node:child_process';
import { assetPath } from '../assets.js';
import { BrokerError } from '../errors.js';
import { validateCmdlet, validateParameters } from '../classify.js';
import { Redactor } from '../redact.js';
import type { Service, Shell } from './services.js';

/** Runs the admin script in the given shell with the request on stdin (tokens never go on a command line). */
export type PsRunner = (shell: Shell, stdin: string) => Promise<{ code: number; stdout: string; stderr: string }>;

export interface AdminCmdletArgs {
  service: Service;
  shell: Shell;
  /** The token the service's connect cmdlet takes. */
  token: string;
  /** Teams only: the Graph token passed alongside. */
  graphToken?: string;
  upn: string;
  organization: string;
  /** SharePoint only: the site to connect to. */
  url?: string;
  cmdlet: string;
  parameters: Record<string, unknown>;
  select?: string[];
  first?: number;
}

export interface AdminCmdletResult {
  result: unknown;
  /** How many items the cmdlet returned before the script kept the first few. */
  total?: number;
  note?: string;
}

const TIMEOUT_MS = 5 * 60 * 1000;
const MAX_ERROR = 1000;
const EXE: Record<Shell, string> = { powershell: 'powershell.exe', pwsh: 'pwsh.exe' };
const NO_PWSH = 'PowerShell 7 (pwsh) is not installed, and SharePoint needs it. Install it yourself: winget install Microsoft.PowerShell';

export function defaultPsRunner(): PsRunner {
  const script = assetPath('admin/run-admin-cmdlet.ps1');
  return (shell, stdin) =>
    new Promise((resolve, reject) => {
      const child = spawn(
        EXE[shell],
        ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      let stdout = '';
      let stderr = '';
      let done = false;
      const timer = setTimeout(() => {
        child.kill();
        if (!done) { done = true; reject(new Error('timeout')); }
      }, TIMEOUT_MS);
      child.stdout.setEncoding('utf8').on('data', (d: string) => { stdout += d; });
      child.stderr.setEncoding('utf8').on('data', (d: string) => { stderr += d; });
      child.on('error', (e: NodeJS.ErrnoException) => {
        clearTimeout(timer);
        if (done) return;
        done = true;
        reject(shell === 'pwsh' && e.code === 'ENOENT' ? new BrokerError('module_missing', NO_PWSH) : e);
      });
      child.on('close', (code) => {
        clearTimeout(timer);
        if (!done) { done = true; resolve({ code: code ?? 1, stdout, stderr }); }
      });
      child.stdin.on('error', () => { /* process exited early */ });
      child.stdin.write(stdin);
      child.stdin.end();
    });
}

const UNEXPECTED = 'The PowerShell command failed unexpectedly.';

interface Envelope { ok: boolean; result?: unknown; total?: unknown; note?: unknown; error?: unknown; code?: unknown }

function parseEnvelope(stdout: string): Envelope | undefined {
  const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const v: unknown = JSON.parse(lines[i]!);
      if (v && typeof v === 'object' && typeof (v as { ok?: unknown }).ok === 'boolean') return v as Envelope;
    } catch { /* try previous line */ }
  }
  return undefined;
}

const FORBIDDEN_COMMON = new Set([
  'erroraction', 'errorvariable', 'warningaction', 'warningvariable', 'informationaction',
  'informationvariable', 'outvariable', 'outbuffer', 'pipelinevariable',
  // The broker's dialog is the confirmation; the script sets Confirm:$false itself. WhatIf stays allowed.
  'confirm',
]);

/** Rejects PowerShell common parameters that would redirect output or errors, and Confirm (the broker owns it). */
export function assertNoForbiddenCommon(parameters: Record<string, unknown>): void {
  for (const k of Object.keys(parameters)) {
    if (FORBIDDEN_COMMON.has(k.toLowerCase())) {
      throw new BrokerError('invalid_parameters', `Invalid parameters: ${k} is not allowed`);
    }
  }
}

/** Error codes the script may report itself; anything else is a plain cmdlet failure. */
const SCRIPT_CODES = new Set(['module_missing']);

export async function runAdminCmdlet(run: PsRunner, args: AdminCmdletArgs): Promise<AdminCmdletResult> {
  validateCmdlet(args.cmdlet);
  const parameters = validateParameters(args.parameters);
  assertNoForbiddenCommon(parameters);
  const { shell, ...request } = args;
  let out: { code: number; stdout: string; stderr: string };
  try {
    out = await run(shell, JSON.stringify({ ...request, parameters }));
  } catch (e) {
    if (e instanceof BrokerError) throw e;
    throw new BrokerError('cmdlet_failed', UNEXPECTED);
  }
  const env = parseEnvelope(out.stdout);
  if (!env) throw new BrokerError('cmdlet_failed', UNEXPECTED);
  if (!env.ok) {
    const redactor = new Redactor();
    redactor.add(args.token);
    redactor.add(args.graphToken);
    const text = typeof env.error === 'string' && env.error ? env.error : 'The command failed.';
    const code = typeof env.code === 'string' && SCRIPT_CODES.has(env.code) ? env.code : 'cmdlet_failed';
    throw new BrokerError(code, redactor.scrub(text).slice(0, MAX_ERROR));
  }
  return {
    result: env.result ?? null,
    ...(typeof env.total === 'number' ? { total: env.total } : {}),
    ...(typeof env.note === 'string' ? { note: env.note.slice(0, 300) } : {}),
  };
}
