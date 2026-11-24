import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BrokerError } from './errors.js';
import { validateCmdlet, validateParameters } from './classify.js';
import { Redactor } from './redact.js';

export type PsRunner = (stdin: string) => Promise<{ code: number; stdout: string; stderr: string }>;

export interface CmdletArgs {
  token: string;
  upn: string;
  organization: string;
  cmdlet: string;
  parameters: Record<string, unknown>;
}

const TIMEOUT_MS = 5 * 60 * 1000;
const MAX_ERROR = 1000;

export function defaultPsRunner(): PsRunner {
  const script = fileURLToPath(new URL('./exo/run-cmdlet.ps1', import.meta.url));
  return (stdin) =>
    new Promise((resolve, reject) => {
      const child = spawn(
        'powershell.exe',
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
      child.on('error', (e) => {
        clearTimeout(timer);
        if (!done) { done = true; reject(e); }
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

const UNEXPECTED = 'Exchange Online PowerShell failed unexpectedly.';

function parseEnvelope(stdout: string): { ok: boolean; result?: unknown; error?: unknown } | undefined {
  const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const v: unknown = JSON.parse(lines[i]);
      if (v && typeof v === 'object' && typeof (v as { ok?: unknown }).ok === 'boolean') {
        return v as { ok: boolean; result?: unknown; error?: unknown };
      }
    } catch { /* try previous line */ }
  }
  return undefined;
}

const FORBIDDEN_COMMON = new Set([
  'erroraction', 'errorvariable', 'warningaction', 'warningvariable', 'informationaction',
  'informationvariable', 'outvariable', 'outbuffer', 'pipelinevariable',
  // The broker's dialog is the confirmation; run-cmdlet.ps1 sets Confirm:$false itself. WhatIf stays allowed.
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

export async function runCmdlet(run: PsRunner, args: CmdletArgs): Promise<unknown> {
  validateCmdlet(args.cmdlet);
  const parameters = validateParameters(args.parameters);
  assertNoForbiddenCommon(parameters);
  let out: { code: number; stdout: string; stderr: string };
  try {
    out = await run(JSON.stringify({ ...args, parameters }));
  } catch {
    throw new BrokerError('exo_failed', UNEXPECTED);
  }
  const env = parseEnvelope(out.stdout);
  if (!env) throw new BrokerError('exo_failed', UNEXPECTED);
  if (!env.ok) {
    const redactor = new Redactor();
    redactor.add(args.token);
    const text = typeof env.error === 'string' && env.error ? env.error : 'Exchange Online command failed.';
    throw new BrokerError('exo_failed', redactor.scrub(text).slice(0, MAX_ERROR));
  }
  return env.result ?? null;
}
