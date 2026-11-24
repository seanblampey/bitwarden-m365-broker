import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export interface ApprovalRequest {
  tenant: string;
  account: string;
  action: string;
}

export type PsScriptRunner = (
  scriptPath: string,
  stdin: string,
) => Promise<{ code: number; stdout: string }>;

const PS_ARGS = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File'];

/** Default runner: no timeout (user may take their time); stdio piped, stdin written then closed. */
export const defaultPsRunner: PsScriptRunner = (scriptPath, stdin) =>
  new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', [...PS_ARGS, scriptPath], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const out: Buffer[] = [];
    child.stdout.on('data', (d: Buffer) => out.push(d));
    child.stderr.on('data', () => {}); // drain; never surfaced
    child.stdin.on('error', () => {}); // child may exit before reading
    child.on('error', () => resolve({ code: -1, stdout: '' })); // cannot spawn powershell.exe
    child.on('close', (code) =>
      resolve({ code: code ?? -1, stdout: Buffer.concat(out).toString('utf8') }),
    );
    child.stdin.end(stdin, 'utf8');
  });

function scriptPath(name: string): string {
  return fileURLToPath(new URL(`./${name}`, import.meta.url));
}

async function safeRun(run: PsScriptRunner, path: string, stdin: string): Promise<{ code: number; stdout: string }> {
  try {
    return await run(path, stdin);
  } catch {
    return { code: -1, stdout: '' };
  }
}

function warn(code: number): void {
  process.stderr.write(`dialog script exited with unexpected code ${code}\n`);
}

/** Returns the password, or null if cancelled or the dialog failed. */
export async function promptPassword(run: PsScriptRunner = defaultPsRunner): Promise<string | null> {
  const { code, stdout } = await safeRun(run, scriptPath('password.ps1'), '');
  if (code === 0) {
    const pw = stdout.replace(/[\r\n]+$/, '');
    return pw === '' ? null : pw;
  }
  if (code !== 1) warn(code);
  return null;
}

/** Returns true only if the user explicitly chose Yes. */
export async function confirmAction(
  req: ApprovalRequest,
  run: PsScriptRunner = defaultPsRunner,
): Promise<boolean> {
  const { code } = await safeRun(run, scriptPath('confirm.ps1'), JSON.stringify(req));
  if (code === 0) return true;
  if (code !== 1) warn(code);
  return false;
}
