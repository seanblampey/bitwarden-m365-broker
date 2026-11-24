import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import {
  promptPassword,
  confirmAction,
  createPsRunner,
  runDialog,
  PS_ARGS,
  DIALOG_TIMEOUT_MS,
  type PsScriptRunner,
} from '../src/win/dialogs.js';
import { BrokerError } from '../src/errors.js';

const req = { tenant: 'contoso.com', account: 'admin', action: 'POST /users' };

async function dialogFailed(p: Promise<unknown>): Promise<void> {
  const e = await p.then(() => { throw new Error('expected failure'); }, (err: unknown) => err);
  expect(e).toBeInstanceOf(BrokerError);
  expect((e as BrokerError).code).toBe('dialog_failed');
  expect((e as BrokerError).message).toBe('The Windows dialog could not be shown or timed out.');
}

describe('confirmAction', () => {
  it('passes the request as JSON on stdin; exit 0 -> true', async () => {
    let stdin = '';
    let script = '';
    const run: PsScriptRunner = async (p, s) => { script = p; stdin = s; return { code: 0, stdout: '' }; };
    expect(await confirmAction(req, run)).toBe(true);
    expect(JSON.parse(stdin)).toEqual(req);
    expect(script.endsWith('confirm.ps1')).toBe(true);
  });
  it('exit 1 -> false', async () => {
    expect(await confirmAction(req, async () => ({ code: 1, stdout: '' }))).toBe(false);
  });
  it('timeout -> false', async () => {
    expect(await confirmAction(req, async () => ({ code: -1, stdout: '', timedOut: true }))).toBe(false);
  });
  it('runner rejection -> dialog_failed', async () => {
    await dialogFailed(confirmAction(req, async () => { throw new Error('spawn'); }));
  });
  it('unexpected exit code -> dialog_failed', async () => {
    await dialogFailed(confirmAction(req, async () => ({ code: 2, stdout: '' })));
    await dialogFailed(confirmAction(req, async () => ({ code: -1, stdout: '' })));
  });
});

describe('promptPassword', () => {
  it('exit 1 -> null', async () => {
    expect(await promptPassword(async () => ({ code: 1, stdout: '' }))).toBeNull();
  });
  it('exit 0 -> stdout with trailing CR/LF trimmed', async () => {
    expect(await promptPassword(async () => ({ code: 0, stdout: 'p w\r\n' }))).toBe('p w');
  });
  it('empty password -> null', async () => {
    expect(await promptPassword(async () => ({ code: 0, stdout: '\r\n' }))).toBeNull();
  });
  it('runner rejection -> dialog_failed', async () => {
    await dialogFailed(promptPassword(async () => { throw new Error('spawn'); }));
  });
  it('unexpected exit code -> dialog_failed', async () => {
    await dialogFailed(promptPassword(async () => ({ code: 9, stdout: 'x' })));
  });
  it('timeout -> dialog_failed', async () => {
    await dialogFailed(promptPassword(async () => ({ code: -1, stdout: '', timedOut: true })));
  });
});

describe('runDialog', () => {
  it('distinguishes ok, cancelled, failed and timeout', async () => {
    expect(await runDialog(async () => ({ code: 0, stdout: 'x' }), 'p', '')).toEqual({ kind: 'ok', stdout: 'x' });
    expect(await runDialog(async () => ({ code: 1, stdout: '' }), 'p', '')).toEqual({ kind: 'cancelled' });
    expect(await runDialog(async () => ({ code: 2, stdout: '' }), 'p', '')).toEqual({ kind: 'failed', code: 2 });
    expect(await runDialog(async () => ({ code: 0, stdout: '', timedOut: true }), 'p', '')).toEqual({ kind: 'timeout' });
  });
});

describe('createPsRunner', () => {
  // The script path is appended after `-e <code>`, so node just ignores it.
  const node = (code: string, timeoutMs: number) => createPsRunner({ command: process.execPath, args: ['-e', code], timeoutMs });

  it('kills a dialog that does not answer within the timeout', async () => {
    const started = Date.now();
    const r = await node('setTimeout(() => {}, 60000)', 300)('script.ps1', '');
    expect(r.timedOut).toBe(true);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('passes stdin and returns exit code and stdout', async () => {
    const code = "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{process.stdout.write(s.toUpperCase());process.exit(1);});";
    expect(await node(code, 10_000)('script.ps1', 'abc')).toEqual({ code: 1, stdout: 'ABC' });
  });

  it('reports a command that cannot be spawned as code -1 (not a timeout)', async () => {
    const r = await createPsRunner({ command: 'definitely-not-a-real-command-xyz', args: [], timeoutMs: 10_000 })('x', '');
    expect(r).toEqual({ code: -1, stdout: '' });
  });

  it('default runner: 5-minute timeout, console hidden but windowsHide off', () => {
    expect(DIALOG_TIMEOUT_MS).toBe(5 * 60_000);
    const i = PS_ARGS.indexOf('-WindowStyle');
    expect(i).toBeGreaterThanOrEqual(0);
    expect(PS_ARGS[i + 1]).toBe('Hidden');
    expect(PS_ARGS[PS_ARGS.length - 1]).toBe('-File');
    const src = readFileSync(new URL('../src/win/dialogs.ts', import.meta.url), 'utf8');
    expect(src).toContain('windowsHide: false');
    expect(src).not.toContain('windowsHide: true');
  });
});

describe('scripts', () => {
  it('exist in src/win; confirm.ps1 defaults to Button2', () => {
    const dir = new URL('../src/win/', import.meta.url);
    expect(existsSync(new URL('password.ps1', dir))).toBe(true);
    expect(readFileSync(new URL('confirm.ps1', dir), 'utf8')).toContain('Button2');
  });
  it('confirm.ps1 never truncates the action and refuses (exit 2) anything over 1600 characters', () => {
    const src = readFileSync(new URL('../src/win/confirm.ps1', import.meta.url), 'utf8');
    expect(src).not.toMatch(/Substring/i);
    expect(src).not.toContain("'...'");
    expect(src).toMatch(/if \(\$action\.Length -gt 1600\) \{ exit 2 \}/);
  });
  it('password.ps1 brings the form to the front and focuses the box when shown', () => {
    const src = readFileSync(new URL('../src/win/password.ps1', import.meta.url), 'utf8');
    const shown = /\$form\.Add_Shown\(\{([^}]*)\}\)/.exec(src)?.[1] ?? '';
    for (const step of ['$form.TopMost = $true', '$form.Activate()', '$form.BringToFront()', '$box.Focus()']) {
      expect(shown).toContain(step);
    }
  });
});
