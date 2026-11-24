import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { promptPassword, confirmAction, type PsScriptRunner } from '../src/win/dialogs.js';

const req = { tenant: 'contoso.com', account: 'admin', action: 'POST /users' };

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
  it('unexpected exit code -> false', async () => {
    expect(await confirmAction(req, async () => ({ code: 5, stdout: '' }))).toBe(false);
  });
});

describe('promptPassword', () => {
  it('exit 1 -> null', async () => {
    expect(await promptPassword(async () => ({ code: 1, stdout: '' }))).toBeNull();
  });
  it('exit 0 -> stdout with trailing CR/LF trimmed', async () => {
    expect(await promptPassword(async () => ({ code: 0, stdout: 'p w\r\n' }))).toBe('p w');
  });
  it('unexpected exit code -> null', async () => {
    expect(await promptPassword(async () => ({ code: 9, stdout: 'x' }))).toBeNull();
  });
});

describe('scripts', () => {
  it('exist in src/win; confirm.ps1 defaults to Button2', () => {
    const dir = new URL('../src/win/', import.meta.url);
    expect(existsSync(new URL('password.ps1', dir))).toBe(true);
    expect(readFileSync(new URL('confirm.ps1', dir), 'utf8')).toContain('Button2');
  });
});
