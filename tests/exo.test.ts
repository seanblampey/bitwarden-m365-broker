import { describe, it, expect, vi } from 'vitest';
import { spawnSync } from 'node:child_process';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCmdlet, type PsRunner } from '../src/exo.js';

const base = { token: 'SECRETTOKEN123', upn: 'a@b.com', organization: 'b.com', cmdlet: 'Get-Mailbox', parameters: { Identity: 'x' } };
const runner = (stdout: string, code = 0): PsRunner => vi.fn(async () => ({ code, stdout, stderr: 'stderr secret' }));

describe('runCmdlet', () => {
  it('rejects invalid cmdlets and parameters before running', async () => {
    const r = runner('{}');
    await expect(runCmdlet(r, { ...base, cmdlet: 'rm -rf' })).rejects.toMatchObject({ code: 'invalid_cmdlet' });
    await expect(runCmdlet(r, { ...base, parameters: { 'a b': 1 } })).rejects.toMatchObject({ code: 'invalid_parameters' });
    expect(r).not.toHaveBeenCalled();
  });
  it('passes the token on stdin and returns the result', async () => {
    const r = runner('{"ok":true,"result":{"n":1}}');
    expect(await runCmdlet(r, base)).toEqual({ n: 1 });
    const stdin = (r as unknown as { mock: { calls: string[][] } }).mock.calls[0][0];
    expect(JSON.parse(stdin)).toMatchObject({ token: 'SECRETTOKEN123', cmdlet: 'Get-Mailbox' });
  });
  it('scrubs and truncates errors', async () => {
    const err = 'bad eyJa.b.c and SECRETTOKEN123 ' + 'z'.repeat(2000);
    const r = runner(JSON.stringify({ ok: false, error: err }));
    const e = await runCmdlet(r, base).catch((x) => x);
    expect(e.code).toBe('exo_failed');
    expect(e.message).not.toContain('eyJa.b.c');
    expect(e.message).not.toContain('SECRETTOKEN123');
    expect(e.message.length).toBeLessThanOrEqual(1000);
  });
  it('scrubs a JWT straddling the truncation point', async () => {
    const jwt = 'eyJhbGciOi.abcdefghijklmnop.sig123456';
    const err = 'a'.repeat(990) + jwt;
    const e = await runCmdlet(runner(JSON.stringify({ ok: false, error: err })), base).catch((x) => x);
    expect(e.message).not.toContain('eyJ');
    expect(e.message.length).toBeLessThanOrEqual(1000);
  });
  it('rejects caller-supplied common parameters before running', async () => {
    const r = runner('{}');
    for (const k of ['ErrorAction', 'errorvariable', 'WarningAction', 'WarningVariable', 'InformationAction', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable']) {
      await expect(runCmdlet(r, { ...base, parameters: { [k]: 'x' } })).rejects.toMatchObject({ code: 'invalid_parameters' });
    }
    expect(r).not.toHaveBeenCalled();
  });
  it('rejects a caller-supplied Confirm but allows WhatIf', async () => {
    const r = runner(JSON.stringify({ ok: true, result: null }));
    for (const k of ['Confirm', 'confirm', 'CONFIRM']) {
      await expect(runCmdlet(r, { ...base, cmdlet: 'Remove-InboxRule', parameters: { Identity: 'x', [k]: false } }))
        .rejects.toMatchObject({ code: 'invalid_parameters', message: `Invalid parameters: ${k} is not allowed` });
    }
    expect(r).not.toHaveBeenCalled();
    await expect(runCmdlet(r, { ...base, cmdlet: 'Remove-InboxRule', parameters: { Identity: 'x', WhatIf: true } })).resolves.toBeNull();
    expect(r).toHaveBeenCalledOnce();
  });
  it('maps garbage output / crashes to a generic error without stderr', async () => {
    for (const r of [runner('not json'), runner('', 1), (async () => { throw new Error('x'); }) as PsRunner]) {
      await expect(runCmdlet(r, base)).rejects.toMatchObject({ code: 'exo_failed', message: 'Exchange Online PowerShell failed unexpectedly.' });
    }
  });
});

describe('run-cmdlet.ps1', () => {
  const path = new URL('../src/exo/run-cmdlet.ps1', import.meta.url);
  const src = readFileSync(path, 'utf8');
  it('contains the module-origin check', () => {
    expect(src).toContain('tmpEXO_');
    expect(src).toContain('Get-Command');
    expect(src).toContain('ExchangeOnlineManagement');
    expect(src).toContain('Disconnect-ExchangeOnline');
    expect(src).toContain("$params['ErrorAction'] = 'Stop'");
    expect(src).toContain("[version]'3.1.0'");
  });
  it('install and update hints name Windows PowerShell (powershell.exe)', () => {
    const lines = src.split('\n').filter((l) => /Install-Module|Update-Module/.test(l));
    expect(lines).toHaveLength(2);
    for (const l of lines) expect(l).toContain('in Windows PowerShell (powershell.exe)');
  });
  it('sets Confirm:$false for approved (non-Get) cmdlets that have a Confirm parameter', () => {
    const block = /if \(\(\$name -cnotlike 'Get-\*'\) -and \$cmd\.Parameters\.ContainsKey\('Confirm'\)\) \{\s*\$params\['Confirm'\] = \$false\s*\}/;
    expect(src).toMatch(block);
    // set after the caller's parameters are copied and before the cmdlet runs
    const set = src.indexOf("$params['Confirm'] = $false");
    expect(set).toBeGreaterThan(src.indexOf('ConvertTo-Param $p.Value'));
    expect(set).toBeLessThan(src.indexOf('& $cmd @params'));
  });
  const hasPwsh = spawnSync('pwsh', ['-NoProfile', '-Command', '$PSVersionTable.PSVersion.Major']).status === 0;
  it.skipIf(!hasPwsh)('refuses Get-Content via a stub module', () => {
    const dir = mkdtempSync(join(tmpdir(), 'exo-'));
    const mod = join(dir, 'ExchangeOnlineManagement');
    spawnSync('mkdir', ['-p', mod]);
    writeFileSync(join(mod, 'ExchangeOnlineManagement.psm1'),
      'function Connect-ExchangeOnline {}\nfunction Disconnect-ExchangeOnline {}\nExport-ModuleMember -Function *');
    const res = spawnSync('pwsh', ['-NoProfile', '-File', path.pathname], {
      input: JSON.stringify({ ...base, cmdlet: 'Get-Content', parameters: { Path: '/etc/hostname' } }),
      env: { ...process.env, PSModulePath: dir },
      encoding: 'utf8',
    });
    expect(JSON.parse(res.stdout.trim())).toEqual({ ok: false, error: 'Cmdlet is not an Exchange Online cmdlet.' });
  });
});
