import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { runAdminCmdlet, defaultPsRunner, type AdminCmdletArgs, type PsRunner } from '../src/admin/runner.js';
import { BrokerError } from '../src/errors.js';

const base: AdminCmdletArgs = {
  service: 'exchange', shell: 'powershell', token: 'SECRETTOKEN123', upn: 'a@b.com', organization: 'b.com',
  cmdlet: 'Get-Mailbox', parameters: { Identity: 'x' },
};
const runner = (stdout: string, code = 0): PsRunner => vi.fn(async () => ({ code, stdout, stderr: 'stderr secret' }));
const calls = (r: PsRunner) => (r as unknown as { mock: { calls: [string, string][] } }).mock.calls;

describe('runAdminCmdlet', () => {
  it('rejects invalid cmdlets and parameters before running', async () => {
    const r = runner('{}');
    await expect(runAdminCmdlet(r, { ...base, cmdlet: 'rm -rf' })).rejects.toMatchObject({ code: 'invalid_cmdlet' });
    await expect(runAdminCmdlet(r, { ...base, cmdlet: 'Get-PnPAccessToken' })).rejects.toMatchObject({ code: 'invalid_cmdlet' });
    await expect(runAdminCmdlet(r, { ...base, parameters: { 'a b': 1 } })).rejects.toMatchObject({ code: 'invalid_parameters' });
    expect(r).not.toHaveBeenCalled();
  });

  it('passes everything on stdin, picks the shell, and returns result, total and note', async () => {
    const r = runner('{"ok":true,"result":[{"n":1}],"total":57,"note":"Only simple properties are shown."}');
    const out = await runAdminCmdlet(r, {
      ...base, service: 'sharepoint', shell: 'pwsh', url: 'https://contoso-admin.sharepoint.com',
      cmdlet: 'Get-PnPTenantSite', parameters: {}, select: ['Url', 'Title'], first: 5,
    });
    expect(out).toEqual({ result: [{ n: 1 }], total: 57, note: 'Only simple properties are shown.' });
    const [shell, stdin] = calls(r)[0]!;
    expect(shell).toBe('pwsh');
    expect(JSON.parse(stdin)).toEqual({
      service: 'sharepoint', token: 'SECRETTOKEN123', upn: 'a@b.com', organization: 'b.com',
      url: 'https://contoso-admin.sharepoint.com', cmdlet: 'Get-PnPTenantSite', parameters: {}, select: ['Url', 'Title'], first: 5,
    });
  });

  it('sends the Graph token for teams', async () => {
    const r = runner('{"ok":true,"result":[]}');
    await runAdminCmdlet(r, { ...base, service: 'teams', graphToken: 'GRAPHTOKEN456', cmdlet: 'Get-CsTeamsMeetingPolicy', parameters: {} });
    expect(calls(r)[0]![0]).toBe('powershell');
    expect(JSON.parse(calls(r)[0]![1])).toMatchObject({ service: 'teams', token: 'SECRETTOKEN123', graphToken: 'GRAPHTOKEN456' });
  });

  it('reports a missing module with the script\'s own message and code', async () => {
    const msg = 'The PnP.PowerShell PowerShell module is not installed. Run in PowerShell 7 (pwsh), not Windows PowerShell: Install-Module PnP.PowerShell -Scope CurrentUser';
    const e = await runAdminCmdlet(runner(JSON.stringify({ ok: false, code: 'module_missing', error: msg })), base).catch((x) => x);
    expect(e).toBeInstanceOf(BrokerError);
    expect(e.code).toBe('module_missing');
    expect(e.message).toBe(msg);
  });

  it('does not let the script choose arbitrary error codes', async () => {
    const e = await runAdminCmdlet(runner(JSON.stringify({ ok: false, code: 'denied', error: 'x' })), base).catch((x) => x);
    expect(e.code).toBe('cmdlet_failed');
  });

  it('passes through a BrokerError from the runner (PowerShell 7 not installed)', async () => {
    const r: PsRunner = async () => { throw new BrokerError('module_missing', 'PowerShell 7 (pwsh) is not installed'); };
    await expect(runAdminCmdlet(r, base)).rejects.toMatchObject({ code: 'module_missing' });
  });

  it('scrubs both tokens and truncates errors', async () => {
    const err = 'bad eyJa.b.c and SECRETTOKEN123 and GRAPHTOKEN456 ' + 'z'.repeat(2000);
    const r = runner(JSON.stringify({ ok: false, error: err }));
    const e = await runAdminCmdlet(r, { ...base, graphToken: 'GRAPHTOKEN456' }).catch((x) => x);
    expect(e.code).toBe('cmdlet_failed');
    expect(e.message).not.toContain('eyJa.b.c');
    expect(e.message).not.toContain('SECRETTOKEN123');
    expect(e.message).not.toContain('GRAPHTOKEN456');
    expect(e.message.length).toBeLessThanOrEqual(1000);
  });

  it('scrubs a JWT straddling the truncation point', async () => {
    const jwt = 'eyJhbGciOi.abcdefghijklmnop.sig123456';
    const err = 'a'.repeat(990) + jwt;
    const e = await runAdminCmdlet(runner(JSON.stringify({ ok: false, error: err })), base).catch((x) => x);
    expect(e.message).not.toContain('eyJ');
    expect(e.message.length).toBeLessThanOrEqual(1000);
  });

  it('rejects caller-supplied common parameters before running', async () => {
    const r = runner('{}');
    for (const k of ['ErrorAction', 'errorvariable', 'WarningAction', 'WarningVariable', 'InformationAction', 'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable']) {
      await expect(runAdminCmdlet(r, { ...base, parameters: { [k]: 'x' } })).rejects.toMatchObject({ code: 'invalid_parameters' });
    }
    expect(r).not.toHaveBeenCalled();
  });

  it('rejects a caller-supplied Confirm but allows WhatIf', async () => {
    const r = runner(JSON.stringify({ ok: true, result: null }));
    for (const k of ['Confirm', 'confirm', 'CONFIRM']) {
      await expect(runAdminCmdlet(r, { ...base, cmdlet: 'Remove-InboxRule', parameters: { Identity: 'x', [k]: false } }))
        .rejects.toMatchObject({ code: 'invalid_parameters', message: `Invalid parameters: ${k} is not allowed` });
    }
    expect(r).not.toHaveBeenCalled();
    await expect(runAdminCmdlet(r, { ...base, cmdlet: 'Remove-InboxRule', parameters: { Identity: 'x', WhatIf: true } })).resolves.toEqual({ result: null });
    expect(r).toHaveBeenCalledOnce();
  });

  it('maps garbage output / crashes to a generic error without stderr', async () => {
    for (const r of [runner('not json'), runner('', 1), (async () => { throw new Error('x'); }) as PsRunner]) {
      await expect(runAdminCmdlet(r, base)).rejects.toMatchObject({ code: 'cmdlet_failed', message: 'The PowerShell command failed unexpectedly.' });
    }
  });

  it('default runner is a function (it only works on Windows)', () => {
    expect(typeof defaultPsRunner()).toBe('function');
  });
});

describe('run-admin-cmdlet.ps1', () => {
  const src = readFileSync(new URL('../src/admin/run-admin-cmdlet.ps1', import.meta.url), 'utf8');

  it('is plain ASCII, so Windows PowerShell 5.1 reads it correctly without a BOM', () => {
    // eslint-disable-next-line no-control-regex
    expect(/[^\x00-\x7f]/.test(src)).toBe(false);
  });

  it('connects each service with a broker-supplied token', () => {
    expect(src).toMatch(/Connect-ExchangeOnline -AccessToken \$token/);
    expect(src).toMatch(/Connect-IPPSSession -AccessToken \$token/);
    expect(src).toMatch(/Connect-MicrosoftTeams -AccessTokens @\(\[string\]\$req\.graphToken, \$token\)/);
    expect(src).toMatch(/Connect-PnPOnline -Url \(\[string\]\$req\.url\) -AccessToken \$token/);
  });

  it('checks each module and its minimum version', () => {
    expect(src).toContain("Assert-Module 'ExchangeOnlineManagement' '3.1.0' $WinHint");
    expect(src).toContain("Assert-Module 'ExchangeOnlineManagement' '3.2.0' $WinHint");
    expect(src).toContain("Assert-Module 'MicrosoftTeams' '6.0.0' $WinHint");
    expect(src).toContain("Assert-Module 'PnP.PowerShell' '3.0.0' $CoreHint");
    expect(src).toContain("[version]'7.4'");
    expect(src).toContain("$script:failCode = 'module_missing'");
    expect(src).toContain('Windows PowerShell (powershell.exe)');
    expect(src).toContain('PowerShell 7 (pwsh)');
  });

  it('never installs or updates a module itself', () => {
    // The only mentions are inside the messages shown to the user.
    for (const line of src.split('\n').filter((l) => /Install-Module|Update-Module/.test(l))) {
      expect(line.trim().startsWith('throw "')).toBe(true);
    }
  });

  it('has the module-origin check for every service, before the cmdlet runs', () => {
    expect(src).toContain("$origins = @('tmpEXO_*', 'ExchangeOnlineManagement')");
    expect(src).toContain("$origins = @('MicrosoftTeams', 'Microsoft.Teams.*')");
    expect(src).toContain("$origins = @('PnP.PowerShell')");
    expect(src).toContain('Get-Command -Name $name -CommandType Cmdlet,Function');
    expect(src.indexOf('if (-not $allowed)')).toBeLessThan(src.indexOf('& $cmd @params'));
    expect(src.indexOf('if (-not $allowed)')).toBeGreaterThan(src.indexOf('Get-Command -Name $name'));
  });

  it('forces ErrorAction Stop, and Confirm:$false for approved (non-Get) cmdlets, before the cmdlet runs', () => {
    expect(src).toContain("$params['ErrorAction'] = 'Stop'");
    const block = /if \(\(\$name -cnotlike 'Get-\*'\) -and \$cmd\.Parameters\.ContainsKey\('Confirm'\)\) \{\s*\$params\['Confirm'\] = \$false\s*\}/;
    expect(src).toMatch(block);
    const set = src.indexOf("$params['Confirm'] = $false");
    expect(set).toBeGreaterThan(src.indexOf('ConvertTo-Param $p.Value'));
    expect(set).toBeLessThan(src.indexOf('& $cmd @params'));
    expect(src).toMatch(/\$service -eq 'sharepoint'\) -and \(\$name -cnotlike 'Get-\*'\) -and \$cmd\.Parameters\.ContainsKey\('Force'\)/);
  });

  it('counts everything, keeps the first items, and selects without script blocks', () => {
    expect(src).toContain('$total = $all.Count');
    expect(src).toContain('$DefaultItems = 200');
    expect(src).toContain('Select-Object -First $take');
    expect(src).not.toMatch(/\[scriptblock\]|Invoke-Expression|\biex\b/i);
    expect(src).toContain('ConvertTo-Json -Depth 4 -Compress');
  });

  it('disconnects every service in finally', () => {
    const fin = src.slice(src.indexOf('} finally {'));
    for (const d of ['Disconnect-ExchangeOnline', 'Disconnect-MicrosoftTeams', 'Disconnect-PnPOnline']) expect(fin).toContain(d);
  });
});
