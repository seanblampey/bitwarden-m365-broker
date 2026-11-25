import { describe, expect, it } from 'vitest';
import { buildGraphUrl, isCmdletRead, isGraphRead, validateCmdlet, validateFirst, validateParameters, validateSelect } from '../src/classify.js';
import { BrokerError } from '../src/errors.js';

describe('buildGraphUrl', () => {
  it('builds urls on graph.microsoft.com', () => {
    expect(buildGraphUrl('/users?$top=5', 'v1.0')).toBe('https://graph.microsoft.com/v1.0/users?$top=5');
    expect(buildGraphUrl('/me', 'beta')).toBe('https://graph.microsoft.com/beta/me');
  });
  it('rejects escaping or malformed paths', () => {
    for (const bad of ['https://evil.com/x', '//evil.com/x', 'users', '/users/../../x', '/users\\x', '/a\r\nb', '', '/users/%2e%2e/x', '/users/./x', '/a\u0000b', '/users/..#', '/users#x']) {
      expect(() => buildGraphUrl(bad, 'v1.0'), bad).toThrow(expect.objectContaining({ code: 'invalid_path' }));
    }
  });
  it('always yields host graph.microsoft.com', () => {
    expect(new URL(buildGraphUrl('/@evil.com', 'v1.0')).host).toBe('graph.microsoft.com');
    expect(new URL(buildGraphUrl('/users/a%40b.com', 'v1.0')).host).toBe('graph.microsoft.com');
  });
  it('accepts UPNs containing @', () => {
    expect(buildGraphUrl('/users/a@b.com', 'v1.0')).toBe('https://graph.microsoft.com/v1.0/users/a@b.com');
  });
  it('throws BrokerError invalid_path without echoing huge input', () => {
    try {
      buildGraphUrl('x'.repeat(5000), 'v1.0');
      expect.unreachable();
    } catch (e: any) {
      expect(e.code).toBe('invalid_path');
      expect(e.message.length).toBeLessThan(200);
    }
  });
});

describe('isGraphRead', () => {
  it('only GET is read', () => {
    expect(isGraphRead('GET')).toBe(true);
    for (const m of ['POST', 'PATCH', 'PUT', 'DELETE'] as const) expect(isGraphRead(m)).toBe(false);
  });
});

describe('cmdlets', () => {
  it('accepts valid names', () => {
    for (const ok of ['Get-Mailbox', 'Set-Mailbox', 'New-TransportRule', 'Get-EXOMailbox']) expect(() => validateCmdlet(ok)).not.toThrow();
  });
  it('rejects bad names', () => {
    for (const bad of ['Get-Mailbox; rm x', 'Invoke-Expression', 'Start-Process', 'iex', 'Get-Mailbox|x', '&Get-Mailbox', 'Get-Content ', 'New-Object', 'Add-Type', 'Set-ExecutionPolicy', 'Out-File', 'Export-Csv', 'Import-Module', 'Stop-Process']) {
      expect(() => validateCmdlet(bad), bad).toThrow(expect.objectContaining({ code: 'invalid_cmdlet' }));
    }
    try { validateCmdlet('x'.repeat(5000)); expect.unreachable(); } catch (e: any) {
      expect(e.code).toBe('invalid_cmdlet');
      expect(e.message.length).toBeLessThan(200);
    }
  });
  it('classifies reads', () => {
    expect(isCmdletRead('Get-Mailbox')).toBe(true);
    expect(isCmdletRead('Set-Mailbox')).toBe(false);
    expect(isCmdletRead('Remove-Mailbox')).toBe(false);
  });
});

describe('validateParameters', () => {
  it('accepts JSON values', () => {
    const p = { Identity: 'a@b.com', ResultSize: 10, Enabled: true, List: ['x'], N: null, O: { a: 1 } };
    expect(validateParameters(p)).toEqual(p);
  });
  it('rejects bad shapes', () => {
    for (const bad of [{ 'Bad Key': 1 }, { '-Identity': 'x' }, null, [1], 'x', undefined, { A: undefined }, { A: () => 1 }, { A: NaN }, { A: new Date() }]) {
      expect(() => validateParameters(bad)).toThrow(expect.objectContaining({ code: 'invalid_parameters' }));
    }
  });
});

describe('admin cmdlet rules', () => {
  it('refuses session, token, credential and local-file cmdlets for every service', () => {
    for (const bad of [
      'Connect-PnPOnline', 'Connect-MicrosoftTeams', 'Disconnect-ExchangeOnline', 'Get-PnPAccessToken',
      'Get-PnPGraphAccessToken', 'Get-PnPAppAuthAccessToken', 'Request-PnPAccessToken', 'Get-PnPStoredCredential',
      'Add-PnPStoredCredential', 'Get-PnPConnection', 'Get-PnPFile', 'Get-PnPAzureCertificate', 'Get-CsOnlineLisCivicAddressSecret',
    ]) {
      let err: unknown;
      try { validateCmdlet(bad); } catch (e) { err = e; }
      expect((err as BrokerError | undefined)?.code, bad).toBe('invalid_cmdlet');
    }
  });

  it('accepts ordinary cmdlets from each service', () => {
    for (const ok of ['Get-PnPTenantSite', 'Set-PnPTenant', 'Get-CsTeamsMeetingPolicy', 'Get-RetentionCompliancePolicy', 'Get-Mailbox', 'Remove-PnPList']) {
      expect(() => validateCmdlet(ok), ok).not.toThrow();
    }
  });

  it('treats a Get- cmdlet with a local-file parameter as needing approval', () => {
    expect(isCmdletRead('Get-Mailbox', { Identity: 'a' })).toBe(true);
    expect(isCmdletRead('Get-Mailbox')).toBe(true);
    expect(isCmdletRead('Set-Mailbox', {})).toBe(false);
    for (const p of ['Out', 'OutFile', 'outputfile', 'OutputPath', 'Path', 'LiteralPath', 'FilePath', 'Folder']) {
      expect(isCmdletRead('Get-PnPSiteTemplate', { [p]: 'c:\\x' }), p).toBe(false);
    }
  });

  it('validates select and first', () => {
    expect(validateSelect(undefined)).toBeUndefined();
    expect(validateSelect(['DisplayName', 'Owner.Email', 'a_b'])).toEqual(['DisplayName', 'Owner.Email', 'a_b']);
    for (const bad of ['x', [1], ['a b'], ['$x'], ['a;b'], ['@{n=1}'], [], Array(51).fill('a')]) {
      expect(() => validateSelect(bad), JSON.stringify(bad)).toThrow(/Invalid parameters/);
    }
    expect(validateFirst(undefined)).toBeUndefined();
    expect(validateFirst(1)).toBe(1);
    expect(validateFirst(1000)).toBe(1000);
    for (const bad of [0, 1001, 1.5, '5', -1, NaN]) expect(() => validateFirst(bad), String(bad)).toThrow(/Invalid parameters/);
  });
});
