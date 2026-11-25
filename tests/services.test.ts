import { describe, expect, it } from 'vitest';
import { planFor, sharePointName, SERVICES } from '../src/admin/services.js';
import type { Credential } from '../src/vault/vault.js';

const cred = (over: Partial<Credential> = {}): Credential => ({
  alias: 'contoso', username: 'admin@contoso.com', password: 'pw', totpSeed: 'SEED', tenant: 'contoso.onmicrosoft.com', ...over,
});
const code = (fn: () => unknown): string | undefined => {
  try { fn(); } catch (e) { return (e as { code?: string }).code; }
  return undefined;
};

describe('planFor', () => {
  it('knows the four services', () => {
    expect([...SERVICES]).toEqual(['exchange', 'compliance', 'teams', 'sharepoint']);
    expect(code(() => planFor('azure', cred()))).toBe('invalid_parameters');
    expect(code(() => planFor(undefined, cred()))).toBe('invalid_parameters');
  });

  it('exchange and compliance share the Exchange PowerShell app, in Windows PowerShell', () => {
    const ex = planFor('exchange', cred());
    const co = planFor('compliance', cred());
    expect(ex.shell).toBe('powershell');
    expect(co.shell).toBe('powershell');
    expect(ex.primary.clientId).toBe('fb78d390-0c51-40cd-8e17-fdbfab77341b');
    expect(co.primary.clientId).toBe(ex.primary.clientId);
    expect(co.primary.redirectUri).toBe(ex.primary.redirectUri);
    expect(ex.primary.scopes).toContain('https://outlook.office365.com/.default');
    expect(co.primary.scopes).toContain('https://ps.compliance.protection.outlook.com/.default');
    expect(co.primary.key).not.toBe(ex.primary.key);
    expect(ex.graph).toBeUndefined();
  });

  it('teams needs a Teams token and a Graph token from the Teams PowerShell app', () => {
    const t = planFor('teams', cred());
    expect(t.shell).toBe('powershell');
    expect(t.primary.clientId).toBe('12128f48-ec9e-42f0-b203-ea49fb6af367');
    expect(t.primary.redirectUri).toBe('https://login.microsoftonline.com/common/oauth2/nativeclient');
    expect(t.primary.scopes).toContain('48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation');
    expect(t.graph?.clientId).toBe(t.primary.clientId);
    expect(t.graph?.scopes).toContain('https://graph.microsoft.com/.default');
    expect(t.graph?.key).not.toBe(t.primary.key);
  });

  it('sharepoint uses PowerShell 7 and the admin site by default', () => {
    const s = planFor('sharepoint', cred());
    expect(s.shell).toBe('pwsh');
    expect(s.url).toBe('https://contoso-admin.sharepoint.com');
    expect(s.primary.clientId).toBe('9bc3ab49-b65d-410a-85ad-de819febfddc');
    expect(s.primary.redirectUri).toBe('https://oauth.spops.microsoft.com');
    expect(s.primary.scopes).toContain('https://contoso-admin.sharepoint.com/.default');
    expect(s.primary.key).toBe('spo:contoso-admin.sharepoint.com');
  });

  it('sharepoint site: only the tenant\'s own hosts, and the token scope follows the host', () => {
    const s = planFor('sharepoint', cred(), 'https://contoso.sharepoint.com/sites/Finance/');
    expect(s.url).toBe('https://contoso.sharepoint.com/sites/Finance');
    expect(s.primary.scopes).toContain('https://contoso.sharepoint.com/.default');
    expect(s.primary.key).toBe('spo:contoso.sharepoint.com');
    expect(planFor('sharepoint', cred(), 'https://contoso-my.sharepoint.com/personal/a_b').primary.key).toBe('spo:contoso-my.sharepoint.com');
    for (const bad of [
      'https://evil.example/', 'https://other.sharepoint.com/sites/x', 'https://contoso.sharepoint.com.evil.example/',
      'http://contoso.sharepoint.com/sites/x', 'https://user:pw@contoso.sharepoint.com/', 'https://contoso.sharepoint.com:8443/',
      'https://contoso.sharepoint.com/sites/x?a=1', 'https://contoso.sharepoint.com/sites/x#f', 'contoso.sharepoint.com', '', 42,
    ]) {
      expect(code(() => planFor('sharepoint', cred(), bad)), String(bad)).toBe('invalid_parameters');
    }
  });

  it('site is refused for other services', () => {
    expect(code(() => planFor('teams', cred(), 'https://contoso.sharepoint.com'))).toBe('invalid_parameters');
  });
});

describe('sharePointName', () => {
  it('comes from the onmicrosoft.com tenant name, or the sharepoint field', () => {
    expect(sharePointName(cred())).toBe('contoso');
    expect(sharePointName(cred({ tenant: 'Contoso.OnMicrosoft.com' }))).toBe('contoso');
    expect(sharePointName(cred({ tenant: 'contoso.com', sharepoint: 'contosoltd' }))).toBe('contosoltd');
    expect(sharePointName(cred({ sharepoint: 'https://ContosoLtd-admin.sharepoint.com/' }))).toBe('contosoltd');
    expect(sharePointName(cred({ sharepoint: 'contosoltd.sharepoint.com' }))).toBe('contosoltd');
  });

  it('asks for the sharepoint field when it cannot tell', () => {
    let err: { code?: string; message?: string } = {};
    try { sharePointName(cred({ tenant: 'contoso.com' })); } catch (e) { err = e as typeof err; }
    expect(err.code).toBe('item_incomplete');
    expect(err.message).toContain('sharepoint');
    expect(code(() => sharePointName(cred({ sharepoint: 'bad name!' })))).toBe('item_incomplete');
    expect(code(() => sharePointName(cred({ sharepoint: 'evil.example/x' })))).toBe('item_incomplete');
  });
});
