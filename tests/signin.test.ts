import { describe, it, expect, afterEach } from 'vitest';
import { existsSync } from 'node:fs';
import { SignInBrowser, SignInError, type SignInParams } from '../src/auth/signin.js';
import { EXO_RESOURCE, graphResource, type Resource } from '../src/auth/resources.js';
import { startFakeLogin, type FakeLogin, type FakeLoginOpts } from './fixtures/fake-login/server.js';
import { totp } from '../src/crypto.js';

const SEED = 'JBSWY3DPEHPK3PXP';
const USER = 'admin@contoso.com';
const PASS = 'Sup3r-Secret-Pw!';
const USER2 = 'ops@fabrikam.com';
const PASS2 = 'An0ther-Secret!';
const codeUser = (code: string) => Buffer.from(code.split('-')[1], 'base64url').toString();
const EXE = '/opt/pw-browsers/chromium';
const res = (key: 'graph' | 'exo'): Resource => ({ key, clientId: `client-${key}`, redirectUri: 'http://localhost:1/cb', scopes: ['openid', `${key}.read`] });

let site: FakeLogin | undefined;
let browser: SignInBrowser | undefined;

afterEach(async () => {
  await browser?.close();
  await site?.close();
  browser = site = undefined;
});

async function setup(opts: Partial<FakeLoginOpts> = {}) {
  site = await startFakeLogin({ username: USER, password: PASS, seed: SEED, ...opts });
  browser = await SignInBrowser.launch({ executablePath: existsSync(EXE) ? EXE : undefined, stepTimeoutMs: 2000, overallTimeoutMs: 10000 });
  const params = (key: 'graph' | 'exo' = 'graph', username = USER, password = PASS): SignInParams =>
    ({ authority: site!.url, tenant: 'contoso.com', resource: res(key), username, password, totpSeed: SEED });
  return { site, browser, params };
}

async function category(p: Promise<unknown>): Promise<SignInError> {
  const err = await p.then(() => { throw new Error('expected failure'); }, (e) => e);
  expect(err).toBeInstanceOf(SignInError);
  expect(err.code).toBe('signin_failed');
  for (const secret of [PASS, SEED, USER, site?.lastOtc()].filter(Boolean) as string[]) expect(err.message).not.toContain(secret);
  return err;
}

describe('resources', () => {
  it('exposes the first-party client ids', () => {
    const g = graphResource(['User.Read']);
    expect(g).toEqual({ key: 'graph', clientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e', redirectUri: 'http://localhost', scopes: ['User.Read'] });
    expect(EXO_RESOURCE).toEqual({
      key: 'exo',
      clientId: 'fb78d390-0c51-40cd-8e17-fdbfab77341b',
      redirectUri: 'https://login.microsoftonline.com/organizations/oauth2/nativeclient',
      scopes: ['https://outlook.office365.com/.default', 'offline_access'],
    });
  });
});

describe('SignInBrowser.authorize', () => {
  it('signs in with password + TOTP and returns code and PKCE verifier', async () => {
    const { browser, params, site } = await setup({ kmsi: true });
    const r = await browser.authorize(params());
    expect(r.code).toMatch(/^CODE-/);
    expect(r.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(site.lastOtc()).toMatch(/^\d{6}$/);
  });

  it('reuses the session for the second resource without the password page', async () => {
    const { browser, params, site } = await setup();
    await browser.authorize(params('graph'));
    const views = site.passwordPageViews();
    const r = await browser.authorize(params('exo'));
    expect(r.code).toMatch(/^CODE-/);
    expect(site.passwordPageViews()).toBe(views);
  });

  it('does not reuse one account\'s session for another account', async () => {
    const { browser, params, site } = await setup({ users: { [USER2]: PASS2 } });
    expect(codeUser((await browser.authorize(params('graph'))).code)).toBe(USER);
    const views = site.passwordPageViews();
    const r = await browser.authorize(params('graph', USER2, PASS2));
    expect(site.passwordPageViews()).toBe(views + 1);
    expect(codeUser(r.code)).toBe(USER2);
    // Both accounts now have sessions; each still gets its own code silently.
    expect(codeUser((await browser.authorize(params('exo', USER.toUpperCase()))).code)).toBe(USER);
    expect(site.passwordPageViews()).toBe(views + 1);
  });

  it('serialises concurrent authorize calls so each gets its own code', async () => {
    const { browser, params } = await setup({ users: { [USER2]: PASS2 } });
    const [a, b] = await Promise.all([browser.authorize(params('graph')), browser.authorize(params('graph', USER2, PASS2))]);
    expect(codeUser(a.code)).toBe(USER);
    expect(codeUser(b.code)).toBe(USER2);
    expect(a.verifier).not.toBe(b.verifier);
  });

  it('rejects a redirect whose state does not match', async () => {
    const { browser, params } = await setup({ wrongState: true });
    expect((await category(browser.authorize(params()))).category).toBe('page_changed');
  });

  it('switches from push to a verification code when offered', async () => {
    const { browser, params, site } = await setup({ mfa: 'push-default-totp-available' });
    const r = await browser.authorize(params());
    expect(r.code).toMatch(/^CODE-/);
    const now = Date.now();
    expect([totp(SEED, now), totp(SEED, now - 30_000)]).toContain(site.lastOtc());
  });

  it('fails with mfa_not_totp when only push is available', async () => {
    const { browser, params } = await setup({ mfa: 'push-only' });
    expect((await category(browser.authorize(params()))).category).toBe('mfa_not_totp');
  });

  it('fails with wrong_password without echoing the password', async () => {
    const { browser, params } = await setup({ wrongPassword: true });
    expect((await category(browser.authorize(params()))).category).toBe('wrong_password');
  });

  it('fails with needs_consent and never accepts consent', async () => {
    const { browser, params, site } = await setup({ consent: true });
    expect((await category(browser.authorize(params()))).category).toBe('needs_consent');
    expect(site.acceptPosted()).toBe(false);
  });

  it('fails with federated when sent to another host', async () => {
    const { browser, params } = await setup({ federated: true });
    expect((await category(browser.authorize(params()))).category).toBe('federated');
  });

  it.each([
    ['AADSTS53003', 'conditional_access'],
    ['AADSTS53000', 'conditional_access'],
    ['AADSTS65001', 'needs_consent'],
    ['AADSTS50053', 'account_locked'],
    ['AADSTS700016', 'needs_consent'],
    ['AADSTS50057', 'account_locked'],
    ['AADSTS50126', 'wrong_password'],
    ['AADSTS50079', 'mfa_setup_required'],
    ['AADSTS50020', 'wrong_tenant'],
    ['AADSTS99999', 'page_changed'],
  ])('maps redirect error %s to %s', async (code, cat) => {
    const { browser, params } = await setup({ error: code });
    const err = await category(browser.authorize(params()));
    expect(err.category).toBe(cat);
    expect(err.message).toContain(code);
  });

  it.each([
    ['AADSTS50020', 'wrong_tenant'],
    ['AADSTS50034', 'wrong_tenant'],
    ['AADSTS53003', 'conditional_access'],
  ])('recognises Microsoft error page %s as %s', async (code, cat) => {
    const { browser, params } = await setup({ aadErrorPage: code });
    const err = await category(browser.authorize(params()));
    expect(err.category).toBe(cat);
    expect(err.message).toContain(code);
  });

  it('reports an unmapped Microsoft error page with its code and heading', async () => {
    const { browser, params } = await setup({ aadErrorPage: 'AADSTS12345' });
    const err = await category(browser.authorize(params()));
    expect(err.category).toBe('page_changed');
    expect(err.message).toContain('AADSTS12345');
    expect(err.message).toContain('heading "Sign in"');
  });

  it('recognises the "More information required" MFA setup interrupt', async () => {
    const { browser, params } = await setup({ proofUp: true });
    expect((await category(browser.authorize(params()))).category).toBe('mfa_setup_required');
  });

  it('needs_consent tells the reader exactly how to grant consent for this tenant', async () => {
    const { browser, params } = await setup({ consentHeading: true });
    const graph = { ...params(), resource: { key: 'graph' as const, clientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e', redirectUri: 'http://localhost', scopes: ['https://graph.microsoft.com/User.ReadWrite.All', 'https://graph.microsoft.com/Group.ReadWrite.All', 'offline_access'] } };
    const err = await category(browser.authorize(graph));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('/contoso.com/v2.0/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e');
    expect(err.message).toContain('scope=https%3A%2F%2Fgraph.microsoft.com%2FUser.ReadWrite.All+https%3A%2F%2Fgraph.microsoft.com%2FGroup.ReadWrite.All&');
    expect(err.message).toContain('Connect-MgGraph -TenantId contoso.com -Scopes "User.ReadWrite.All","Group.ReadWrite.All"');
    expect(err.message).not.toContain('offline_access');
    expect(err.message).toContain('Consent on behalf of your organization');
  });

  it('needs_consent for Exchange points to Connect-ExchangeOnline', async () => {
    const { browser, params } = await setup({ consentHeading: true });
    const err = await category(browser.authorize({ ...params(), resource: EXO_RESOURCE }));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('Connect-ExchangeOnline');
    expect(err.message).not.toContain('adminconsent');
  });

  it('recognises a consent page by its heading and never accepts it', async () => {
    const { site, browser, params } = await setup({ consentHeading: true });
    expect((await category(browser.authorize(params()))).category).toBe('needs_consent');
    expect(site.acceptPosted()).toBe(false);
  });

  it('fails with page_changed on an unknown page within the step timeout', async () => {
    const { browser, params } = await setup({ unknownPage: true });
    const t0 = Date.now();
    const err = await category(browser.authorize(params()));
    expect(err.category).toBe('page_changed');
    expect(Date.now() - t0).toBeLessThan(5000);
    // Says where it stopped (address without query, heading), never field values.
    expect(err.message).toMatch(/Stopped at: 127\.0\.0\.1:\d+\/contoso\.com\/oauth2\/v2\.0\/authorize, heading "Something new"/);
    expect(err.message).not.toContain('client_id');
  });
});
