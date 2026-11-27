import { describe, it, expect, afterEach } from 'vitest';
import { existsSync } from 'node:fs';
import { SignInBrowser, SignInError, type SignInParams } from '../src/auth/signin.js';
import { EXO_RESOURCE, graphResource, type Resource } from '../src/auth/resources.js';
import { startFakeLogin, type FakeLogin, type FakeLoginOpts } from './fixtures/fake-login/server.js';
import { totp } from '../src/crypto.js';
import { TokenManager } from '../src/auth/tokens.js';
import { Redactor } from '../src/redact.js';
import { BrokerError } from '../src/errors.js';

const SEED = 'JBSWY3DPEHPK3PXP';
const USER = 'admin@contoso.com';
const PASS = 'Sup3r-Secret-Pw!';
const USER2 = 'ops@fabrikam.com';
const PASS2 = 'An0ther-Secret!';
const codeUser = (code: string) => Buffer.from(code.split('-')[1], 'base64url').toString();
const EXE = '/opt/pw-browsers/chromium';
const res = (key: 'graph' | 'exo'): Resource => ({ key, clientId: `client-${key}`, redirectUri: 'http://localhost:1/cb', scopes: ['openid', `${key}.read`], appName: `App ${key}` });

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
    expect(g).toMatchObject({ key: 'graph', clientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e', redirectUri: 'http://localhost', scopes: ['User.Read'] });
    expect(g.appName).toBe('Microsoft Graph Command Line Tools');
    expect(EXO_RESOURCE).toMatchObject({
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
    const graph = { ...params(), resource: graphResource(['https://graph.microsoft.com/User.ReadWrite.All', 'https://graph.microsoft.com/Group.ReadWrite.All', 'offline_access']) };
    const err = await category(browser.authorize(graph));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('/contoso.com/v2.0/adminconsent?client_id=14d82eec-204b-4c2f-b7e8-296a70dab67e');
    // the link asks for exactly what sign-in asks for (offline_access included), so approving it ends the prompts
    expect(err.message).toContain('scope=https%3A%2F%2Fgraph.microsoft.com%2FUser.ReadWrite.All+https%3A%2F%2Fgraph.microsoft.com%2FGroup.ReadWrite.All+offline_access&');
    expect(err.message).toContain('Connect-MgGraph -TenantId contoso.com -Scopes "User.ReadWrite.All","Group.ReadWrite.All" ');
    expect(err.message).toContain('Install-Module Microsoft.Graph.Authentication -Scope CurrentUser');
    expect(err.message).toContain('Consent on behalf of your organization');
  });

  it('needs_consent for Exchange points to Connect-ExchangeOnline', async () => {
    const { browser, params } = await setup({ consentHeading: true });
    const err = await category(browser.authorize({ ...params(), resource: EXO_RESOURCE }));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('Connect-ExchangeOnline');
    // every app gets the consent link, with the scopes its sign-in requests
    expect(err.message).toContain('/contoso.com/v2.0/adminconsent?client_id=fb78d390-0c51-40cd-8e17-fdbfab77341b');
    expect(err.message).toContain('scope=https%3A%2F%2Foutlook.office365.com%2F.default+offline_access&');
    expect(err.message).not.toContain('never accepts');
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

  it('clicks the account-picker tile even when the Bitwarden username is typed in a different case', async () => {
    const MIXED = 'Admin@Contoso.com';
    const { site, browser, params } = await setup({ alwaysPicker: true, users: { [MIXED]: PASS } });
    await browser.authorize(params('graph', MIXED));
    const views = site.passwordPageViews();
    // Session exists, so the picker is shown; its tile is written in lower case.
    const second = await browser.authorize(params('exo', MIXED));
    expect(codeUser(second.code)).toBe(MIXED);
    expect(site.passwordPageViews()).toBe(views);
  });

  it('after consent is granted, the next sign-in does not ask to pick an account', async () => {
    const { site, browser, params } = await setup({ consent: true });
    await category(browser.authorize(params()));
    await browser.grantConsent(params());
    const views = site.passwordPageViews();
    expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
    // rode the session left by the consent sign-in: no second password entry
    expect(site.passwordPageViews()).toBe(views);
  });

  describe('grantConsent (only ever called after the user says Yes)', () => {
    it('signs in, clicks Accept on the admin-consent page, and the next sign-in then succeeds', async () => {
      const { site, browser, params } = await setup({ consent: true });
      expect((await category(browser.authorize(params()))).category).toBe('needs_consent');
      expect(site.adminAccepts()).toBe(0);
      await browser.grantConsent(params());
      expect(site.adminAccepts()).toBe(1);
      // asked for every scope the sign-in requests, OpenID Connect ones included
      expect(site.lastAdminConsentScope()).toBe('openid graph.read');
      expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
      // the ordinary (per-user) consent page was never accepted
      expect(site.acceptPosted()).toBe(false);
    });

    it('authorize on its own never accepts consent of either kind', async () => {
      const { site, browser, params } = await setup({ consent: true });
      await category(browser.authorize(params()));
      await category(browser.authorize(params('exo')));
      expect(site.acceptPosted()).toBe(false);
      expect(site.adminAccepts()).toBe(0);
    });

    it('reports consent_not_allowed when the account may not approve apps', async () => {
      const a = await setup({ consent: true, notAdmin: true });
      const err = await category(a.browser.grantConsent(a.params()));
      expect(err.category).toBe('consent_not_allowed');
      expect(a.site.adminAccepts()).toBe(0);
      await a.browser.close();
      await a.site.close();
      const b = await setup({ consent: true, adminConsentError: 'AADSTS90094' });
      expect((await category(b.browser.grantConsent(b.params()))).category).toBe('consent_not_allowed');
    });

    it('asks for the OpenID Connect scopes too, so the sign-in that follows is not sent back to consent', async () => {
      const { site, browser, params } = await setup({ consent: true });
      await browser.grantConsent(params());
      expect(site.lastAdminConsentScope()?.split(' ')).toEqual(['openid', 'graph.read']);
      expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
    });

    it('rejects an admin-consent redirect whose state does not match', async () => {
      const { browser, params } = await setup({ consent: true, wrongState: true });
      expect((await category(browser.grantConsent(params()))).category).toBe('page_changed');
    });
  });
});

describe('SignInBrowser after its browser or a context has gone away', () => {
  const internals = (b: SignInBrowser) => b as unknown as { browser: { close(): Promise<void> }; contexts: Map<string, { close(): Promise<void> }> };

  it('a browser that died fails with browser_failed, never a raw Playwright error, and reports it is no longer connected', async () => {
    const { browser, params } = await setup();
    await browser.authorize(params());
    expect(browser.isConnected()).toBe(true);
    await internals(browser).browser.close();
    const err = await browser.authorize(params()).catch((e) => e);
    expect(err).toBeInstanceOf(BrokerError);
    expect(err.code).toBe('browser_failed');
    expect(err.message).not.toMatch(/Target page|browserContext|playwright/i);
    expect(browser.isConnected()).toBe(false);
  });

  it('a closed account context is replaced by a fresh one', async () => {
    const { site, browser, params } = await setup();
    await browser.authorize(params());
    await internals(browser).contexts.get(USER)!.close();
    const views = site.passwordPageViews();
    expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
    // a fresh context has no session, so it signs in again
    expect(site.passwordPageViews()).toBe(views + 1);
  });

  it('forget(username) throws away that account\'s session, so the next sign-in starts clean', async () => {
    const { site, browser, params } = await setup({ users: { [USER2]: PASS2 } });
    await browser.authorize(params());
    await browser.authorize(params('graph', USER2, PASS2));
    const views = site.passwordPageViews();
    await browser.forget(USER.toUpperCase());
    await browser.authorize(params());
    expect(site.passwordPageViews()).toBe(views + 1);
    // the other account keeps its session
    await browser.authorize(params('exo', USER2, PASS2));
    expect(site.passwordPageViews()).toBe(views + 1);
  });
});

describe('Microsoft-style consent page (/reprocess, "Permissions requested / Review for your organization")', () => {
  it('authorize reports needs_consent with the manual steps, never page_changed', async () => {
    const { site, browser, params } = await setup({ consent: true, realConsentPage: true });
    const err = await category(browser.authorize(params()));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('/contoso.com/v2.0/adminconsent?client_id=client-graph');
    expect(site.adminAccepts()).toBe(0);
    expect(site.selfOnlyAccepts()).toBe(0);
  });

  it('grantConsent clicks the visible Accept, not the hidden duplicate from the previous step', async () => {
    const { site, browser, params } = await setup({ consent: true, realConsentPage: true });
    await category(browser.authorize(params()));
    await browser.grantConsent(params());
    expect(site.adminAccepts()).toBe(1);
    expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
  });

  it('grantConsent ticks "Consent on behalf of your organization" before Accept', async () => {
    const { site, browser, params } = await setup({ consent: true, realConsentPage: true, orgCheckbox: true });
    await category(browser.authorize(params()));
    await browser.grantConsent(params());
    expect(site.selfOnlyAccepts()).toBe(0);
    expect(site.adminAccepts()).toBe(1);
    expect((await browser.authorize(params())).code).toMatch(/^CODE-/);
  });

  it('a consent page with no usable Accept ends in needs_consent with the manual steps, not page_changed', async () => {
    const { site, browser, params } = await setup({ consent: true, realConsentPage: true, noVisibleAccept: true });
    await category(browser.authorize(params()));
    const err = await category(browser.grantConsent(params()));
    expect(err.category).toBe('needs_consent');
    expect(err.message).toContain('/contoso.com/v2.0/adminconsent?client_id=client-graph');
    expect(err.message).toContain('heading "Permissions requested Review for your organization"');
    expect(site.adminAccepts()).toBe(0);
  });
});

describe('one-click consent, end to end (real TokenManager and browser, fake Microsoft)', () => {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const fakeJwt = (claims: object) => `eyJ${b64({ alg: 'none' }).slice(3)}.${b64(claims)}.sig`;
  const cred = { alias: 'contoso', username: USER, password: PASS, totpSeed: SEED, tenant: 'contoso.com' };

  async function run(answer: boolean) {
    site = await startFakeLogin({ username: USER, password: PASS, seed: SEED, consent: true });
    browser = await SignInBrowser.launch({ executablePath: existsSync(EXE) ? EXE : undefined, stepTimeoutMs: 2000, overallTimeoutMs: 10000 });
    const asked: unknown[] = [];
    const codes: string[] = [];
    const tm = new TokenManager({
      authority: site.url,
      getBrowser: async () => browser!,
      fetch: (async (_url: string, init: { body: string }) => {
        codes.push(new URLSearchParams(init.body).get('code') ?? '');
        return new Response(JSON.stringify({ access_token: fakeJwt({ upn: USER }), refresh_token: 'r', id_token: fakeJwt({ preferred_username: USER }), expires_in: 3600 }));
      }) as never,
      redactor: new Redactor(),
      approveConsent: async (r) => { asked.push(r); return answer; },
      consentWaitMs: 0,
    });
    return { tm, asked, codes, site };
  }

  it('Yes: approves the app, signs in again and returns a token', async () => {
    const t = await run(true);
    const out = await t.tm.getAccessToken(cred, res('graph'));
    expect(out.upn).toBe(USER);
    expect(t.asked).toEqual([{ alias: 'contoso', tenant: 'contoso.com', account: USER, appName: 'App graph', scopes: ['graph.read'] }]);
    expect(t.site.adminAccepts()).toBe(1);
    expect(t.codes[0]).toMatch(/^CODE-/);
  });

  it('No: nothing is approved and sign-in ends with needs_consent', async () => {
    const t = await run(false);
    const err = await t.tm.getAccessToken(cred, res('graph')).catch((e) => e);
    expect(err).toBeInstanceOf(SignInError);
    expect(err.category).toBe('needs_consent');
    expect(t.site.adminAccepts()).toBe(0);
    expect(t.site.acceptPosted()).toBe(false);
    expect(t.codes).toEqual([]);
  });
});
