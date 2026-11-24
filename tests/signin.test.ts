import { describe, it, expect, afterEach } from 'vitest';
import { existsSync } from 'node:fs';
import { SignInBrowser, SignInError, type SignInParams } from '../src/auth/signin.js';
import { EXO_RESOURCE, graphResource, type Resource } from '../src/auth/resources.js';
import { startFakeLogin, type FakeLogin, type FakeLoginOpts } from './fixtures/fake-login/server.js';
import { totp } from '../src/crypto.js';

const SEED = 'JBSWY3DPEHPK3PXP';
const USER = 'admin@contoso.com';
const PASS = 'Sup3r-Secret-Pw!';
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
  const params = (key: 'graph' | 'exo' = 'graph'): SignInParams => ({ authority: site!.url, tenant: 'contoso.com', resource: res(key), username: USER, password: PASS, totpSeed: SEED });
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
    ['AADSTS99999', 'page_changed'],
  ])('maps redirect error %s to %s', async (code, cat) => {
    const { browser, params } = await setup({ error: code });
    expect((await category(browser.authorize(params()))).category).toBe(cat);
  });

  it('fails with page_changed on an unknown page within the step timeout', async () => {
    const { browser, params } = await setup({ unknownPage: true });
    const t0 = Date.now();
    expect((await category(browser.authorize(params()))).category).toBe('page_changed');
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});
