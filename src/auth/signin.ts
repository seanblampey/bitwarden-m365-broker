import { chromium, type Browser, type BrowserContext, type Page, type Request, type Route } from 'playwright-core';
import { BrokerError } from '../errors.js';
import { randomBytes } from 'node:crypto';
import { pkcePair, totp } from '../crypto.js';
import type { Resource } from './resources.js';

export type SignInCategory =
  | 'wrong_password' | 'mfa_not_totp' | 'needs_consent' | 'conditional_access'
  | 'federated' | 'account_locked' | 'page_changed';

const MESSAGES: Record<SignInCategory, string> = {
  wrong_password: 'Microsoft rejected the password for this account.',
  mfa_not_totp: 'The account does not offer an authenticator-app code (TOTP) for MFA, so the broker cannot complete sign-in.',
  needs_consent: 'Microsoft asked for consent to the app; an administrator must grant consent first (the broker never accepts consent).',
  conditional_access: 'A Conditional Access policy blocked this sign-in.',
  federated: 'The account signs in through a federated identity provider, which the broker does not support.',
  account_locked: 'Microsoft reports that the account is locked.',
  page_changed: 'The Microsoft sign-in page did not look as expected or did not respond in time.',
};

export class SignInError extends BrokerError {
  category: SignInCategory;
  constructor(category: SignInCategory) {
    super('signin_failed', MESSAGES[category]);
    this.name = 'SignInError';
    this.category = category;
  }
}

export interface SignInParams {
  authority: string;
  tenant: string;
  resource: Resource;
  username: string;
  password: string;
  totpSeed: string;
}

export interface LaunchOpts {
  headless?: boolean;
  channel?: string;
  executablePath?: string;
  stepTimeoutMs?: number;
  overallTimeoutMs?: number;
}

type State =
  | 'consent' | 'federated' | 'password_error' | 'kmsi' | 'otc' | 'pick_otp' | 'other_mfa'
  | 'password' | 'username' | 'account_tile' | 'none';

const SEL = {
  loginfmt: 'input[name=loginfmt]',
  passwd: 'input[name=passwd]',
  passwordError: '#passwordError',
  otc: 'input[name=otc]',
  next: '#idSIButton9',
  otcSubmit: '#idSubmit_SAOTCC_Continue',
  pushTitle: '#idDiv_SAOTCAS_Title',
  pushProof: '[data-value=PhoneAppNotification]',
  otpProof: '[data-value=PhoneAppOTP]',
  otherWay: '#signInAnotherWay, a#idA_SAASTO_TOTP',
  kmsi: '#KmsiCheckboxField',
  back: '#idBtn_Back',
  consent: '#consentHeader',
};

const visible = (page: Page, sel: string) => page.locator(sel).first().isVisible().catch(() => false);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Classify the current page; order matters (errors and consent win over input fields). */
async function detectState(page: Page, authorityHost: string, username: string): Promise<State> {
  let url: URL | undefined;
  try { url = new URL(page.url()); } catch { /* about:blank etc. */ }
  if (url && /\/consent/i.test(url.pathname)) return 'consent';
  if (await visible(page, SEL.consent)) return 'consent';
  if (url && /^https?:$/.test(url.protocol) && url.host !== authorityHost) return 'federated';
  if (await visible(page, SEL.passwordError)) return 'password_error';
  if ((await page.locator(SEL.kmsi).count().catch(() => 0)) > 0 && (await visible(page, SEL.back))) return 'kmsi';
  if (await visible(page, SEL.otc)) return 'otc';
  if (await visible(page, SEL.otpProof)) return 'pick_otp';
  if ((await visible(page, SEL.pushTitle)) || (await visible(page, SEL.pushProof))) return 'other_mfa';
  if (await visible(page, SEL.passwd)) return 'password';
  if (await visible(page, SEL.loginfmt)) return 'username';
  if (await visible(page, `[data-test-id=${JSON.stringify(username)}]`)) return 'account_tile';
  return 'none';
}

/** Secrets are only ever typed into pages served by the authority itself. */
function onAuthority(page: Page, authorityHost: string): boolean {
  try { return new URL(page.url()).host === authorityHost; } catch { return false; }
}

function mapAuthError(error: string, description: string): SignInCategory {
  const s = `${error} ${description}`;
  if (/AADSTS5300[03]\b/.test(s)) return 'conditional_access';
  if (/AADSTS65001\b/.test(s)) return 'needs_consent';
  if (/AADSTS50053\b/.test(s)) return 'account_locked';
  return 'page_changed';
}

type Outcome = { code: string } | { category: SignInCategory };

export class SignInBrowser {
  /**
   * One in-memory context (no storageState, no profile dir) per lower-cased username, created on first use.
   * Each account's cookies stay apart, so a second account never meets the first one's account picker.
   */
  private readonly contexts = new Map<string, BrowserContext>();
  /** Lower-cased usernames that completed sign-in in their context (silent SSO only for them). */
  private readonly signedIn = new Set<string>();
  /** Serialises authorize() so sign-ins never overlap. */
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private readonly browser: Browser,
    private readonly stepMs: number,
    private readonly overallMs: number,
  ) {}

  static async launch(opts: LaunchOpts = {}): Promise<SignInBrowser> {
    const browser = await chromium.launch({
      headless: opts.headless ?? true,
      ...(opts.executablePath ? { executablePath: opts.executablePath } : { channel: opts.channel ?? 'msedge' }),
    });
    return new SignInBrowser(browser, opts.stepTimeoutMs ?? 15_000, opts.overallTimeoutMs ?? 60_000);
  }

  private async contextFor(user: string): Promise<BrowserContext> {
    let context = this.contexts.get(user);
    if (!context) {
      context = await this.browser.newContext();
      this.contexts.set(user, context);
    }
    return context;
  }

  authorize(p: SignInParams): Promise<{ code: string; verifier: string }> {
    const run = this.queue.then(() => this.authorizeNow(p));
    this.queue = run.catch(() => {});
    return run;
  }

  private async authorizeNow(p: SignInParams): Promise<{ code: string; verifier: string }> {
    const { verifier, challenge } = pkcePair();
    const state = randomBytes(16).toString('base64url');
    const user = p.username.toLowerCase();
    // Playwright errors can quote internals: never pass them through.
    const context = await this.contextFor(user).catch(() => { throw new SignInError('page_changed'); });
    const authority = p.authority.replace(/\/+$/, '');
    const q = new URLSearchParams({
      client_id: p.resource.clientId,
      response_type: 'code',
      redirect_uri: p.resource.redirectUri,
      scope: p.resource.scopes.join(' '),
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
    });
    if (!this.signedIn.has(user)) q.set('prompt', 'select_account');
    q.set('login_hint', p.username);
    const url = `${authority}/${encodeURIComponent(p.tenant)}/oauth2/v2.0/authorize?${q}`;

    let outcome: Outcome | undefined;
    const isRedirect = (u: string) => u.startsWith(p.resource.redirectUri);
    const capture = (u: string) => {
      if (outcome || !isRedirect(u)) return;
      const sp = new URL(u).searchParams;
      if (sp.get('state') !== state) { outcome = { category: 'page_changed' }; return; }
      const err = sp.get('error');
      const code = sp.get('code');
      outcome = err || !code ? { category: mapAuthError(err ?? '', sp.get('error_description') ?? '') } : { code };
    };
    const matcher = (u: URL) => isRedirect(u.href);
    const handler = async (route: Route) => {
      capture(route.request().url());
      await route.abort().catch(() => {});
    };
    await context.route(matcher, handler);
    const onRequest = (r: Request) => capture(r.url());
    context.on('request', onRequest);
    const page = await context.newPage();
    try {
      const result = await this.drive(page, url, new URL(authority).host, p, () => outcome);
      if ('category' in result) throw new SignInError(result.category);
      this.signedIn.add(user);
      return { code: result.code, verifier };
    } catch (e) {
      // Playwright errors can quote selectors or page content: never pass them through.
      if (e instanceof BrokerError) throw e;
      throw new SignInError('page_changed');
    } finally {
      context.off('request', onRequest);
      await context.unroute(matcher, handler).catch(() => {});
      await page.close().catch(() => {});
    }
  }

  private async drive(page: Page, url: string, authorityHost: string, p: SignInParams, outcome: () => Outcome | undefined): Promise<Outcome> {
    const deadline = Date.now() + this.overallMs;
    const left = () => Math.max(0, Math.min(this.stepMs, deadline - Date.now()));
    page.setDefaultTimeout(this.stepMs);
    await page.goto(url, { timeout: left() }).catch(() => {});
    const actions = new Map<State, number>();
    let state: State = 'none';
    let marker = 0;

    while (Date.now() < deadline) {
      // Wait (up to one step) for a recognisable page, ignoring the state just acted on
      // unless the document was replaced or the step timed out.
      const stepEnd = Date.now() + left();
      const prev = state as State;
      const sig = marker as number;
      for (;;) {
        const o = outcome();
        if (o) return o;
        const s = await detectState(page, authorityHost, p.username);
        const reloaded = sig === 0 || (await page.evaluate(() => (window as any).__sib).catch(() => undefined)) !== sig;
        if (s !== 'none' && (s !== prev || reloaded)) { state = s; break; }
        if (Date.now() >= stepEnd) {
          // Same page still showing after a full step: retry its action (bounded below).
          if (s === 'none') return { category: 'page_changed' };
          break;
        }
        await sleep(150);
      }
      const n = (actions.get(state) ?? 0) + 1;
      actions.set(state, n);
      if (n > 3) return { category: 'page_changed' };
      marker = Date.now();
      await page.evaluate((m) => { (window as any).__sib = m; }, marker).catch(() => {});

      switch (state) {
        case 'consent': return { category: 'needs_consent' };
        case 'federated': return { category: 'federated' };
        case 'password_error': return { category: 'wrong_password' };
        case 'username':
          await page.locator(SEL.loginfmt).first().fill(p.username);
          await page.locator(SEL.next).first().click();
          break;
        case 'password':
          if (!onAuthority(page, authorityHost)) return { category: 'federated' };
          await page.locator(SEL.passwd).first().fill(p.password);
          await page.locator(SEL.next).first().click();
          break;
        case 'otc':
          if (!onAuthority(page, authorityHost)) return { category: 'federated' };
          await page.locator(SEL.otc).first().fill(totp(p.totpSeed));
          await page.locator(SEL.otcSubmit).first().click();
          break;
        case 'pick_otp':
          await page.locator(SEL.otpProof).first().click();
          break;
        case 'other_mfa':
          if (!(await visible(page, SEL.otherWay))) return { category: 'mfa_not_totp' };
          await page.locator(SEL.otherWay).first().click();
          break;
        case 'kmsi':
          await page.locator(SEL.back).first().click();
          break;
        case 'account_tile':
          await page.locator(`[data-test-id=${JSON.stringify(p.username)}]`).first().click();
          break;
      }
    }
    return outcome() ?? { category: 'page_changed' };
  }

  async close(): Promise<void> {
    const contexts = [...this.contexts.values()];
    this.contexts.clear();
    await Promise.all(contexts.map((c) => c.close().catch(() => {})));
    await this.browser.close().catch(() => {});
  }
}
