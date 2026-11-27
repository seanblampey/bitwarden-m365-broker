import { chromium, type Browser, type BrowserContext, type Page, type Request, type Route } from 'playwright-core';
import { BrokerError } from '../errors.js';
import { randomBytes } from 'node:crypto';
import { pkcePair, totp } from '../crypto.js';
import { permissionScopes, type Resource } from './resources.js';

export type SignInCategory =
  | 'wrong_password' | 'mfa_not_totp' | 'needs_consent' | 'conditional_access'
  | 'federated' | 'account_locked' | 'mfa_setup_required' | 'wrong_tenant' | 'consent_not_allowed' | 'page_changed';

const MESSAGES: Record<SignInCategory, string> = {
  wrong_password: 'Microsoft rejected the password for this account.',
  mfa_not_totp: 'The account does not offer an authenticator-app code (TOTP) for MFA, so the broker cannot complete sign-in.',
  needs_consent: 'Microsoft asked for consent to the app, and it has not been approved for this tenant.',
  consent_not_allowed: 'Microsoft will not let this account approve the app for the organisation. The account needs a role that can grant admin consent (Global Administrator, Privileged Role Administrator or Cloud Application Administrator).',
  conditional_access: 'A Conditional Access policy blocked this sign-in.',
  federated: 'The account signs in through a federated identity provider, which the broker does not support.',
  account_locked: 'Microsoft reports that the account is locked or disabled.',
  mfa_setup_required: 'Microsoft wants this account to set up or update its MFA methods ("More information required"). Sign in once yourself and finish the setup, then try again.',
  wrong_tenant: 'Microsoft says this account does not exist in that tenant. Check the item\'s username and its tenant field.',
  page_changed: 'The Microsoft sign-in page did not look as expected or did not respond in time.',
};

export class SignInError extends BrokerError {
  category: SignInCategory;
  /** Where sign-in stopped (page address without query, title, heading, AADSTS code); never field values. */
  detail?: string;
  /** What the person should do about it (e.g. how to grant consent for this tenant). */
  help?: string;
  constructor(category: SignInCategory, detail?: string, help?: string) {
    super('signin_failed', [MESSAGES[category], help, detail && `Stopped at: ${detail}`].filter(Boolean).join(' '));
    this.name = 'SignInError';
    this.category = category;
    this.detail = detail;
    this.help = help;
  }
}

const GRAPH_PREFIX = 'https://graph.microsoft.com/';

/**
 * The sign-in browser itself went away (Edge crashed or was closed, e.g. by an Edge update or by closing the
 * window shown with showSignInWindow). Not a sign-in problem: the next try starts a fresh browser.
 */
export const browserGone = () => new BrokerError(
  'browser_failed',
  'The sign-in browser (Microsoft Edge) closed or stopped responding. Try again: the broker starts a fresh one.',
);

/**
 * Microsoft's admin-consent page for one app in one tenant. It asks for every scope sign-in asks for,
 * OpenID Connect ones included: a grant without `openid`/`profile` sends the next sign-in straight back
 * to a consent page (incremental consent), however often the admin approves.
 */
export function adminConsentUrl(authority: string, tenant: string, resource: Resource, state?: string): string {
  const q = new URLSearchParams({
    client_id: resource.clientId,
    scope: resource.scopes.join(' '),
    redirect_uri: resource.redirectUri,
  });
  if (state) q.set('state', state);
  return `${authority.replace(/\/+$/, '')}/${encodeURIComponent(tenant)}/v2.0/adminconsent?${q}`;
}

/**
 * Steps for an administrator to grant consent once in this tenant by hand, so the message tells
 * whoever reads it exactly what to do. Never includes the account name or any secret.
 */
export function consentHelp(authority: string, tenant: string, resource: Resource): string {
  const ways = [
    `open this link in your browser and click Accept: ${adminConsentUrl(authority, tenant, resource)} `
      + '(afterwards the browser may show a page that cannot be reached; that is expected and consent is done)',
  ];
  if (resource.key === 'graph') {
    const short = permissionScopes(resource).filter((x) => x.startsWith(GRAPH_PREFIX)).map((x) => x.slice(GRAPH_PREFIX.length));
    ways.push(
      `in Windows PowerShell run: Connect-MgGraph -TenantId ${tenant} -Scopes ${short.map((x) => `"${x}"`).join(',')} `
        + 'and tick "Consent on behalf of your organization" before accepting '
        + '(needs the Microsoft.Graph.Authentication module: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser)',
    );
  }
  if (resource.connectHint) ways.push(`in PowerShell run ${resource.connectHint} once, sign in and accept the prompt`);
  return `To approve "${resource.appName}" for tenant ${tenant} yourself (once per tenant), signed in as that tenant's admin, do ONE of these: `
    + `${ways.map((w, i) => `(${i + 1}) ${w}`).join('; ')}. Then try again.`;
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
  | 'consent' | 'needs_admin' | 'federated' | 'aad_error' | 'proof_up' | 'password_error' | 'kmsi' | 'otc' | 'pick_otp' | 'other_mfa'
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
  proofUp: '#idSubmit_ProofUp_Redirect',
  heading: '#loginHeader, [role=heading], h1, .text-title, #idDiv_SAOTCAS_Title',
};

/**
 * Microsoft's sign-in is one page that keeps each finished step in the DOM, hidden with aria-hidden="true",
 * tabindex="-1" and opacity 0, often underneath the current one and earlier in document order. Playwright counts
 * opacity 0 as visible, so a plain `.first()` can pick the old step's heading or its #idSIButton9 (whose click then
 * waits on the covering step until it times out). Every selector the broker reads or acts on skips them.
 */
const ACTIVE = ':not([aria-hidden="true"]):not([aria-hidden="true"] *)';
/** Inputs and buttons of an inactive step are also taken out of the tab order. */
const FIELD = `${ACTIVE}:not([tabindex="-1"])`;
/** Applies `suffix` to every part of a selector list. Selectors here never contain a comma inside a part. */
const activeSelector = (sel: string, suffix: string = FIELD) => sel.split(',').map((x) => `${x.trim()}${suffix}`).join(', ');
const active = (page: Page, sel: string, suffix: string = FIELD) => page.locator(activeSelector(sel, suffix)).filter({ visible: true }).first();

/** The "Consent on behalf of your organization" box on the consent page Microsoft shows admins at sign-in. */
const ORG_CONSENT = /on behalf of (your|the) organi[sz]ation/i;
const CONSENT_HEADING = /^\s*permissions requested/i;

const AADSTS = /AADSTS\d{5,6}/;
const clip = (t: string | null | undefined, n = 80) => (t ?? '').replace(/\s+/g, ' ').trim().slice(0, n);

async function headingText(page: Page): Promise<string> {
  for (const el of await page.locator(activeSelector(SEL.heading, ACTIVE)).all().catch(() => [])) {
    if (await el.isVisible().catch(() => false)) {
      const t = clip(await el.innerText().catch(() => ''));
      if (t) return t;
    }
  }
  return '';
}

const bodyText = (page: Page) => page.locator('body').innerText({ timeout: 1000 }).catch(() => '');

/**
 * Where sign-in stopped, for diagnosis: page address (no query or fragment), title, visible
 * heading and any AADSTS error code. Never reads input values.
 */
async function describe(page: Page): Promise<string> {
  let where = '';
  try { const u = new URL(page.url()); where = `${u.host}${u.pathname}`; } catch { /* blank */ }
  const title = clip(await page.title().catch(() => ''));
  const heading = await headingText(page);
  const code = (await bodyText(page)).match(AADSTS)?.[0];
  return [where, title && `title "${title}"`, heading && heading !== title && `heading "${heading}"`, code]
    .filter(Boolean).join(', ') || 'no page loaded';
}

/** The account-picker tile for a user. Microsoft writes the address in lower case; Bitwarden may not. */
const accountTile = (username: string) => `[data-test-id=${JSON.stringify(username)} i]`;

const visible = (page: Page, sel: string, suffix: string = ACTIVE) => active(page, sel, suffix).isVisible().catch(() => false);

/** Microsoft's consent page, by any of its marks: a visible "Permissions requested" heading or the organisation box. */
async function consentShown(page: Page): Promise<boolean> {
  if (await visible(page, SEL.consent)) return true;
  if (await page.locator(activeSelector(SEL.heading, ACTIVE)).filter({ hasText: CONSENT_HEADING, visible: true }).count().catch(() => 0)) return true;
  return page.getByRole('checkbox', { name: ORG_CONSENT }).first().isVisible().catch(() => false);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Classify the current page; order matters (errors and consent win over input fields). */
async function detectState(page: Page, authorityHost: string, username: string): Promise<State> {
  let url: URL | undefined;
  try { url = new URL(page.url()); } catch { /* about:blank etc. */ }
  if (url && /\/consent/i.test(url.pathname)) return 'consent';
  if (url && /^https?:$/.test(url.protocol) && url.host !== authorityHost) return 'federated';
  if (await consentShown(page)) return 'consent';
  const heading = (await headingText(page)).toLowerCase();
  if (/^(need admin approval|approval required)/.test(heading)) return 'needs_admin';
  if ((await visible(page, SEL.proofUp)) || /^(more information required|action required|let's keep your account secure)/.test(heading)) return 'proof_up';
  if (await visible(page, SEL.passwordError)) return 'password_error';
  if ((await page.locator(activeSelector(SEL.kmsi, ACTIVE)).count().catch(() => 0)) > 0 && (await visible(page, SEL.back))) return 'kmsi';
  if (await visible(page, SEL.otc)) return 'otc';
  if (await visible(page, SEL.otpProof)) return 'pick_otp';
  if ((await visible(page, SEL.pushTitle)) || (await visible(page, SEL.pushProof))) return 'other_mfa';
  if (await visible(page, SEL.passwd)) return 'password';
  if (await visible(page, SEL.loginfmt)) return 'username';
  if (await visible(page, accountTile(username))) return 'account_tile';
  // Microsoft shows many sign-in errors on its own page instead of redirecting back.
  if (AADSTS.test(await bodyText(page))) return 'aad_error';
  return 'none';
}

/** Secrets are only ever typed into pages served by the authority itself. */
function onAuthority(page: Page, authorityHost: string): boolean {
  try { return new URL(page.url()).host === authorityHost; } catch { return false; }
}

function mapAuthError(error: string, description: string): SignInCategory {
  const s = `${error} ${description}`;
  if (/AADSTS5300[03]\b/.test(s)) return 'conditional_access';
  if (/AADSTS(65001|700016)\b/.test(s)) return 'needs_consent';
  if (/AADSTS(90094|90008)\b/.test(s)) return 'consent_not_allowed';
  if (/AADSTS(50053|50057)\b/.test(s)) return 'account_locked';
  if (/AADSTS50126\b/.test(s)) return 'wrong_password';
  if (/AADSTS(50072|50079)\b/.test(s)) return 'mfa_setup_required';
  if (/AADSTS(50020|50034|90072)\b/.test(s)) return 'wrong_tenant';
  return 'page_changed';
}

type Failure = { category: SignInCategory; detail?: string };
type Outcome = { code: string } | { consented: true } | Failure;
/** What a redirect back to the app means, once its state has been checked. */
type RedirectReader = (query: URLSearchParams) => Outcome;

function redirectFailure(sp: URLSearchParams): Failure {
  const err = sp.get('error') ?? '';
  const desc = sp.get('error_description') ?? '';
  const code = desc.match(AADSTS)?.[0];
  return { category: mapAuthError(err, desc), detail: `redirect error ${clip(err, 40)}${code ? ` ${code}` : ''}` };
}

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
  ) {
    // Everything held for a browser that died is dead too.
    browser.on('disconnected', () => {
      this.contexts.clear();
      this.signedIn.clear();
    });
  }

  /** False once the browser process has gone; the owner should launch a new SignInBrowser. */
  isConnected(): boolean {
    return this.browser.isConnected();
  }

  /**
   * Throws away one account's browser session (cookies), so its next sign-in starts from the login page.
   * Waits for any sign-in already running.
   */
  forget(username: string): Promise<void> {
    return this.enqueue(async () => {
      const user = username.toLowerCase();
      const context = this.contexts.get(user);
      this.contexts.delete(user);
      this.signedIn.delete(user);
      await context?.close().catch(() => {});
    });
  }

  static async launch(opts: LaunchOpts = {}): Promise<SignInBrowser> {
    const browser = await chromium.launch({
      headless: opts.headless ?? true,
      ...(opts.executablePath ? { executablePath: opts.executablePath } : { channel: opts.channel ?? 'msedge' }),
    });
    return new SignInBrowser(browser, opts.stepTimeoutMs ?? 15_000, opts.overallTimeoutMs ?? 60_000);
  }

  /** The account's context, or a new one if there is none or the old one was closed. */
  private async contextFor(user: string): Promise<BrowserContext> {
    if (!this.browser.isConnected()) throw browserGone();
    let context = this.contexts.get(user);
    if (!context) {
      // Playwright errors can quote internals: never pass them through.
      const created = await this.browser.newContext().catch(() => { throw browserGone(); });
      created.on('close', () => {
        if (this.contexts.get(user) === created) {
          this.contexts.delete(user);
          this.signedIn.delete(user);
        }
      });
      this.contexts.set(user, created);
      context = created;
    }
    return context;
  }

  authorize(p: SignInParams): Promise<{ code: string; verifier: string }> {
    return this.enqueue(() => this.authorizeNow(p));
  }

  /**
   * Approves the app for the whole organisation on Microsoft's admin-consent page.
   * The caller must have the user's explicit Yes first: this is the only code that clicks Accept.
   */
  grantConsent(p: SignInParams): Promise<void> {
    return this.enqueue(() => this.grantConsentNow(p));
  }

  private enqueue<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => {});
    return run;
  }

  private async authorizeNow(p: SignInParams): Promise<{ code: string; verifier: string }> {
    const { verifier, challenge } = pkcePair();
    const state = randomBytes(16).toString('base64url');
    const user = p.username.toLowerCase();
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
    const result = await this.visit(p, url, state, false, (sp) => {
      const code = sp.get('code');
      return sp.get('error') || !code ? redirectFailure(sp) : { code };
    });
    if (!('code' in result)) throw new SignInError('page_changed');
    this.signedIn.add(user);
    return { code: result.code, verifier };
  }

  private async grantConsentNow(p: SignInParams): Promise<void> {
    const state = randomBytes(16).toString('base64url');
    const url = adminConsentUrl(p.authority, p.tenant, p.resource, state);
    const result = await this.visit(p, url, state, true, (sp) => {
      if (sp.get('error')) return redirectFailure(sp);
      return /^true$/i.test(sp.get('admin_consent') ?? '') ? { consented: true } : { category: 'page_changed', detail: 'admin consent was not confirmed' };
    });
    if (!('consented' in result)) throw new SignInError('page_changed');
    // This account's context is signed in now, so the sign-in that follows must not ask to pick an account.
    this.signedIn.add(p.username.toLowerCase());
  }

  /**
   * Opens `url` in the account's context, works through Microsoft's pages, and returns what the redirect
   * back to the app said. Failures throw SignInError. `acceptConsent` is true only for grantConsent.
   */
  private async visit(p: SignInParams, url: string, state: string, acceptConsent: boolean, read: RedirectReader): Promise<Outcome> {
    const user = p.username.toLowerCase();
    const context = await this.contextFor(user);
    const authority = p.authority.replace(/\/+$/, '');

    let outcome: Outcome | undefined;
    const isRedirect = (u: string) => u.startsWith(p.resource.redirectUri);
    const capture = (u: string) => {
      if (outcome || !isRedirect(u)) return;
      const sp = new URL(u).searchParams;
      outcome = sp.get('state') !== state ? { category: 'page_changed' } : read(sp);
    };
    const matcher = (u: URL) => isRedirect(u.href);
    const handler = async (route: Route) => {
      capture(route.request().url());
      await route.abort().catch(() => {});
    };
    const onRequest = (r: Request) => capture(r.url());
    const cleanUp = async () => {
      context.off('request', onRequest);
      await context.unroute(matcher, handler).catch(() => {});
    };
    let page: Page;
    try {
      await context.route(matcher, handler);
      context.on('request', onRequest);
      page = await context.newPage();
    } catch {
      // The context or the whole browser is gone. Never let Playwright's error out: drop the context so the
      // next try gets a fresh one (and the owner a fresh browser, if this one died).
      await cleanUp();
      if (this.contexts.get(user) === context) {
        this.contexts.delete(user);
        this.signedIn.delete(user);
      }
      await context.close().catch(() => {});
      throw browserGone();
    }
    try {
      const result = await this.drive(page, url, new URL(authority).host, p, () => outcome, acceptConsent);
      if ('category' in result) {
        const help = result.category === 'needs_consent' ? consentHelp(authority, p.tenant, p.resource) : undefined;
        throw new SignInError(result.category, result.detail, help);
      }
      return result;
    } catch (e) {
      // Playwright errors can quote selectors or page content: never pass them through.
      if (e instanceof BrokerError) throw e;
      if (!this.browser.isConnected() || page.isClosed()) throw browserGone();
      const detail = `${await describe(page)} (an expected button or field did not respond)`;
      // Stuck on the consent page: the person can still approve by hand, so say how instead of page_changed.
      if (await consentShown(page).catch(() => false)) throw new SignInError('needs_consent', detail, consentHelp(authority, p.tenant, p.resource));
      throw new SignInError('page_changed', detail);
    } finally {
      await cleanUp();
      await page.close().catch(() => {});
    }
  }

  private async drive(page: Page, url: string, authorityHost: string, p: SignInParams, outcome: () => Outcome | undefined, acceptConsent: boolean): Promise<Outcome> {
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
          if (s === 'none') return { category: 'page_changed', detail: await describe(page) };
          break;
        }
        await sleep(150);
      }
      const n = (actions.get(state) ?? 0) + 1;
      actions.set(state, n);
      if (n > 3) return { category: state === 'consent' ? 'needs_consent' : 'page_changed', detail: `${await describe(page)} (still there after 3 tries)` };
      marker = Date.now();
      await page.evaluate((m) => { (window as any).__sib = m; }, marker).catch(() => {});

      switch (state) {
        case 'consent': {
          if (!acceptConsent) return { category: 'needs_consent', detail: await describe(page) };
          // Reached only from grantConsent, i.e. after the user's explicit Yes; and only on Microsoft's own page.
          if (!onAuthority(page, authorityHost)) return { category: 'federated', detail: await describe(page) };
          const stuck = await this.acceptConsent(page, left());
          if (stuck) return { category: 'needs_consent', detail: `${await describe(page)} (${stuck})` };
          break;
        }
        case 'needs_admin': return { category: 'consent_not_allowed' };
        case 'federated': return { category: 'federated', detail: await describe(page) };
        case 'proof_up': return { category: 'mfa_setup_required' };
        case 'aad_error': {
          const code = (await bodyText(page)).match(AADSTS)?.[0] ?? '';
          const category = mapAuthError(code, '');
          return category === 'page_changed' ? { category, detail: await describe(page) } : { category, detail: code };
        }
        case 'password_error': return { category: 'wrong_password' };
        case 'username':
          await active(page, SEL.loginfmt).fill(p.username);
          await active(page, SEL.next).click();
          break;
        case 'password':
          if (!onAuthority(page, authorityHost)) return { category: 'federated' };
          await active(page, SEL.passwd).fill(p.password);
          await active(page, SEL.next).click();
          break;
        case 'otc':
          if (!onAuthority(page, authorityHost)) return { category: 'federated' };
          await active(page, SEL.otc).fill(totp(p.totpSeed));
          await active(page, SEL.otcSubmit).click();
          break;
        case 'pick_otp':
          await active(page, SEL.otpProof, ACTIVE).click();
          break;
        case 'other_mfa':
          if (!(await visible(page, SEL.otherWay))) return { category: 'mfa_not_totp' };
          await active(page, SEL.otherWay, ACTIVE).click();
          break;
        case 'kmsi':
          await active(page, SEL.back).click();
          break;
        case 'account_tile':
          await active(page, accountTile(p.username), ACTIVE).click();
          break;
      }
    }
    return outcome() ?? { category: 'page_changed', detail: `${await describe(page)} (timed out)` };
  }

  /**
   * On the consent page, after the user's Yes: ticks "Consent on behalf of your organization" when the page has it
   * (without it, Accept approves the app for this one account and Microsoft asks again for everyone else), then
   * clicks the visible Accept. Returns why it could not, or undefined once Accept was clicked.
   */
  private async acceptConsent(page: Page, timeoutMs: number): Promise<string | undefined> {
    const org = page.getByRole('checkbox', { name: ORG_CONSENT }).first();
    if (await org.isVisible().catch(() => false)) {
      if (!(await org.isChecked().catch(() => false))) {
        // Microsoft styles this box; if the input itself will not take the click, its label will.
        await org.check({ timeout: 2000 }).catch(() => page.getByText(ORG_CONSENT).first().click({ timeout: 2000 }).catch(() => {}));
      }
      if (!(await org.isChecked().catch(() => false))) return 'could not tick "Consent on behalf of your organization"';
    }
    // getByRole leaves out aria-hidden steps; #idSIButton9 (active step only) covers a page in another language.
    const accept = page.getByRole('button', { name: /^\s*accept\s*$/i }).or(page.locator(activeSelector(SEL.next))).filter({ visible: true }).first();
    try {
      await accept.waitFor({ state: 'visible', timeout: Math.min(timeoutMs, 5000) });
    } catch {
      return 'no Accept button found';
    }
    await accept.click();
    return undefined;
  }

  async close(): Promise<void> {
    const contexts = [...this.contexts.values()];
    this.contexts.clear();
    await Promise.all(contexts.map((c) => c.close().catch(() => {})));
    await this.browser.close().catch(() => {});
  }
}
