import type { AuditLog } from '../audit.js';
import { BrokerError } from '../errors.js';
import type { Redactor } from '../redact.js';
import type { Credential } from '../vault/vault.js';
import { permissionScopes, type Resource } from './resources.js';
import { SignInError, type SignInBrowser, type SignInParams } from './signin.js';

const REFRESH_MARGIN_MS = 5 * 60_000;

export interface TokenManagerDeps {
  authority: string;
  getBrowser: () => Promise<SignInBrowser>;
  fetch: typeof fetch;
  redactor: Redactor;
  now?: () => number;
  /**
   * Asks the user whether to approve an app for the organisation when Microsoft wants consent.
   * Without it (or on No, or if asking fails) sign-in ends with needs_consent, as before.
   */
  approveConsent?: (r: ConsentRequest) => Promise<boolean>;
  audit?: Pick<AuditLog, 'write'>;
  /** Pause after granting consent before signing in again, while Microsoft applies it. */
  consentWaitMs?: number;
}

/** What the user is asked to approve: one Microsoft app, for one tenant, with these permissions. */
export interface ConsentRequest {
  alias: string;
  tenant: string;
  account: string;
  appName: string;
  scopes: string[];
}

interface CacheEntry {
  clientId: string;
  token: string;
  refreshToken?: string;
  upn: string;
  expiresAt: number;
}

function claims(jwt: string | undefined): Record<string, unknown> {
  try {
    const part = jwt?.split('.')[1];
    if (!part) return {};
    const v = JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

const str = (v: unknown): string | undefined => (typeof v === 'string' && v ? v : undefined);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Acquires, caches and refreshes access tokens per (alias, resource). */
export class TokenManager {
  /** alias -> resource key -> entry. Nested so an alias containing ":" cannot collide with another. */
  private cache = new Map<string, Map<string, CacheEntry>>();
  private inflight = new Map<string, Promise<{ token: string; upn: string }>>();
  /** "alias, app" pairs whose consent the user declined; not asked again until disconnect. */
  private declined = new Set<string>();
  private browserP: Promise<SignInBrowser> | undefined;
  private now: () => number;

  constructor(private deps: TokenManagerDeps) {
    this.now = deps.now ?? Date.now;
  }

  getAccessToken(cred: Credential, resource: Resource): Promise<{ token: string; upn: string }> {
    const key = JSON.stringify([cred.alias, resource.key]);
    const running = this.inflight.get(key);
    if (running) return running;
    const p = this.acquire(cred, resource).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  async drop(alias?: string): Promise<void> {
    if (alias === undefined) {
      this.cache.clear();
      this.declined.clear();
      const bp = this.browserP;
      this.browserP = undefined;
      // A launch that failed has nothing to close.
      const browser = bp ? await bp.catch(() => undefined) : undefined;
      await browser?.close();
      return;
    }
    this.cache.delete(alias);
    for (const k of [...this.declined]) if ((JSON.parse(k) as string[])[0] === alias) this.declined.delete(k);
  }

  private async acquire(cred: Credential, resource: Resource) {
    const entries = this.cache.get(cred.alias);
    const cached = entries?.get(resource.key);
    if (cached && cached.expiresAt - this.now() > REFRESH_MARGIN_MS) {
      return { token: cached.token, upn: cached.upn };
    }
    // The resource's own refresh token first; otherwise one this alias already holds for the same app
    // (Teams needs a Graph token and a Teams token; SharePoint one per host). That saves a second sign-in.
    const refreshToken = cached?.refreshToken
      ?? [...(entries?.values() ?? [])].find((e) => e.clientId === resource.clientId && e.refreshToken)?.refreshToken;
    if (refreshToken) {
      try {
        return this.store(cred, resource, await this.refresh(cred, resource, refreshToken));
      } catch (e) {
        if (e instanceof BrokerError && e.code === 'wrong_account') throw e;
        entries?.delete(resource.key);
      }
    }
    const { code, verifier } = await this.signIn(cred, resource);
    const body = new URLSearchParams({
      client_id: resource.clientId,
      grant_type: 'authorization_code',
      code,
      redirect_uri: resource.redirectUri,
      code_verifier: verifier,
      scope: resource.scopes.join(' '),
    });
    return this.store(cred, resource, await this.post(cred.tenant, resource, body));
  }

  /** Browser sign-in. If Microsoft wants consent for the app and the user says Yes, grants it and signs in again. */
  private async signIn(cred: Credential, resource: Resource): Promise<{ code: string; verifier: string }> {
    const browser = await this.browser();
    const params: SignInParams = {
      authority: this.deps.authority,
      tenant: cred.tenant,
      resource,
      username: cred.username,
      password: cred.password,
      totpSeed: cred.totpSeed,
    };
    try {
      return await browser.authorize(params);
    } catch (e) {
      const { approveConsent, audit } = this.deps;
      const declinedKey = JSON.stringify([cred.alias, resource.clientId]);
      if (!(e instanceof SignInError) || e.category !== 'needs_consent' || !approveConsent || this.declined.has(declinedKey)) throw e;
      const approved = await approveConsent({
        alias: cred.alias,
        tenant: cred.tenant,
        account: cred.username,
        appName: resource.appName,
        scopes: permissionScopes(resource),
      }).catch(() => false);
      if (!approved) {
        this.declined.add(declinedKey);
        throw e;
      }
      try {
        await browser.grantConsent(params);
      } catch (g) {
        audit?.write({ type: 'consent_failed', tenant: cred.alias, detail: `${resource.appName}: ${g instanceof SignInError ? g.category : 'error'}` });
        throw g;
      }
      audit?.write({ type: 'consent_granted', tenant: cred.alias, detail: resource.appName });
      await sleep(this.deps.consentWaitMs ?? 3000);
      return browser.authorize(params);
    }
  }

  /** Launches the sign-in browser once; a failed launch is forgotten so the next call retries. */
  private browser(): Promise<SignInBrowser> {
    if (!this.browserP) {
      const p = this.deps.getBrowser().catch(() => {
        if (this.browserP === p) this.browserP = undefined;
        // Launch errors can quote paths and command lines: never pass them through.
        throw new BrokerError('browser_failed', 'Could not start Microsoft Edge for sign-in. Is Edge installed?');
      });
      this.browserP = p;
    }
    return this.browserP;
  }

  private refresh(cred: Credential, resource: Resource, refreshToken: string): Promise<CacheEntry> {
    return this.post(
      cred.tenant,
      resource,
      new URLSearchParams({
        client_id: resource.clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: resource.scopes.join(' '),
      }),
      refreshToken,
    );
  }

  private store(cred: Credential, resource: Resource, entry: CacheEntry) {
    let entries = this.cache.get(cred.alias);
    if (entry.upn.toLowerCase() !== cred.username.toLowerCase()) {
      entries?.delete(resource.key);
      throw new BrokerError('wrong_account', 'Signed in as a different account than the Bitwarden item.');
    }
    if (!entries) {
      entries = new Map();
      this.cache.set(cred.alias, entries);
    }
    entries.set(resource.key, entry);
    return { token: entry.token, upn: entry.upn };
  }

  private async post(tenant: string, resource: Resource, body: URLSearchParams, previousRefresh?: string): Promise<CacheEntry> {
    let res: Response;
    try {
      res = await this.deps.fetch(`${this.deps.authority}/${tenant}/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
    } catch {
      throw new BrokerError('token_failed', 'Could not reach the Microsoft token endpoint.');
    }
    let json: Record<string, unknown> = {};
    try {
      json = (await res.json()) as Record<string, unknown>;
    } catch {
      /* non-JSON body: ignored */
    }
    const accessToken = str(json.access_token);
    if (!res.ok || !accessToken) {
      const code = str(json.error)?.replace(/[^\w.-]/g, '').slice(0, 64);
      throw new BrokerError('token_failed', `Token request failed${code ? `: ${code}` : ` (HTTP ${res.status})`}.`);
    }
    const refreshToken = str(json.refresh_token);
    this.deps.redactor.add(accessToken);
    this.deps.redactor.add(refreshToken);
    this.deps.redactor.add(str(json.id_token));
    const idc = claims(str(json.id_token));
    const ac = claims(accessToken);
    const upn = str(idc.preferred_username) ?? str(ac.upn) ?? str(ac.unique_name) ?? '';
    const expiresIn = typeof json.expires_in === 'number' ? json.expires_in : Number(json.expires_in) || 3600;
    return { clientId: resource.clientId, token: accessToken, refreshToken: refreshToken ?? previousRefresh, upn, expiresAt: this.now() + expiresIn * 1000 };
  }
}
