import { BrokerError } from '../errors.js';
import type { Redactor } from '../redact.js';
import type { Credential } from '../vault/vault.js';
import type { Resource } from './resources.js';
import type { SignInBrowser } from './signin.js';

const REFRESH_MARGIN_MS = 5 * 60_000;

export interface TokenManagerDeps {
  authority: string;
  getBrowser: () => Promise<SignInBrowser>;
  fetch: typeof fetch;
  redactor: Redactor;
  now?: () => number;
}

interface CacheEntry {
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

/** Acquires, caches and refreshes access tokens per (alias, resource). */
export class TokenManager {
  private cache = new Map<string, CacheEntry>();
  private inflight = new Map<string, Promise<{ token: string; upn: string }>>();
  private browserP: Promise<SignInBrowser> | undefined;
  private now: () => number;

  constructor(private deps: TokenManagerDeps) {
    this.now = deps.now ?? Date.now;
  }

  getAccessToken(cred: Credential, resource: Resource): Promise<{ token: string; upn: string }> {
    const key = `${cred.alias}:${resource.key}`;
    const running = this.inflight.get(key);
    if (running) return running;
    const p = this.acquire(key, cred, resource).finally(() => this.inflight.delete(key));
    this.inflight.set(key, p);
    return p;
  }

  async drop(alias?: string): Promise<void> {
    if (alias === undefined) {
      this.cache.clear();
      const bp = this.browserP;
      this.browserP = undefined;
      // A launch that failed has nothing to close.
      const browser = bp ? await bp.catch(() => undefined) : undefined;
      await browser?.close();
      return;
    }
    for (const k of [...this.cache.keys()]) if (k.startsWith(`${alias}:`)) this.cache.delete(k);
  }

  private async acquire(key: string, cred: Credential, resource: Resource) {
    const cached = this.cache.get(key);
    if (cached && cached.expiresAt - this.now() > REFRESH_MARGIN_MS) {
      return { token: cached.token, upn: cached.upn };
    }
    if (cached?.refreshToken) {
      try {
        return await this.store(key, cred, await this.refresh(cred, resource, cached.refreshToken));
      } catch (e) {
        if (e instanceof BrokerError && e.code === 'wrong_account') throw e;
        this.cache.delete(key);
      }
    }
    const browser = await this.browser();
    const { code, verifier } = await browser.authorize({
      authority: this.deps.authority,
      tenant: cred.tenant,
      resource,
      username: cred.username,
      password: cred.password,
      totpSeed: cred.totpSeed,
    });
    const body = new URLSearchParams({
      client_id: resource.clientId,
      grant_type: 'authorization_code',
      code,
      redirect_uri: resource.redirectUri,
      code_verifier: verifier,
      scope: resource.scopes.join(' '),
    });
    return this.store(key, cred, await this.post(cred.tenant, body));
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
      new URLSearchParams({
        client_id: resource.clientId,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        scope: resource.scopes.join(' '),
      }),
      refreshToken,
    );
  }

  private store(key: string, cred: Credential, entry: CacheEntry) {
    if (entry.upn.toLowerCase() !== cred.username.toLowerCase()) {
      this.cache.delete(key);
      throw new BrokerError('wrong_account', 'Signed in as a different account than the Bitwarden item.');
    }
    this.cache.set(key, entry);
    return { token: entry.token, upn: entry.upn };
  }

  private async post(tenant: string, body: URLSearchParams, previousRefresh?: string): Promise<CacheEntry> {
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
    return { token: accessToken, refreshToken: refreshToken ?? previousRefresh, upn, expiresAt: this.now() + expiresIn * 1000 };
  }
}
