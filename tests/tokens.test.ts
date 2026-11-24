import { describe, it, expect, vi } from 'vitest';
import { TokenManager } from '../src/auth/tokens.js';
import { Redactor } from '../src/redact.js';
import { BrokerError } from '../src/errors.js';
import type { Resource } from '../src/auth/resources.js';
import type { Credential } from '../src/vault/vault.js';

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (claims: object) => `eyJ${b64({ alg: 'none' }).slice(3)}.${b64(claims)}.sig`;

const res: Resource = { key: 'graph', clientId: 'cid', redirectUri: 'http://localhost', scopes: ['a', 'offline_access'] };
const cred: Credential = { alias: 'acme', username: 'Admin@acme.com', password: 'pw', totpSeed: 'SEED', tenant: 'acme.com' };

function tokenResp(n: number, upn = 'admin@acme.com', expires = 3600) {
  return new Response(
    JSON.stringify({
      access_token: jwt({ upn, n }),
      refresh_token: `refresh-token-${n}`,
      id_token: jwt({ preferred_username: upn }),
      expires_in: expires,
    }),
    { status: 200 },
  );
}

function setup(responses: Array<() => Response | Promise<Response>>) {
  let t = 1_000_000;
  const calls: Array<{ url: string; body: URLSearchParams }> = [];
  let i = 0;
  const fetchFn = vi.fn(async (url: string, init: { body: string }) => {
    calls.push({ url, body: new URLSearchParams(init.body) });
    return responses[i++]!();
  });
  const browser = { authorize: vi.fn(async () => ({ code: 'CODE', verifier: 'VER' })), close: vi.fn(async () => {}) };
  const getBrowser = vi.fn(async () => browser as never);
  const redactor = new Redactor();
  const tm = new TokenManager({
    authority: 'https://login.example',
    getBrowser,
    fetch: fetchFn as never,
    redactor,
    now: () => t,
  });
  return { tm, calls, browser, getBrowser, redactor, advance: (ms: number) => (t += ms) };
}

describe('TokenManager', () => {
  it('exchanges the code on first call and caches', async () => {
    const s = setup([() => tokenResp(1)]);
    const r1 = await s.tm.getAccessToken(cred, res);
    expect(r1.upn).toBe('admin@acme.com');
    expect(s.calls[0]!.url).toBe('https://login.example/acme.com/oauth2/v2.0/token');
    const b = s.calls[0]!.body;
    expect(b.get('grant_type')).toBe('authorization_code');
    expect(b.get('code')).toBe('CODE');
    expect(b.get('code_verifier')).toBe('VER');
    expect(b.get('client_id')).toBe('cid');
    expect(b.get('redirect_uri')).toBe('http://localhost');
    expect(b.get('scope')).toBe('a offline_access');
    const r2 = await s.tm.getAccessToken(cred, res);
    expect(r2.token).toBe(r1.token);
    expect(s.calls).toHaveLength(1);
  });

  it('refreshes near expiry without authorize', async () => {
    const s = setup([() => tokenResp(1), () => tokenResp(2)]);
    await s.tm.getAccessToken(cred, res);
    s.advance(56 * 60_000);
    const r = await s.tm.getAccessToken(cred, res);
    expect(s.browser.authorize).toHaveBeenCalledTimes(1);
    expect(s.calls[1]!.body.get('grant_type')).toBe('refresh_token');
    expect(s.calls[1]!.body.get('refresh_token')).toBe('refresh-token-1');
    expect(r.token).toContain('.');
  });

  it('falls back to authorize when refresh fails', async () => {
    const s = setup([() => tokenResp(1), () => new Response('{"error":"invalid_grant"}', { status: 400 }), () => tokenResp(3)]);
    await s.tm.getAccessToken(cred, res);
    s.advance(56 * 60_000);
    await s.tm.getAccessToken(cred, res);
    expect(s.browser.authorize).toHaveBeenCalledTimes(2);
    expect(s.calls[1]!.body.get('grant_type')).toBe('refresh_token');
    expect(s.calls[2]!.body.get('grant_type')).toBe('authorization_code');
  });

  it('error message has the error code only and never the body', async () => {
    const body = JSON.stringify({ error: 'invalid_grant', error_description: 'secret desc', access_token: 'eyJhbGciOi.abc.def' });
    const s = setup([() => new Response(body, { status: 400 })]);
    const err = await s.tm.getAccessToken(cred, res).catch((e) => e);
    expect(err).toBeInstanceOf(BrokerError);
    expect(err.code).toBe('token_failed');
    expect(err.message).toContain('invalid_grant');
    expect(err.message).not.toContain('eyJ');
    expect(err.message).not.toContain('secret desc');
  });

  it('maps network errors', async () => {
    const s = setup([() => Promise.reject(new Error('boom https://x?code=1'))]);
    const err = await s.tm.getAccessToken(cred, res).catch((e) => e);
    expect(err.code).toBe('token_failed');
    expect(err.message).toBe('Could not reach the Microsoft token endpoint.');
  });

  it('registers tokens with the redactor', async () => {
    const s = setup([() => tokenResp(1)]);
    const { token } = await s.tm.getAccessToken(cred, res);
    expect(s.redactor.scrub(`x ${token} y refresh-token-1`)).toBe('x [REDACTED] y [REDACTED]');
    const id = jwt({ preferred_username: 'admin@acme.com' });
    expect(s.redactor.scrub(`id ${id}`)).toBe('id [REDACTED]');
  });

  it('rejects a token for a different account and drops the cache', async () => {
    const s = setup([() => tokenResp(1, 'other@acme.com'), () => tokenResp(2)]);
    const err = await s.tm.getAccessToken(cred, res).catch((e) => e);
    expect(err.code).toBe('wrong_account');
    expect(err.message).toBe('Signed in as a different account than the Bitwarden item.');
    await s.tm.getAccessToken(cred, res);
    expect(s.browser.authorize).toHaveBeenCalledTimes(2);
  });

  it('rejects wrong account on refresh', async () => {
    const s = setup([() => tokenResp(1), () => tokenResp(2, 'other@acme.com')]);
    await s.tm.getAccessToken(cred, res);
    s.advance(56 * 60_000);
    const err = await s.tm.getAccessToken(cred, res).catch((e) => e);
    expect(err.code).toBe('wrong_account');
    expect(s.browser.authorize).toHaveBeenCalledTimes(1);
  });

  it('keeps the previous refresh token when the response omits one', async () => {
    const noRefresh = () =>
      new Response(JSON.stringify({ access_token: jwt({ upn: 'admin@acme.com', n: 2 }), id_token: jwt({ preferred_username: 'admin@acme.com' }), expires_in: 3600 }), { status: 200 });
    const s = setup([() => tokenResp(1), noRefresh, () => tokenResp(3)]);
    await s.tm.getAccessToken(cred, res);
    s.advance(56 * 60_000);
    await s.tm.getAccessToken(cred, res);
    s.advance(56 * 60_000);
    await s.tm.getAccessToken(cred, res);
    expect(s.calls[2]!.body.get('grant_type')).toBe('refresh_token');
    expect(s.calls[2]!.body.get('refresh_token')).toBe('refresh-token-1');
  });

  it('launches one browser for concurrent acquisitions of different keys', async () => {
    const s = setup([() => tokenResp(1), () => tokenResp(2)]);
    const exo: Resource = { ...res, key: 'exo' };
    await Promise.all([s.tm.getAccessToken(cred, res), s.tm.getAccessToken(cred, exo)]);
    expect(s.getBrowser).toHaveBeenCalledTimes(1);
  });

  it('shares one in-flight acquisition', async () => {
    const s = setup([() => tokenResp(1)]);
    const [a, b] = await Promise.all([s.tm.getAccessToken(cred, res), s.tm.getAccessToken(cred, res)]);
    expect(a.token).toBe(b.token);
    expect(s.calls).toHaveLength(1);
  });

  it('drop(alias) forgets that alias; drop() closes the browser', async () => {
    const s = setup([() => tokenResp(1), () => tokenResp(2)]);
    await s.tm.getAccessToken(cred, res);
    await s.tm.drop('acme');
    await s.tm.getAccessToken(cred, res);
    expect(s.calls).toHaveLength(2);
    await s.tm.drop();
    expect(s.browser.close).toHaveBeenCalledTimes(1);
  });

  it('maps a failed browser launch to browser_failed and retries the launch on the next call', async () => {
    const s = setup([() => tokenResp(1)]);
    s.getBrowser.mockImplementationOnce(async () => {
      throw new Error('browserType.launch: Executable doesn\'t exist at C:\\Program Files\\msedge.exe');
    });
    const e = await s.tm.getAccessToken(cred, res).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(BrokerError);
    expect(e).toMatchObject({ code: 'browser_failed', message: 'Could not start Microsoft Edge for sign-in. Is Edge installed?' });
    const r = await s.tm.getAccessToken(cred, res);
    expect(r.upn).toBe('admin@acme.com');
    expect(s.getBrowser).toHaveBeenCalledTimes(2);
    await s.tm.drop();
    expect(s.browser.close).toHaveBeenCalledOnce();
  });

  it('drop() after a failed launch does not throw', async () => {
    const s = setup([]);
    let fail!: (e: Error) => void;
    s.getBrowser.mockImplementationOnce(() => new Promise((_r, rej) => { fail = rej; }));
    const pending = s.tm.getAccessToken(cred, res).catch((x: unknown) => x);
    await Promise.resolve();
    const dropped = s.tm.drop();
    fail(new Error('launch failed'));
    await expect(dropped).resolves.toBeUndefined();
    expect(await pending).toMatchObject({ code: 'browser_failed' });
  });

  it('drop() without a browser does not obtain one', async () => {
    const s = setup([]);
    await s.tm.drop();
    expect(s.getBrowser).not.toHaveBeenCalled();
  });
});
