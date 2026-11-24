import { describe, it, expect, vi } from 'vitest';
import { graphRequest } from '../src/graph.js';

const ok = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('graphRequest', () => {
  it('sends the bearer token only to graph.microsoft.com', async () => {
    const f = vi.fn(async () => ok({ a: 1 }));
    const r = await graphRequest(f as unknown as typeof fetch, 'tok', { method: 'GET', path: '/me', apiVersion: 'v1.0' });
    expect(r).toEqual({ status: 200, body: { a: 1 } });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(new URL(url).host).toBe('graph.microsoft.com');
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer tok');
    expect(init.redirect).toBe('manual');
    expect(init.body).toBeUndefined();
  });
  it('adds ConsistencyLevel for $count and $search only', async () => {
    const f = vi.fn(async () => ok({}));
    await graphRequest(f as unknown as typeof fetch, 't', { method: 'GET', path: '/users?$count=true', apiVersion: 'v1.0' });
    await graphRequest(f as unknown as typeof fetch, 't', { method: 'GET', path: '/me', apiVersion: 'v1.0' });
    const h0 = (f.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    const h1 = (f.mock.calls[1] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(h0.ConsistencyLevel).toBe('eventual');
    expect(h1.ConsistencyLevel).toBeUndefined();
  });
  it('sends JSON body with content type', async () => {
    const f = vi.fn(async () => ok({}, 201));
    await graphRequest(f as unknown as typeof fetch, 't', { method: 'POST', path: '/users', body: { x: 1 }, apiVersion: 'beta' });
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain('/beta/users');
    expect(init.body).toBe('{"x":1}');
    expect((init.headers as Record<string, string>)['Content-Type']).toBe('application/json');
  });
  it('rejects invalid paths before fetch', async () => {
    const f = vi.fn();
    for (const p of ['https://evil.com/x', '//evil.com', '/../x']) {
      await expect(graphRequest(f as unknown as typeof fetch, 't', { method: 'GET', path: p, apiVersion: 'v1.0' })).rejects.toMatchObject({ code: 'invalid_path' });
    }
    expect(f).not.toHaveBeenCalled();
  });
  it('does not follow redirects', async () => {
    const f = vi.fn(async () => new Response(null, { status: 302, headers: { location: 'https://evil.com' } }));
    const r = await graphRequest(f as unknown as typeof fetch, 't', { method: 'GET', path: '/me', apiVersion: 'v1.0' });
    expect(r).toEqual({ status: 302, body: { redirected: true } });
  });
  it('returns non-JSON as truncated text and maps network errors', async () => {
    const big = 'x'.repeat(200 * 1024);
    const r = await graphRequest((async () => new Response(big, { status: 200 })) as unknown as typeof fetch, 't', { method: 'GET', path: '/me', apiVersion: 'v1.0' });
    expect((r.body as string).length).toBe(100 * 1024);
    await expect(graphRequest((async () => { throw new Error('boom tok'); }) as unknown as typeof fetch, 't', { method: 'GET', path: '/me', apiVersion: 'v1.0' }))
      .rejects.toMatchObject({ code: 'graph_failed', message: 'Could not reach Microsoft Graph.' });
  });
});
