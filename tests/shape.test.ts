import { describe, expect, it } from 'vitest';
import { capResult } from '../src/shape.js';

const big = (n: number) => Array.from({ length: n }, (_, i) => ({ id: i, name: `user-${i}`, mail: `user-${i}@contoso.com` }));

describe('capResult', () => {
  it('returns small values unchanged', () => {
    for (const v of [null, 5, 'x', { a: 1 }, [1, 2, 3], { value: [{ id: 1 }] }]) expect(capResult(v)).toEqual(v);
  });

  it('cuts a huge array to whole items and reports the true total', () => {
    const out = capResult(big(10_000)) as { truncated: boolean; totalItems: number; shownItems: number; note: string; items: unknown[] };
    expect(out.truncated).toBe(true);
    expect(out.totalItems).toBe(10_000);
    expect(out.shownItems).toBe(out.items.length);
    expect(out.shownItems).toBeGreaterThan(0);
    expect(out.shownItems).toBeLessThan(10_000);
    expect(out.items[0]).toEqual({ id: 0, name: 'user-0', mail: 'user-0@contoso.com' });
    expect(JSON.stringify(out).length).toBeLessThanOrEqual(31_000);
    expect(out.note).toMatch(/select|first|filter/i);
  });

  it('cuts a Graph page, keeping nextLink and using @odata.count as the total', () => {
    const page = { '@odata.context': 'ctx', '@odata.count': 12345, '@odata.nextLink': 'https://graph.microsoft.com/v1.0/users?$skiptoken=x', value: big(5000) };
    const out = capResult(page) as Record<string, unknown> & { value: unknown[] };
    expect(out.truncated).toBe(true);
    expect(out.totalItems).toBe(12345);
    expect(out.shownItems).toBe(out.value.length);
    expect(out['@odata.nextLink']).toBe(page['@odata.nextLink']);
    expect(JSON.stringify(out).length).toBeLessThanOrEqual(31_000);
  });

  it('reports a known total even when the items fit', () => {
    const out = capResult(big(200), { total: 500 }) as { truncated: boolean; totalItems: number; shownItems: number; items: unknown[] };
    expect(out.truncated).toBe(true);
    expect(out.totalItems).toBe(500);
    expect(out.shownItems).toBe(200);
    expect(capResult(big(3), { total: 3 })).toEqual(big(3));
  });

  it('cuts any other oversized value by characters', () => {
    const out = capResult({ blob: 'x'.repeat(100_000) }) as { truncated: boolean; text: string; note: string };
    expect(out.truncated).toBe(true);
    expect(out.text.length).toBeLessThanOrEqual(30_000);
    const s = capResult('y'.repeat(50_000), { maxChars: 1000 }) as { truncated: boolean; text: string };
    expect(s.text.length).toBeLessThanOrEqual(1000);
  });

  it('keeps at least one item even if it alone is over the cap, cut as text', () => {
    const out = capResult([{ blob: 'x'.repeat(100_000) }]) as { truncated: boolean; text?: string };
    expect(out.truncated).toBe(true);
    expect(JSON.stringify(out).length).toBeLessThanOrEqual(31_000);
  });
});
