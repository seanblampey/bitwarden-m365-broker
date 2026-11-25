/** Results larger than this many characters of JSON are cut before they reach the model. */
export const MAX_RESULT_CHARS = 30_000;

const NOTE =
  'Result cut to fit. Narrow the request instead of paging through it: ask for fewer fields (select / $select), '
  + 'fewer items (first / $top), or filter on the server ($filter, -Filter, -Identity).';

const size = (v: unknown): number => (JSON.stringify(v) ?? 'null').length;

/** How many leading items fit in `budget` characters of JSON (commas included). */
function fit(items: unknown[], budget: number): number {
  let used = 2; // [ ]
  let n = 0;
  for (const item of items) {
    const cost = size(item) + (n > 0 ? 1 : 0);
    if (used + cost > budget) break;
    used += cost;
    n++;
  }
  return n;
}

function cutText(value: unknown, maxChars: number): { truncated: true; note: string; text: string } {
  const json = typeof value === 'string' ? value : (JSON.stringify(value) ?? 'null');
  // Leave room for the wrapper and for JSON escaping of the text itself.
  let text = json.slice(0, Math.max(0, maxChars - NOTE.length - 100));
  while (size({ truncated: true, note: NOTE, text }) > maxChars && text.length > 0) {
    text = text.slice(0, Math.floor(text.length * 0.9));
  }
  return { truncated: true, note: NOTE, text };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Keeps a result small enough for the model. Lists (a top-level array, or a Graph `{ value: [...] }` page)
 * keep whole items and gain `truncated`, `totalItems`, `shownItems` and a note; anything else over the cap
 * is cut as text. `total` is the real item count when the caller knows more exist than were returned.
 */
export function capResult(value: unknown, opts: { maxChars?: number; total?: number } = {}): unknown {
  const maxChars = opts.maxChars ?? MAX_RESULT_CHARS;
  const overhead = NOTE.length + 120;

  if (Array.isArray(value)) {
    const total = Math.max(opts.total ?? 0, value.length);
    if (size(value) <= maxChars && total === value.length) return value;
    const n = fit(value, maxChars - overhead);
    if (n === 0 && value.length > 0) return cutText(value, maxChars);
    return { truncated: true, totalItems: total, shownItems: n, note: NOTE, items: value.slice(0, n) };
  }

  if (isRecord(value) && Array.isArray(value.value)) {
    if (size(value) <= maxChars) return value;
    const items = value.value;
    const { value: _dropped, ...rest } = value;
    const count = typeof value['@odata.count'] === 'number' ? value['@odata.count'] : items.length;
    const n = fit(items, maxChars - overhead - size(rest));
    if (n === 0) return cutText(value, maxChars);
    return { ...rest, truncated: true, totalItems: Math.max(count, items.length), shownItems: n, note: NOTE, value: items.slice(0, n) };
  }

  if (size(value) <= maxChars) return value;
  return cutText(value, maxChars);
}
