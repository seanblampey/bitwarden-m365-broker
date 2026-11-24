import { test, expect } from 'vitest';
import { Redactor } from '../src/redact.js';

test('removes registered secrets anywhere', () => {
  const r = new Redactor(); r.add('Hunter2!pass');
  expect(r.scrub('bad password Hunter2!pass here')).toBe('bad password [REDACTED] here');
});
test('removes JWT-shaped strings without registration', () => {
  expect(new Redactor().scrub('t=eyJhbGciOi.eyJzdWIiOi.sig_-x end')).toBe('t=[REDACTED] end');
});
test('ignores empty / very short secrets', () => { const r = new Redactor(); r.add(''); r.add('ab'); expect(r.scrub('ab')).toBe('ab'); });
test('scrubDeep walks objects and arrays', () => {
  const r = new Redactor(); r.add('s3cretvalue');
  expect(r.scrubDeep({ a: ['x s3cretvalue'], b: { c: 's3cretvalue' }, n: 1 }))
    .toEqual({ a: ['x [REDACTED]'], b: { c: '[REDACTED]' }, n: 1 });
});
test('regex metacharacters in secrets are literal', () => { const r = new Redactor(); r.add('a.b*c(d'); expect(r.scrub('xa.b*c(dx')).toBe('x[REDACTED]x'); });
