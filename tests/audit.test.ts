import { describe, it, expect, vi } from 'vitest';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '../src/audit.js';
import { Redactor } from '../src/redact.js';

describe('AuditLog', () => {
  it('appends scrubbed JSON lines with ts, creating the directory', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'aud-')), 'sub', 'audit.jsonl');
    const r = new Redactor();
    r.add('p4ssword!');
    const log = new AuditLog(file, r);
    log.write({ type: 'call', tenant: 'contoso.com', detail: 'used p4ssword! here' });
    log.write({ type: 'lock' });
    const text = readFileSync(file, 'utf8');
    expect(text).not.toContain('p4ssword!');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    expect(lines).toHaveLength(2);
    expect(lines[0].detail).toContain('[REDACTED]');
    expect(lines[0].type).toBe('call');
    expect(Number.isNaN(Date.parse(lines[0].ts))).toBe(false);
  });
  it('never throws; warns on stderr without secrets', () => {
    const dir = mkdtempSync(join(tmpdir(), 'aud-'));
    const blocker = join(dir, 'file');
    writeFileSync(blocker, 'x');
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const log = new AuditLog(join(blocker, 'audit.jsonl'), new Redactor());
    expect(() => log.write({ type: 'error', detail: 'x' })).not.toThrow();
    expect(spy).toHaveBeenCalledOnce();
    expect(String(spy.mock.calls[0]![0])).toMatch(/audit/i);
    spy.mockRestore();
  });
});
