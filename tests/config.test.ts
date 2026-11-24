import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfig, defaultPaths } from '../src/config.js';
import { BrokerError } from '../src/errors.js';

const dir = () => mkdtempSync(join(tmpdir(), 'cfg-'));

describe('loadConfig', () => {
  it('returns defaults for a missing file', () => {
    const c = loadConfig(join(dir(), 'nope.json'));
    expect(c.folderName).toBe('Claude Access');
    expect(c.idleMinutes).toBe(30);
    expect(c.graphScopes).toHaveLength(11);
    expect(c.graphScopes).toContain('offline_access');
  });
  it('merges a partial file', () => {
    const f = join(dir(), 'c.json');
    writeFileSync(f, JSON.stringify({ idleMinutes: 5 }));
    const c = loadConfig(f);
    expect(c.idleMinutes).toBe(5);
    expect(c.folderName).toBe('Claude Access');
  });
  it('throws bad_config on invalid JSON', () => {
    const f = join(dir(), 'c.json');
    writeFileSync(f, '{nope');
    try {
      loadConfig(f);
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(BrokerError);
      expect((e as BrokerError).code).toBe('bad_config');
    }
  });
});

describe('defaultPaths', () => {
  it('builds Windows paths from env', () => {
    const p = defaultPaths({ APPDATA: 'C:\\Users\\a\\AppData\\Roaming', LOCALAPPDATA: 'C:\\Users\\a\\AppData\\Local' });
    expect(p.configFile).toBe('C:\\Users\\a\\AppData\\Roaming\\claude-bw-broker\\config.json');
    expect(p.auditFile).toBe('C:\\Users\\a\\AppData\\Local\\claude-bw-broker\\audit.jsonl');
  });
  it('falls back to USERPROFILE', () => {
    const p = defaultPaths({ USERPROFILE: 'C:\\Users\\b' });
    expect(p.configFile).toBe('C:\\Users\\b\\AppData\\Roaming\\claude-bw-broker\\config.json');
    expect(p.auditFile).toBe('C:\\Users\\b\\AppData\\Local\\claude-bw-broker\\audit.jsonl');
  });
});
