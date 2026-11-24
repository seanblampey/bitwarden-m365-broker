import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { win32 } from 'node:path';
import { BrokerError } from './errors.js';

export interface BrokerConfig {
  folderName: string;
  idleMinutes: number;
  graphScopes: string[];
  /** Show the sign-in browser window instead of running it hidden (for diagnosing sign-in). */
  showSignInWindow: boolean;
}

const DEFAULTS: BrokerConfig = {
  folderName: 'Claude Access',
  idleMinutes: 30,
  showSignInWindow: false,
  graphScopes: [
    'https://graph.microsoft.com/User.ReadWrite.All',
    'https://graph.microsoft.com/Group.ReadWrite.All',
    'https://graph.microsoft.com/Directory.ReadWrite.All',
    'https://graph.microsoft.com/MailboxSettings.ReadWrite',
    'https://graph.microsoft.com/Organization.Read.All',
    'https://graph.microsoft.com/Reports.Read.All',
    'https://graph.microsoft.com/AuditLog.Read.All',
    'https://graph.microsoft.com/TeamSettings.ReadWrite.All',
    'offline_access',
    'openid',
    'profile',
  ],
};

export function defaultPaths(env: NodeJS.ProcessEnv = process.env): { configFile: string; auditFile: string } {
  const profile = env.USERPROFILE || homedir();
  const roaming = env.APPDATA || win32.join(profile, 'AppData', 'Roaming');
  const local = env.LOCALAPPDATA || win32.join(profile, 'AppData', 'Local');
  return {
    configFile: win32.join(roaming, 'claude-bw-broker', 'config.json'),
    auditFile: win32.join(local, 'claude-bw-broker', 'audit.jsonl'),
  };
}

export function loadConfig(configFile: string): BrokerConfig {
  let raw: string;
  try {
    raw = readFileSync(configFile, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { ...DEFAULTS, graphScopes: [...DEFAULTS.graphScopes] };
    throw new BrokerError('bad_config', `Cannot read config file: ${(e as NodeJS.ErrnoException).code ?? 'error'}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new BrokerError('bad_config', 'Config file is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new BrokerError('bad_config', 'Config file must be a JSON object');
  }
  const p = parsed as Record<string, unknown>;
  const cfg: BrokerConfig = { ...DEFAULTS, graphScopes: [...DEFAULTS.graphScopes] };
  if (p.folderName !== undefined) {
    if (typeof p.folderName !== 'string' || !p.folderName) throw new BrokerError('bad_config', 'folderName must be a non-empty string');
    cfg.folderName = p.folderName;
  }
  if (p.idleMinutes !== undefined) {
    if (typeof p.idleMinutes !== 'number' || !Number.isFinite(p.idleMinutes) || p.idleMinutes <= 0) {
      throw new BrokerError('bad_config', 'idleMinutes must be a positive number');
    }
    cfg.idleMinutes = p.idleMinutes;
  }
  if (p.graphScopes !== undefined) {
    if (!Array.isArray(p.graphScopes) || !p.graphScopes.every((s) => typeof s === 'string')) {
      throw new BrokerError('bad_config', 'graphScopes must be an array of strings');
    }
    cfg.graphScopes = p.graphScopes as string[];
  }
  if (p.showSignInWindow !== undefined) {
    if (typeof p.showSignInWindow !== 'boolean') throw new BrokerError('bad_config', 'showSignInWindow must be true or false');
    cfg.showSignInWindow = p.showSignInWindow;
  }
  return cfg;
}
