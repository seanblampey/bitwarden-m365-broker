import type { AuditLog } from '../audit.js';
import { BrokerError } from '../errors.js';
import type { Redactor } from '../redact.js';
import type { BwClient, BwItem } from './bw.js';

export interface Credential {
  alias: string;
  username: string;
  password: string;
  totpSeed: string;
  tenant: string;
  /** Optional: the tenant's SharePoint name ("contoso" in contoso.sharepoint.com) when it differs from the tenant domain. */
  sharepoint?: string;
}

export interface VaultDeps {
  bw: BwClient;
  /** null = user cancelled; a failed or timed-out dialog rejects with BrokerError('dialog_failed'), passed through as is. */
  promptPassword: () => Promise<string | null>;
  redactor: Redactor;
  audit: AuditLog;
  folderName: string;
  idleMs: number;
  now?: () => number;
}

const MAX_ATTEMPTS = 3;

interface Unlocked {
  session: string;
  items: BwItem[];
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function itemName(item: unknown): string | undefined {
  return isObject(item) ? str(item.name) : undefined;
}

/** Value of a custom field by name (case-insensitive), trimmed; undefined if absent or empty. */
function customField(item: Record<string, unknown>, name: string): string | undefined {
  if (!Array.isArray(item.fields)) return undefined;
  for (const f of item.fields) {
    if (isObject(f) && typeof f.name === 'string' && f.name.toLowerCase() === name) {
      const v = str(f.value)?.trim();
      if (v) return v;
    }
  }
  return undefined;
}

/**
 * Alias -> item, so every alias is unique. A Bitwarden name used once is its own alias;
 * a repeated name becomes "name (username)", and "#2", "#3"... if that still repeats.
 */
function aliasMap(items: readonly BwItem[]): Map<string, BwItem> {
  const named = items.flatMap((item) => {
    const name = itemName(item);
    return name === undefined ? [] : [{ item, name }];
  });
  const count = new Map<string, number>();
  for (const { name } of named) count.set(name, (count.get(name) ?? 0) + 1);
  const out = new Map<string, BwItem>();
  for (const { item, name } of named) {
    const user = item.login?.username?.trim();
    const base = (count.get(name) ?? 0) > 1 && user ? `${name} (${user})` : name;
    let alias = base;
    for (let n = 2; out.has(alias); n++) alias = `${base} #${n}`;
    out.set(alias, item);
  }
  return out;
}

export class Vault {
  private state: Unlocked | null = null;
  private inflight: Promise<Unlocked> | null = null;
  private lastUse = 0;
  private readonly now: () => number;

  constructor(private readonly deps: VaultDeps) {
    this.now = deps.now ?? Date.now;
  }

  async listTenants(): Promise<string[]> {
    const { items } = await this.ensure();
    return [...aliasMap(items).keys()];
  }

  async getCredential(alias: string): Promise<Credential> {
    const { items } = await this.ensure();
    const item = aliasMap(items).get(alias) as unknown as Record<string, unknown> | undefined;
    if (!item) {
      throw new BrokerError('not_allowed', `"${alias}" is not in the Bitwarden folder "${this.deps.folderName}".`);
    }
    const login = isObject(item.login) ? item.login : {};
    const username = str(login.username);
    const password = str(login.password);
    const totpSeed = str(login.totp);
    const tenant = customField(item, 'tenant');
    const missing: string[] = [];
    if (!username) missing.push('username');
    if (!password) missing.push('password');
    if (!totpSeed) missing.push('TOTP');
    if (!tenant) missing.push('tenant');
    if (missing.length > 0) {
      throw new BrokerError(
        'item_incomplete',
        `Bitwarden item "${alias}" is missing: ${missing.join(', ')}. Add the missing field(s) to the item and try again.`,
      );
    }
    const sharepoint = customField(item, 'sharepoint');
    return { alias, username: username!, password: password!, totpSeed: totpSeed!, tenant: tenant!, ...(sharepoint ? { sharepoint } : {}) };
  }

  async lock(): Promise<void> {
    // An unlock in progress is abandoned: wait for it so its session can be dropped.
    if (this.inflight) await this.inflight.catch(() => undefined);
    if (!this.state) return;
    this.state = null;
    try {
      await this.deps.bw.lock();
    } finally {
      this.deps.audit.write({ type: 'lock' });
    }
  }

  private async ensure(): Promise<Unlocked> {
    if (this.state && this.now() - this.lastUse >= this.deps.idleMs) {
      await this.lock();
    }
    if (!this.state) {
      if (!this.inflight) {
        this.inflight = this.unlock().then(
          (s) => {
            this.state = s;
            this.inflight = null;
            return s;
          },
          (e) => {
            this.inflight = null;
            throw e;
          },
        );
      }
      const s = await this.inflight;
      this.lastUse = this.now();
      return s;
    }
    this.lastUse = this.now();
    return this.state;
  }

  private async unlock(): Promise<Unlocked> {
    const { bw, redactor, audit, folderName } = this.deps;
    // Even if bw reports 'unlocked', we never borrow a session we did not create.
    if ((await bw.status()) === 'unauthenticated') {
      throw new BrokerError('not_logged_in', 'Run "bw login" yourself in a terminal outside Claude, then try again.');
    }
    let session: string | null = null;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS && session === null; attempt++) {
      const password = await this.deps.promptPassword();
      if (password === null) {
        throw new BrokerError('unlock_cancelled', 'The Bitwarden unlock prompt was cancelled.');
      }
      try {
        session = await bw.unlock(password);
      } catch (e) {
        if (!(e instanceof BrokerError) || e.code !== 'wrong_master_password') throw e;
        if (attempt === MAX_ATTEMPTS) {
          throw new BrokerError('wrong_master_password', 'Bitwarden rejected the master password 3 times.');
        }
      }
    }
    if (session === null) throw new BrokerError('wrong_master_password', 'Bitwarden rejected the master password.');
    redactor.add(session);
    try {
      await bw.sync(session);
      const folderId = await bw.folderId(session, folderName);
      if (!folderId) {
        throw new BrokerError('folder_missing', `Bitwarden folder "${folderName}" was not found.`);
      }
      const items = await bw.listItems(session, folderId);
      for (const item of items) {
        if (!isObject(item) || !isObject(item.login)) continue;
        redactor.add(str(item.login.password));
        redactor.add(str(item.login.totp));
      }
      audit.write({ type: 'unlock' });
      return { session, items };
    } catch (e) {
      // Do not leave a session we created alive after a failed setup.
      await bw.lock().catch(() => undefined);
      throw e;
    }
  }
}
