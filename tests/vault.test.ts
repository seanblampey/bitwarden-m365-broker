import { describe, it, expect, vi } from 'vitest';
import { Vault } from '../src/vault/vault.js';
import { Redactor } from '../src/redact.js';
import { BrokerError } from '../src/errors.js';
import type { BwItem } from '../src/vault/bw.js';

const good: BwItem = {
  id: '1',
  name: 'contoso-admin',
  login: { username: 'admin@contoso.com', password: 'pw-contoso-1', totp: 'JBSWY3DPEHPK3PXP' },
  fields: [{ name: 'Tenant', value: 'contoso.com' }],
};
const noTotp: BwItem = { id: '2', name: 'fabrikam', login: { username: 'a@f.com', password: 'pw-fab-1' }, fields: [{ name: 'tenant', value: 'fabrikam.com' }] };
const noTenant: BwItem = { id: '3', name: 'adatum', login: { username: 'a@a.com', password: 'pw-adatum', totp: 'SEEDADATUM' } };

function setup(opts: { items?: unknown[]; prompts?: (string | null)[]; status?: 'unauthenticated' | 'locked' | 'unlocked'; folder?: string | null; wrong?: string[] } = {}) {
  const prompts = [...(opts.prompts ?? ['master'])];
  const bw = {
    status: vi.fn(async () => opts.status ?? 'locked'),
    unlock: vi.fn(async (pw: string) => {
      if (opts.wrong?.includes(pw)) throw new BrokerError('wrong_master_password', 'Bitwarden rejected the master password.');
      return 'SESSION-TOKEN-XYZ';
    }),
    sync: vi.fn(async () => {}),
    folderId: vi.fn(async () => (opts.folder === undefined ? 'f1' : opts.folder)),
    listItems: vi.fn(async () => (opts.items ?? [good, noTotp, noTenant]) as BwItem[]),
    lock: vi.fn(async () => {}),
  };
  const promptPassword = vi.fn(async () => (prompts.length ? prompts.shift()! : null));
  const redactor = new Redactor();
  const audit = { write: vi.fn() };
  let t = 0;
  const vault = new Vault({ bw: bw as never, promptPassword, redactor, audit: audit as never, folderName: 'Claude Access', idleMs: 30 * 60_000, now: () => t });
  return { vault, bw, promptPassword, redactor, audit, advance: (ms: number) => (t += ms) };
}
const min = 60_000;

describe('Vault', () => {
  it('unlock_cancelled when dialog cancelled', async () => {
    const { vault } = setup({ prompts: [null] });
    await expect(vault.listTenants()).rejects.toMatchObject({ code: 'unlock_cancelled' });
  });
  it('dialog_failed (not unlock_cancelled) when the password dialog fails; next call prompts again', async () => {
    const { vault, bw, promptPassword } = setup();
    promptPassword.mockImplementationOnce(async () => {
      throw new BrokerError('dialog_failed', 'The Windows dialog could not be shown or timed out.');
    });
    await expect(vault.listTenants()).rejects.toMatchObject({ code: 'dialog_failed' });
    expect(bw.unlock).not.toHaveBeenCalled();
    expect(await vault.listTenants()).toEqual(['contoso-admin', 'fabrikam', 'adatum']);
    expect(promptPassword).toHaveBeenCalledTimes(2);
  });
  it('not_logged_in when unauthenticated, without prompting', async () => {
    const { vault, promptPassword } = setup({ status: 'unauthenticated' });
    await expect(vault.listTenants()).rejects.toMatchObject({ code: 'not_logged_in' });
    expect(promptPassword).not.toHaveBeenCalled();
  });
  it('prompts even when bw status is unlocked', async () => {
    const { vault, promptPassword } = setup({ status: 'unlocked' });
    await vault.listTenants();
    expect(promptPassword).toHaveBeenCalledTimes(1);
  });
  it('re-prompts on wrong password up to 3 times then fails', async () => {
    const { vault, promptPassword } = setup({ prompts: ['a', 'b', 'c', 'd'], wrong: ['a', 'b', 'c'] });
    await expect(vault.listTenants()).rejects.toMatchObject({ code: 'wrong_master_password' });
    expect(promptPassword).toHaveBeenCalledTimes(3);
  });
  it('succeeds on second attempt', async () => {
    const { vault, promptPassword } = setup({ prompts: ['a', 'master'], wrong: ['a'] });
    await expect(vault.listTenants()).resolves.toHaveLength(3);
    expect(promptPassword).toHaveBeenCalledTimes(2);
  });
  it('listTenants returns names in the folder only', async () => {
    const { vault, bw } = setup();
    expect(await vault.listTenants()).toEqual(['contoso-admin', 'fabrikam', 'adatum']);
    expect(bw.listItems).toHaveBeenCalledWith('SESSION-TOKEN-XYZ', 'f1');
  });
  it('folder_missing names the folder', async () => {
    const { vault } = setup({ folder: null });
    const e = await vault.listTenants().catch((x) => x);
    expect(e.code).toBe('folder_missing');
    expect(e.message).toContain('Claude Access');
  });
  it('returns a full credential, field name case-insensitive', async () => {
    const { vault } = setup();
    expect(await vault.getCredential('contoso-admin')).toEqual({
      alias: 'contoso-admin', username: 'admin@contoso.com', password: 'pw-contoso-1', totpSeed: 'JBSWY3DPEHPK3PXP', tenant: 'contoso.com',
    });
  });
  it('not_allowed for alias outside folder', async () => {
    const { vault } = setup();
    await expect(vault.getCredential('other')).rejects.toMatchObject({ code: 'not_allowed' });
  });
  it('item_incomplete names TOTP', async () => {
    const { vault } = setup();
    const e = await vault.getCredential('fabrikam').catch((x) => x);
    expect(e.code).toBe('item_incomplete');
    expect(e.message).toContain('TOTP');
    expect(e.message).not.toContain('pw-fab-1');
  });
  it('item_incomplete names tenant', async () => {
    const { vault } = setup();
    const e = await vault.getCredential('adatum').catch((x) => x);
    expect(e.code).toBe('item_incomplete');
    expect(e.message).toContain('tenant');
    expect(e.message).not.toContain('SEEDADATUM');
  });
  it('gives every item a unique alias when Bitwarden names repeat', async () => {
    const mk = (id: string, name: string, username: string, tenant: string): BwItem =>
      ({ id, name, login: { username, password: `pw-${id}`, totp: 'JBSWY3DPEHPK3PXP' }, fields: [{ name: 'tenant', value: tenant }] });
    const items = [
      mk('a', 'O365 - Northwind', 'admin@northwind.example', 'northwind.example'),
      mk('b', 'O365 - Northwind', 'ops@northwind.example', 'northwind.example'),
      mk('c', 'O365 - Northwind', 'ops@northwind.example', 'other.com'),
      mk('d', 'Solo', 'x@solo.com', 'solo.com'),
    ];
    const { vault } = setup({ items });
    const aliases = await vault.listTenants();
    expect(aliases).toEqual([
      'O365 - Northwind (admin@northwind.example)',
      'O365 - Northwind (ops@northwind.example)',
      'O365 - Northwind (ops@northwind.example) #2',
      'Solo',
    ]);
    expect(new Set(aliases).size).toBe(aliases.length);
    expect((await vault.getCredential('O365 - Northwind (ops@northwind.example) #2')).tenant).toBe('other.com');
    expect((await vault.getCredential('O365 - Northwind (admin@northwind.example)')).alias).toBe('O365 - Northwind (admin@northwind.example)');
    await expect(vault.getCredential('O365 - Northwind')).rejects.toMatchObject({ code: 'not_allowed' });
  });
  it('handles malformed items defensively', async () => {
    const { vault } = setup({ items: [null, 'x', 5, { id: 'z' }, { name: 'bare' }, { name: 'bad', login: 'x', fields: 'y' }, good] });
    expect(await vault.listTenants()).toEqual(['bare', 'bad', 'contoso-admin']);
    const e = await vault.getCredential('bare').catch((x) => x);
    expect(e.code).toBe('item_incomplete');
    expect(e.message).toMatch(/username.*password.*TOTP.*tenant/);
    await expect(vault.getCredential('bad')).rejects.toMatchObject({ code: 'item_incomplete' });
  });
  it('registers secrets with the redactor and audits unlock', async () => {
    const { vault, redactor, audit } = setup();
    await vault.listTenants();
    expect(redactor.scrub('pw-contoso-1 JBSWY3DPEHPK3PXP SESSION-TOKEN-XYZ')).toBe('[REDACTED] [REDACTED] [REDACTED]');
    expect(redactor.scrub('pw-fab-1')).toBe('[REDACTED]');
    expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ type: 'unlock' }));
  });
  it('no second prompt within 29 minutes', async () => {
    const { vault, promptPassword, advance, bw } = setup({ prompts: ['m', 'm'] });
    await vault.listTenants();
    advance(29 * min);
    await vault.listTenants();
    expect(promptPassword).toHaveBeenCalledTimes(1);
    expect(bw.lock).not.toHaveBeenCalled();
  });
  it('use refreshes the idle timer', async () => {
    const { vault, promptPassword, advance } = setup({ prompts: ['m', 'm'] });
    await vault.listTenants();
    advance(29 * min);
    await vault.listTenants();
    advance(29 * min);
    await vault.listTenants();
    expect(promptPassword).toHaveBeenCalledTimes(1);
  });
  it('locks and re-prompts after 31 minutes idle', async () => {
    const { vault, promptPassword, advance, bw, audit } = setup({ prompts: ['m', 'm'] });
    await vault.listTenants();
    advance(31 * min);
    await vault.listTenants();
    expect(promptPassword).toHaveBeenCalledTimes(2);
    expect(bw.lock).toHaveBeenCalledTimes(1);
    expect(audit.write).toHaveBeenCalledWith(expect.objectContaining({ type: 'lock' }));
    expect(bw.listItems).toHaveBeenCalledTimes(2);
  });
  it('concurrent calls share one prompt', async () => {
    const { vault, promptPassword } = setup();
    await Promise.all([vault.listTenants(), vault.getCredential('contoso-admin')]);
    expect(promptPassword).toHaveBeenCalledTimes(1);
  });
  it('lock() forgets session; next call prompts again', async () => {
    const { vault, promptPassword, bw } = setup({ prompts: ['m', 'm'] });
    await vault.listTenants();
    await vault.lock();
    expect(bw.lock).toHaveBeenCalledTimes(1);
    await vault.listTenants();
    expect(promptPassword).toHaveBeenCalledTimes(2);
  });
  it('lock() without a session is a no-op', async () => {
    const { vault, bw } = setup();
    await vault.lock();
    expect(bw.lock).not.toHaveBeenCalled();
  });
  it('failed unlock after cancel allows a later retry', async () => {
    const { vault } = setup({ prompts: [null, 'm'] });
    await expect(vault.listTenants()).rejects.toMatchObject({ code: 'unlock_cancelled' });
    await expect(vault.listTenants()).resolves.toHaveLength(3);
  });
});
