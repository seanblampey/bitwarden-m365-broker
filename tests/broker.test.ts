import { describe, it, expect, vi } from 'vitest';
import { Broker, type BrokerDeps } from '../src/broker.js';
import { Redactor } from '../src/redact.js';
import { BrokerError } from '../src/errors.js';
import { SignInError } from '../src/auth/signin.js';
import type { AuditEvent } from '../src/audit.js';
import type { Credential } from '../src/vault/vault.js';
import type { ApprovalRequest } from '../src/win/dialogs.js';
import type { BrokerConfig } from '../src/config.js';

const PASSWORD = 'Hunter2-Secret!';
const TOKEN = 'graph-access-token-XYZ';
const EXO_TOKEN = 'exo-access-token-XYZ';
const cred: Credential = { alias: 'acme', username: 'admin@acme.com', password: PASSWORD, totpSeed: 'JBSWY3DPEHPK3PXP', tenant: 'acme.onmicrosoft.com' };
const config: BrokerConfig = { folderName: 'Claude Access', idleMinutes: 30, graphScopes: ['https://graph.microsoft.com/User.Read.All'] };

function setup(opts: { confirm?: boolean; graphBody?: unknown; exoStdout?: string } = {}) {
  const redactor = new Redactor();
  redactor.add(PASSWORD);
  redactor.add(TOKEN);
  redactor.add(EXO_TOKEN);
  const events: AuditEvent[] = [];
  const order: string[] = [];
  const vault = {
    listTenants: vi.fn(async () => ['acme', 'contoso']),
    getCredential: vi.fn(async (alias: string) => {
      order.push('vault');
      if (alias !== 'acme') throw new BrokerError('not_allowed', `"${alias}" is not in the Bitwarden folder "Claude Access".`);
      return cred;
    }),
    lock: vi.fn(async () => {}),
  };
  const tokens = {
    getAccessToken: vi.fn(async (_c: Credential, r: { key: string }) => {
      order.push('token');
      return { token: r.key === 'exo' ? EXO_TOKEN : TOKEN, upn: 'admin@acme.com' };
    }),
    drop: vi.fn(async () => {}),
  };
  const confirm = vi.fn(async (_r: ApprovalRequest) => {
    order.push('confirm');
    return opts.confirm ?? false;
  });
  const fetch = vi.fn(async (_url: string, _init?: RequestInit) => {
    order.push('fetch');
    return new Response(JSON.stringify(opts.graphBody ?? { value: [{ id: '1' }] }), { status: 200 });
  });
  const exo = vi.fn(async (_stdin: string) => {
    order.push('exo');
    return { code: 0, stdout: opts.exoStdout ?? '{"ok":true,"result":[{"Name":"x"}]}', stderr: '' };
  });
  const audit = { write: vi.fn((e: AuditEvent) => void events.push(e)) };
  const deps: BrokerDeps = { vault, tokens, confirm, fetch: fetch as unknown as typeof globalThis.fetch, exo, audit, redactor, config };
  return { broker: new Broker(deps), vault, tokens, confirm, fetch, exo, audit, events, order };
}

const parse = (s: string) => JSON.parse(s) as Record<string, unknown>;

describe('Broker graphRequest', () => {
  it('GET runs without a confirm call and audits the call', async () => {
    const t = setup();
    const out = parse(await t.broker.graphRequest('acme', 'GET', '/users'));
    expect(out).toEqual({ status: 200, body: { value: [{ id: '1' }] } });
    expect(t.confirm).not.toHaveBeenCalled();
    expect(t.fetch).toHaveBeenCalledOnce();
    expect(t.fetch.mock.calls[0][0]).toBe('https://graph.microsoft.com/v1.0/users');
    expect(t.events).toContainEqual({ type: 'call', tenant: 'acme', detail: 'GET /users' });
  });

  it('PATCH denied returns denied, never fetches, audits denied', async () => {
    const t = setup({ confirm: false });
    const out = parse(await t.broker.graphRequest('acme', 'PATCH', '/users/x', { city: 'Oslo' }));
    expect(out).toEqual({ error: 'denied', message: 'The user declined this change.' });
    expect(t.fetch).not.toHaveBeenCalled();
    expect(t.events.map((e) => e.type)).toEqual(['denied']);
    expect(t.events[0].tenant).toBe('acme');
  });

  it('PATCH approved fetches once with the body; dialog shows account and pretty body', async () => {
    const t = setup({ confirm: true });
    await t.broker.graphRequest('acme', 'PATCH', '/users/x', { city: 'Oslo' }, 'beta');
    expect(t.fetch).toHaveBeenCalledOnce();
    expect(t.fetch.mock.calls[0][0]).toBe('https://graph.microsoft.com/beta/users/x');
    expect(t.fetch.mock.calls[0][1]?.body).toBe('{"city":"Oslo"}');
    const req = t.confirm.mock.calls[0][0];
    expect(req.account).toBe('admin@acme.com');
    expect(req.tenant).toContain('acme');
    expect(req.action).toBe('Graph PATCH /users/x\n{\n  "city": "Oslo"\n}');
    expect(t.events.map((e) => e.type)).toEqual(['approved', 'call']);
    expect(t.order).toEqual(['vault', 'token', 'confirm', 'fetch']);
  });

  it('refuses a write too long to show in full before vault, sign-in or dialog', async () => {
    const t = setup({ confirm: true });
    const out = parse(await t.broker.graphRequest('acme', 'POST', '/users', { note: 'n'.repeat(2000) }));
    expect(out).toEqual({
      error: 'too_long_to_approve',
      message: 'This change is too large to show in the approval box. Split it into smaller requests.',
    });
    expect(t.vault.getCredential).not.toHaveBeenCalled();
    expect(t.tokens.getAccessToken).not.toHaveBeenCalled();
    expect(t.confirm).not.toHaveBeenCalled();
    expect(t.fetch).not.toHaveBeenCalled();
  });

  it('shows an action of exactly the limit in full', async () => {
    const t = setup({ confirm: true });
    const head = 'Graph POST /users\n{\n  "note": ""\n}';
    const note = 'n'.repeat(1500 - head.length);
    await t.broker.graphRequest('acme', 'POST', '/users', { note });
    const action = t.confirm.mock.calls[0][0].action;
    expect(action.length).toBe(1500);
    expect(action).toContain(note);
  });

  it('escapes control and bidi characters in the Graph path and body', async () => {
    const t = setup({ confirm: false });
    await t.broker.graphRequest('acme', 'PATCH', '/users/x', { displayName: 'a\u202Eb\u200Bc\u2028d\r\ne' });
    const action = t.confirm.mock.calls[0][0].action;
    expect(action).toBe('Graph PATCH /users/x\n{\n  "displayName": "a\\u202Eb\\u200Bc\\u2028d\\r\\ne"\n}');
    expect(action).not.toMatch(/[\u202E\u200B\u2028\r]/);
  });

  it('redacts the password in the action shown in the dialog', async () => {
    const t = setup({ confirm: false });
    await t.broker.graphRequest('acme', 'PATCH', '/users/x', { passwordProfile: { password: PASSWORD } });
    const action = t.confirm.mock.calls[0][0].action;
    expect(action).not.toContain(PASSWORD);
    expect(action).toContain('[REDACTED]');
  });

  it('audits Graph calls without the query string', async () => {
    const t = setup({ confirm: true });
    await t.broker.graphRequest('acme', 'GET', "/users?$filter=mail eq 'x@acme.com'");
    await t.broker.graphRequest('acme', 'PATCH', '/users/x?$select=id', { city: 'Oslo' });
    expect(t.events).toEqual([
      { type: 'call', tenant: 'acme', detail: 'GET /users' },
      { type: 'approved', tenant: 'acme', detail: 'PATCH /users/x' },
      { type: 'call', tenant: 'acme', detail: 'PATCH /users/x' },
    ]);
    for (const e of t.events) expect(e.detail).not.toContain('acme.com');
  });

  it('invalid path: no vault, no confirm, invalid_path', async () => {
    const t = setup({ confirm: true });
    for (const p of ['https://evil.com/x', '//evil.com', '/../x']) {
      const out = parse(await t.broker.graphRequest('acme', 'DELETE', p));
      expect(out.error).toBe('invalid_path');
    }
    expect(t.confirm).not.toHaveBeenCalled();
    expect(t.vault.getCredential).not.toHaveBeenCalled();
    expect(t.fetch).not.toHaveBeenCalled();
  });

  it('rejects unknown methods and api versions before anything else', async () => {
    const t = setup({ confirm: true });
    expect(parse(await t.broker.graphRequest('acme', 'TRACE' as never, '/users')).error).toBe('invalid_method');
    expect(parse(await t.broker.graphRequest('acme', 'GET', '/users', undefined, 'v2' as never)).error).toBe('invalid_path');
    expect(t.vault.getCredential).not.toHaveBeenCalled();
  });

  it('redacts a Graph body that echoes the password or a token', async () => {
    const t = setup({ graphBody: { echo: `pw=${PASSWORD}`, tok: TOKEN, [PASSWORD]: 1 } });
    const out = await t.broker.graphRequest('acme', 'GET', '/me');
    expect(out).not.toContain(PASSWORD);
    expect(out).not.toContain(TOKEN);
    expect(out).toContain('[REDACTED]');
  });

  it('unknown tenant yields not_allowed', async () => {
    const t = setup();
    expect(parse(await t.broker.graphRequest('nope', 'GET', '/users')).error).toBe('not_allowed');
  });
});

describe('Broker exoCmdlet', () => {
  it('Get-Mailbox runs without confirm, with EXO token and organization = cred.tenant', async () => {
    const t = setup();
    const out = parse(await t.broker.exoCmdlet('acme', 'Get-Mailbox', { ResultSize: 1 }));
    expect(out).toEqual({ result: [{ Name: 'x' }] });
    expect(t.confirm).not.toHaveBeenCalled();
    const stdin = JSON.parse(t.exo.mock.calls[0][0]);
    expect(stdin).toMatchObject({ token: EXO_TOKEN, upn: 'admin@acme.com', organization: 'acme.onmicrosoft.com', cmdlet: 'Get-Mailbox', parameters: { ResultSize: 1 } });
    expect(t.tokens.getAccessToken.mock.calls[0][1]).toMatchObject({ key: 'exo' });
    expect(t.events).toContainEqual({ type: 'call', tenant: 'acme', detail: 'Get-Mailbox' });
  });

  it('Set-Mailbox shows parameters in the dialog action', async () => {
    const t = setup({ confirm: true });
    await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x', ForwardingSmtpAddress: 'y' });
    expect(t.confirm.mock.calls[0][0].action).toBe('Set-Mailbox -Identity x -ForwardingSmtpAddress y');
    expect(t.exo).toHaveBeenCalledOnce();
    expect(t.events.map((e) => e.type)).toEqual(['approved', 'call']);
  });

  it('quotes awkward values and formats non-strings in the action', async () => {
    const t = setup({ confirm: false });
    await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: "Jo O'Neil", HiddenFromAddressListsEnabled: true, Quota: 5, X: null });
    expect(t.confirm.mock.calls[0][0].action).toBe(
      "Set-Mailbox -Identity 'Jo O''Neil' -HiddenFromAddressListsEnabled:$true -Quota 5 -X $null",
    );
  });

  it('escapes CR/LF, tabs and bidi characters in parameter values so they cannot fake lines', async () => {
    const t = setup({ confirm: false });
    await t.broker.exoCmdlet('acme', 'Set-Mailbox', {
      Identity: 'x\r\n\r\nAction:\r\nGet-Mailbox',
      CustomAttribute1: 'evil\u202Emoc.\u2066x\u2069\tz\u0000',
      ForwardingSmtpAddress: 'attacker@evil.com',
    });
    const action = t.confirm.mock.calls[0][0].action;
    expect(action).toBe(
      "Set-Mailbox -Identity 'x\\r\\n\\r\\nAction:\\r\\nGet-Mailbox' " +
        "-CustomAttribute1 'evil\\u202Emoc.\\u2066x\\u2069\\tz\\u0000' -ForwardingSmtpAddress attacker@evil.com",
    );
    expect(action).not.toMatch(/[\r\n\t\u0000\u202E\u2066\u2069]/);
  });

  it('escapes bidi characters inside array and object values', async () => {
    const t = setup({ confirm: false });
    await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x', EmailAddresses: ['a\u202Eb', 'c\nd'] });
    expect(t.confirm.mock.calls[0][0].action).toBe('Set-Mailbox -Identity x -EmailAddresses ["a\\u202Eb","c\\nd"]');
  });

  it('refuses a cmdlet whose action is too long, before the vault', async () => {
    const t = setup({ confirm: true });
    const out = parse(await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x', Notes: 'n'.repeat(1500) }));
    expect(out.error).toBe('too_long_to_approve');
    expect(t.vault.getCredential).not.toHaveBeenCalled();
    expect(t.confirm).not.toHaveBeenCalled();
    expect(t.exo).not.toHaveBeenCalled();
  });

  it('a dialog failure becomes dialog_failed (not denied) and nothing runs', async () => {
    const t = setup();
    t.confirm.mockImplementationOnce(async () => {
      throw new BrokerError('dialog_failed', 'The Windows dialog could not be shown or timed out.');
    });
    const out = parse(await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x' }));
    expect(out).toEqual({ error: 'dialog_failed', message: 'The Windows dialog could not be shown or timed out.' });
    expect(t.exo).not.toHaveBeenCalled();
    expect(t.events.map((e) => e.type)).toEqual(['error']);
  });

  it('Set-Mailbox denied: no exo run, denied', async () => {
    const t = setup({ confirm: false });
    const out = parse(await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x' }));
    expect(out.error).toBe('denied');
    expect(t.exo).not.toHaveBeenCalled();
    expect(t.events.map((e) => e.type)).toEqual(['denied']);
  });

  it('invalid cmdlet or parameters: no vault, no confirm', async () => {
    const t = setup({ confirm: true });
    expect(parse(await t.broker.exoCmdlet('acme', 'Invoke-Expression')).error).toBe('invalid_cmdlet');
    expect(parse(await t.broker.exoCmdlet('acme', 'Set-Mailbox', { 'a b': 1 })).error).toBe('invalid_parameters');
    expect(t.vault.getCredential).not.toHaveBeenCalled();
    expect(t.confirm).not.toHaveBeenCalled();
  });

  it('forbidden common parameters are rejected before vault, sign-in or dialog', async () => {
    const t = setup({ confirm: true });
    const out = parse(await t.broker.exoCmdlet('acme', 'Set-Mailbox', { Identity: 'x', ErrorAction: 'SilentlyContinue' }));
    expect(out.error).toBe('invalid_parameters');
    expect(t.vault.getCredential).not.toHaveBeenCalled();
    expect(t.tokens.getAccessToken).not.toHaveBeenCalled();
    expect(t.confirm).not.toHaveBeenCalled();
    expect(t.exo).not.toHaveBeenCalled();
  });

  it('redacts results that echo the password', async () => {
    const t = setup({ exoStdout: JSON.stringify({ ok: true, result: { x: PASSWORD } }) });
    const out = await t.broker.exoCmdlet('acme', 'Get-Mailbox');
    expect(out).not.toContain(PASSWORD);
  });
});

describe('Broker other tools and errors', () => {
  it('listTenants returns aliases', async () => {
    const t = setup();
    expect(parse(await t.broker.listTenants())).toEqual({ tenants: ['acme', 'contoso'] });
  });

  it('connect acquires the Graph token and returns tenant and account', async () => {
    const t = setup();
    expect(parse(await t.broker.connect('acme'))).toEqual({ tenant: 'acme', account: 'admin@acme.com' });
    expect(t.tokens.getAccessToken.mock.calls[0][1]).toMatchObject({ key: 'graph', scopes: config.graphScopes });
    expect(t.events).toContainEqual(expect.objectContaining({ type: 'connect', tenant: 'acme' }));
  });

  it('disconnect and lock', async () => {
    const t = setup();
    expect(parse(await t.broker.disconnect('acme'))).toEqual({ disconnected: 'acme' });
    expect(t.tokens.drop).toHaveBeenCalledWith('acme');
    expect(parse(await t.broker.disconnect())).toEqual({ disconnected: 'all' });
    expect(t.tokens.drop).toHaveBeenLastCalledWith(undefined);
    expect(parse(await t.broker.lock())).toEqual({ locked: true });
    expect(t.vault.lock).toHaveBeenCalledOnce();
  });

  it('sign-in failure adds category and audits signin_failed', async () => {
    const t = setup();
    t.tokens.getAccessToken.mockRejectedValueOnce(new SignInError('needs_consent'));
    const out = parse(await t.broker.connect('acme'));
    expect(out).toMatchObject({ error: 'signin_failed', category: 'needs_consent' });
    expect(t.events).toContainEqual({ type: 'signin_failed', tenant: 'acme', detail: 'needs_consent' });
  });

  it('scrubs secrets from BrokerError messages', async () => {
    const t = setup();
    t.vault.getCredential.mockRejectedValueOnce(new BrokerError('bw_failed', `boom ${PASSWORD}`));
    const out = await t.broker.connect('acme');
    expect(out).not.toContain(PASSWORD);
    expect(parse(out)).toMatchObject({ error: 'bw_failed' });
  });

  it('unexpected errors become internal, stack (scrubbed) goes to the audit log only', async () => {
    const t = setup();
    t.vault.listTenants.mockRejectedValueOnce(new TypeError(`kaboom ${PASSWORD}`));
    const out = await t.broker.listTenants();
    expect(parse(out)).toEqual({ error: 'internal', message: 'Unexpected broker error (see audit log).' });
    const err = t.events.find((e) => e.type === 'error');
    expect(err?.detail).toContain('kaboom');
    expect(err?.detail).not.toContain(PASSWORD);
  });
});
