import { describe, it, expect } from 'vitest';
import { BwClient, nodeRunner, type Runner } from '../src/vault/bw.js';
import { BrokerError } from '../src/errors.js';

type Call = { args: string[]; env: Record<string, string> };
type Reply = { code: number; stdout: string; stderr: string };

function fake(replies: Reply[]): { run: Runner; calls: Call[] } {
  const calls: Call[] = [];
  const queue = [...replies];
  const run: Runner = async (args, env) => {
    calls.push({ args: [...args], env: { ...env } });
    return queue.shift() ?? { code: 0, stdout: '', stderr: '' };
  };
  return { run, calls };
}
const ok = (stdout = ''): Reply => ({ code: 0, stdout, stderr: '' });

describe('BwClient', () => {
  it('nodeRunner is exported', () => {
    expect(typeof nodeRunner).toBe('function');
  });

  it('status parses JSON status', async () => {
    const { run, calls } = fake([ok(JSON.stringify({ status: 'locked' }))]);
    expect(await new BwClient(run).status()).toBe('locked');
    expect(calls[0].args).toEqual(['status']);
  });

  it('status rejects malformed output without echoing it', async () => {
    const { run } = fake([ok('not json password=hunter2')]);
    const err = await new BwClient(run).status().catch((e) => e);
    expect(err).toBeInstanceOf(BrokerError);
    expect(err.code).toBe('bw_failed');
    expect(err.message).toBe('Bitwarden CLI returned unexpected output.');
  });

  it('status rejects unknown status values', async () => {
    const { run } = fake([ok(JSON.stringify({ status: 'weird' }))]);
    await expect(new BwClient(run).status()).rejects.toMatchObject({ code: 'bw_failed' });
  });

  it('unlock passes password only via env and returns trimmed session', async () => {
    const { run, calls } = fake([ok('SESSIONKEY\n')]);
    const session = await new BwClient(run).unlock('master-pw-123');
    expect(session).toBe('SESSIONKEY');
    expect(calls[0].args).toEqual(['unlock', '--passwordenv', 'BW_BROKER_MASTER', '--raw']);
    expect(calls[0].args.join(' ')).not.toContain('master-pw-123');
    expect(calls[0].env).toEqual({ BW_BROKER_MASTER: 'master-pw-123' });
  });

  it('unlock maps invalid master password', async () => {
    const { run } = fake([{ code: 1, stdout: '', stderr: 'Invalid master password.' }]);
    await expect(new BwClient(run).unlock('master-pw-123')).rejects.toMatchObject({
      code: 'wrong_master_password',
      message: 'Bitwarden rejected the master password.',
    });
  });

  it('unlock failure message does not contain the password and is truncated', async () => {
    const { run } = fake([{ code: 1, stdout: '', stderr: `boom master-pw-123 ${'x'.repeat(2000)}` }]);
    const err = await new BwClient(run).unlock('master-pw-123').catch((e) => e);
    expect(err.code).toBe('bw_failed');
    expect(err.message).not.toContain('master-pw-123');
    expect(err.message.length).toBeLessThanOrEqual(600);
  });

  it('unlock with empty output fails', async () => {
    const { run } = fake([ok('  \n')]);
    await expect(new BwClient(run).unlock('master-pw-123')).rejects.toMatchObject({ code: 'bw_failed' });
  });

  it('sync/lock/listItems pass session via env, never args', async () => {
    const { run, calls } = fake([ok(), ok(JSON.stringify([{ id: '1', name: 'a' }])), ok()]);
    const c = new BwClient(run);
    await c.sync('SESS-XYZ');
    const items = await c.listItems('SESS-XYZ', 'f1');
    await c.lock();
    expect(items).toEqual([{ id: '1', name: 'a' }]);
    expect(calls[0]).toEqual({ args: ['sync'], env: { BW_SESSION: 'SESS-XYZ' } });
    expect(calls[1]).toEqual({ args: ['list', 'items', '--folderid', 'f1'], env: { BW_SESSION: 'SESS-XYZ' } });
    expect(calls[2].args).toEqual(['lock']);
    for (const call of calls) expect(call.args.join(' ')).not.toContain('SESS-XYZ');
  });

  it('listItems rejects non-array output without echoing it', async () => {
    const { run } = fake([ok('{"password":"hunter2"}')]);
    const err = await new BwClient(run).listItems('S', 'f').catch((e) => e);
    expect(err.message).toBe('Bitwarden CLI returned unexpected output.');
  });

  it('folderId returns exact match', async () => {
    const { run, calls } = fake([
      ok(JSON.stringify([{ id: 'a', name: 'Claude Access Old' }, { id: 'b', name: 'Claude Access' }])),
    ]);
    expect(await new BwClient(run).folderId('S', 'Claude Access')).toBe('b');
    expect(calls[0].args).toEqual(['list', 'folders', '--search', 'Claude Access']);
    expect(calls[0].env).toEqual({ BW_SESSION: 'S' });
  });

  it('folderId returns null when only a partial-name folder exists', async () => {
    const { run } = fake([ok(JSON.stringify([{ id: 'a', name: 'Claude Access Old' }]))]);
    expect(await new BwClient(run).folderId('S', 'Claude Access')).toBeNull();
  });

  it('non-zero exit scrubs session from stderr', async () => {
    const { run } = fake([{ code: 1, stdout: '', stderr: 'bad session SESS-XYZ' }]);
    const err = await new BwClient(run).sync('SESS-XYZ').catch((e) => e);
    expect(err.code).toBe('bw_failed');
    expect(err.message).not.toContain('SESS-XYZ');
  });
});
