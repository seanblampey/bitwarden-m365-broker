import { describe, it, expect, vi } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, isEntryPoint } from '../src/server.js';
import type { Broker } from '../src/broker.js';

function fakeBroker() {
  return {
    listTenants: vi.fn(async () => '{"tenants":["acme"]}'),
    connect: vi.fn(async (t: string) => JSON.stringify({ tenant: t, account: 'a@acme.com' })),
    graphRequest: vi.fn(async () => '{"status":200,"body":{"ok":1}}'),
    adminCmdlet: vi.fn(async () => '{"error":"denied","message":"The user declined this change."}'),
    disconnect: vi.fn(async (t?: string) => JSON.stringify({ disconnected: t ?? 'all' })),
    lock: vi.fn(async () => '{"locked":true}'),
  };
}

async function connect() {
  const broker = fakeBroker();
  const server = createServer(broker as unknown as Broker);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'test', version: '0.0.0' });
  await Promise.all([server.connect(serverT), client.connect(clientT)]);
  return { broker, client, server };
}

describe('MCP server', () => {
  it('lists exactly the six tools', async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      ['admin_cmdlet', 'connect', 'disconnect', 'graph_request', 'list_tenants', 'lock'],
    );
    for (const t of tools) expect(t.description).toBeTruthy();
  });

  it('graph_request returns text content and defaults api_version', async () => {
    const { client, broker } = await connect();
    const r = await client.callTool({ name: 'graph_request', arguments: { tenant: 'acme', method: 'GET', path: '/users' } });
    expect(r.content).toEqual([{ type: 'text', text: '{"status":200,"body":{"ok":1}}' }]);
    expect(r.isError).toBeFalsy();
    expect(broker.graphRequest).toHaveBeenCalledWith('acme', 'GET', '/users', undefined, 'v1.0');
  });

  it('rejects an invalid method via the schema without calling the broker', async () => {
    const { client, broker } = await connect();
    const r = await client.callTool({ name: 'graph_request', arguments: { tenant: 'acme', method: 'TRACE', path: '/users' } });
    expect(r.isError).toBe(true);
    expect(broker.graphRequest).not.toHaveBeenCalled();
  });

  it('marks broker error results as isError and passes admin_cmdlet arguments', async () => {
    const { client, broker } = await connect();
    const r = await client.callTool({ name: 'admin_cmdlet', arguments: { tenant: 'acme', service: 'exchange', cmdlet: 'Set-Mailbox', parameters: { Identity: 'x' }, select: ['Name'], first: 3 } });
    expect(r.isError).toBe(true);
    expect(broker.adminCmdlet).toHaveBeenCalledWith('acme', 'exchange', 'Set-Mailbox', { Identity: 'x' }, { select: ['Name'], first: 3, site: undefined });
    // null for unused options is accepted and passed on as absent
    await client.callTool({ name: 'admin_cmdlet', arguments: { tenant: 'acme', service: 'teams', cmdlet: 'Get-CsTeamsMeetingPolicy', parameters: null, select: null, first: null, site: null } });
    expect(broker.adminCmdlet).toHaveBeenLastCalledWith('acme', 'teams', 'Get-CsTeamsMeetingPolicy', undefined, { select: undefined, first: undefined, site: undefined });
    // an unknown service never reaches the broker
    const bad = await client.callTool({ name: 'admin_cmdlet', arguments: { tenant: 'acme', service: 'azure', cmdlet: 'Get-Thing' } }).catch((e) => ({ isError: true, e }));
    expect((bad as { isError?: boolean }).isError).toBe(true);
    expect(broker.adminCmdlet).toHaveBeenCalledTimes(2);
  });

  it('routes the remaining tools', async () => {
    const { client, broker } = await connect();
    await client.callTool({ name: 'list_tenants', arguments: {} });
    await client.callTool({ name: 'connect', arguments: { tenant: 'acme' } });
    await client.callTool({ name: 'disconnect', arguments: {} });
    await client.callTool({ name: 'lock', arguments: {} });
    expect(broker.listTenants).toHaveBeenCalledOnce();
    expect(broker.connect).toHaveBeenCalledWith('acme');
    expect(broker.disconnect).toHaveBeenCalledWith(undefined);
    expect(broker.lock).toHaveBeenCalledOnce();
  });
});

describe('isEntryPoint', () => {
  const id = (p: string) => p;
  it('matches the same path, case-insensitively only on win32', () => {
    const url = 'file:///C:/Plugins/Broker/dist/server.js';
    const winPath = new URL(url).pathname; // the path fileURLToPath yields on this host
    expect(isEntryPoint(url, winPath, 'linux', id)).toBe(true);
    expect(isEntryPoint(url, winPath.toLowerCase(), 'win32', id)).toBe(true);
    expect(isEntryPoint(url, winPath.toLowerCase(), 'linux', id)).toBe(false);
    expect(isEntryPoint(url, '/other/server.js', 'win32', id)).toBe(false);
  });
  it('is false when argv[1] is missing or cannot be resolved', () => {
    expect(isEntryPoint('file:///x/server.js', undefined, 'win32', id)).toBe(false);
    const fail = () => { throw new Error('ENOENT'); };
    expect(isEntryPoint('file:///x/server.js', '/x/server.js', 'win32', fail)).toBe(false);
  });
  it('resolves real paths by default', () => {
    expect(isEntryPoint(import.meta.url, new URL(import.meta.url).pathname)).toBe(true);
  });
});
