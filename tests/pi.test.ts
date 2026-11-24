import { describe, it, expect } from 'vitest';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import bitwardenM365, { decidePi, piGuardEnv, MCP_SERVER_NAME, type PiApi, type PiToolCallEvent } from '../src/pi/extension.js';

const winEnv = {
  USERPROFILE: 'C:\\Users\\alex',
  APPDATA: 'C:\\Users\\alex\\AppData\\Roaming',
  LOCALAPPDATA: 'C:\\Users\\alex\\AppData\\Local',
};
const env = piGuardEnv(winEnv, 'C:\\Users\\alex\\.pi\\agent\\git\\github.com\\x\\bitwarden-m365-broker', 'C:\\work\\proj');
const blocked = (tool: string, input: Record<string, unknown>) => !decidePi(tool, input, env).allow;

describe('decidePi', () => {
  it('blocks the Bitwarden CLI in bash and powershell', () => {
    expect(blocked('bash', { command: 'bw list items' })).toBe(true);
    expect(blocked('powershell', { command: '& bw.exe get password x' })).toBe(true);
    expect(blocked('bash', { command: 'git status' })).toBe(false);
  });

  it('blocks reads, writes and edits of Bitwarden and broker files, including @-prefixed paths', () => {
    expect(blocked('read', { path: 'C:\\Users\\alex\\AppData\\Roaming\\Bitwarden CLI\\data.json' })).toBe(true);
    expect(blocked('read', { path: '@C:/Users/alex/AppData/Local/claude-bw-broker/audit.jsonl' })).toBe(true);
    expect(blocked('write', { path: 'C:\\Users\\alex\\AppData\\Roaming\\claude-bw-broker\\config.json', content: '{}' })).toBe(true);
    expect(blocked('edit', { path: 'C:\\work\\proj\\src\\a.ts', edits: [] })).toBe(false);
    expect(blocked('read', { path: 'src/a.ts' })).toBe(false);
  });

  it('protects Pi\'s own config so the model cannot switch this extension off', () => {
    expect(blocked('write', { path: 'C:\\Users\\alex\\.pi\\agent\\settings.json', content: '{}' })).toBe(true);
    expect(blocked('edit', { path: 'C:\\Users\\alex\\.pi\\agent\\mcp.json', edits: [] })).toBe(true);
    expect(blocked('write', { path: '.pi\\extensions\\evil.ts', content: '' })).toBe(true);
    expect(blocked('bash', { command: 'rm -rf ~/.pi/agent/git' })).toBe(true);
    expect(blocked('bash', { command: 'cd .pi && cat settings.json' })).toBe(true);
    expect(blocked('ls', { path: 'C:\\Users\\alex\\.pi' })).toBe(true);
  });

  it('honours PI_CODING_AGENT_DIR', () => {
    const custom = piGuardEnv({ ...winEnv, PI_CODING_AGENT_DIR: 'D:\\pi-config' }, 'D:\\pkg', 'C:\\work\\proj');
    expect(decidePi('write', { path: 'D:\\pi-config\\settings.json' }, custom).allow).toBe(false);
  });

  it('blocks searches and listings rooted above protected folders', () => {
    expect(blocked('grep', { pattern: 'password', path: 'C:\\Users\\alex\\AppData\\Roaming' })).toBe(true);
    expect(blocked('find', { pattern: '*.json', path: 'C:\\Users\\alex' })).toBe(true);
    expect(blocked('ls', { path: 'C:\\Users\\alex\\AppData' })).toBe(true);
    expect(blocked('grep', { pattern: 'TODO' })).toBe(false);
    expect(blocked('find', { pattern: '*.ts', path: 'src' })).toBe(false);
  });

  it('allows the broker\'s own tools and codemode (its tool calls are checked one by one)', () => {
    expect(blocked('mcp__bitwarden_m365__graph_request', { tenant: 't', method: 'GET', path: '/users' })).toBe(false);
    expect(blocked('codemode', { code: 'await tools.bash({ command: "bw list items" })' })).toBe(false);
  });

  it('checks every text value of an unknown tool with the shell rules', () => {
    expect(blocked('some_ext_exec', { cmd: { line: 'bw get password x' } })).toBe(true);
    expect(blocked('mcp__files__read_file', { path: 'C:\\Users\\alex\\AppData\\Roaming\\Bitwarden\\data.json' })).toBe(true);
    expect(blocked('web_search', { query: 'graph api list users' })).toBe(false);
  });

  it('fails closed on malformed input', () => {
    expect(blocked('bash', {})).toBe(true);
    expect(blocked('read', { path: 42 })).toBe(true);
  });
});

describe('extension entry point', () => {
  function load() {
    const servers: Array<{ name: string; config: Record<string, unknown> }> = [];
    let handler: ((e: PiToolCallEvent, ctx: { cwd?: string }) => Promise<unknown>) | undefined;
    const pi: PiApi = {
      registerMcpServer: (name, config) => servers.push({ name, config }),
      on: (_event, h) => { handler = h; },
    };
    bitwardenM365(pi);
    return { servers, handler: handler! };
  }

  it('registers the broker as a direct MCP server pointing at dist/server.js', () => {
    const { servers } = load();
    expect(servers).toHaveLength(1);
    expect(servers[0]!.name).toBe(MCP_SERVER_NAME);
    expect(servers[0]!.config.command).toBe('node');
    expect(servers[0]!.config.exposure).toBe('direct');
    const args = servers[0]!.config.args as string[];
    expect(args[0]!.endsWith(join('dist', 'server.js'))).toBe(true);
    expect(existsSync(args[0]!)).toBe(true);
  });

  it('blocks a bw call and allows a harmless one through the tool_call handler', async () => {
    const { handler } = load();
    expect(await handler({ toolName: 'bash', input: { command: 'bw list items' } }, { cwd: '/tmp' })).toMatchObject({ block: true });
    expect(await handler({ toolName: 'bash', input: { command: 'ls' } }, { cwd: '/tmp' })).toBeUndefined();
  });
});
