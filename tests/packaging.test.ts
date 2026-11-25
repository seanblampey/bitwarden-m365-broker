import { describe, it, expect, beforeAll } from 'vitest';
import { execSync, spawn } from 'node:child_process';
import { existsSync, readFileSync, cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = join(__dirname, '..');
const json = (p: string) => JSON.parse(readFileSync(join(root, p), 'utf8'));

describe('plugin packaging', () => {
  beforeAll(() => {
    execSync('npm run build', { cwd: root, stdio: 'pipe' });
  }, 120_000);

  it('plugin.json and marketplace.json parse and match', () => {
    const plugin = json('.claude-plugin/plugin.json');
    const market = json('.claude-plugin/marketplace.json');
    expect(plugin.name).toBe('bitwarden-m365');
    expect(market.name).toBe('bitwarden-m365');
    expect(market.plugins).toHaveLength(1);
    expect(market.plugins[0]).toMatchObject({ name: plugin.name, source: './' });
  });

  it('.mcp.json points at dist/server.js', () => {
    const s = json('.mcp.json').mcpServers['bitwarden-m365'];
    expect(s.command).toBe('node');
    expect(s.args).toEqual(['${CLAUDE_PLUGIN_ROOT}/dist/server.js']);
  });

  it('hooks.json points at dist/hook/main.js', () => {
    const h = json('hooks/hooks.json').hooks.PreToolUse[0].hooks[0];
    expect(h.command).toContain('${CLAUDE_PLUGIN_ROOT}/dist/hook/main.js');
  });

  it('SKILL.md has name and description frontmatter', () => {
    const t = readFileSync(join(root, 'skills/m365-broker/SKILL.md'), 'utf8');
    expect(t).toMatch(/^---\nname: m365-broker\ndescription: .+\n---/);
  });

  it('build output contains everything the manifests reference', () => {
    for (const f of [
      'dist/server.js',
      'dist/hook/main.js',
      'dist/win/password.ps1',
      'dist/win/confirm.ps1',
      'dist/admin/run-admin-cmdlet.ps1',
      'dist/node_modules/playwright-core/package.json',
    ]) {
      expect(existsSync(join(root, f)), f).toBe(true);
    }
  });

  it('bundled server runs from a folder with no node_modules and lists its tools', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bw-m365-'));
    try {
      cpSync(join(root, 'dist'), join(dir, 'dist'), { recursive: true });
      const names = await new Promise<string[]>((resolve, reject) => {
        const p = spawn(process.execPath, [join(dir, 'dist/server.js')], { cwd: dir, stdio: ['pipe', 'pipe', 'pipe'] });
        let out = '';
        let err = '';
        const timer = setTimeout(() => { p.kill(); reject(new Error(`timeout: ${err}`)); }, 15_000);
        p.stderr.on('data', (d) => (err += d));
        p.stdout.on('data', (d) => {
          out += d;
          const line = out.split('\n').find((l) => l.includes('"id":2'));
          if (line) {
            clearTimeout(timer);
            p.stdin.end();
            resolve(JSON.parse(line).result.tools.map((t: { name: string }) => t.name));
          }
        });
        const send = (m: object) => p.stdin.write(JSON.stringify(m) + '\n');
        send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
      });
      expect(names.sort()).toEqual(['admin_cmdlet', 'connect', 'disconnect', 'graph_request', 'list_tenants', 'lock']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('bundled hook runs from a folder with no node_modules', () => {
    const dir = mkdtempSync(join(tmpdir(), 'bw-m365-'));
    try {
      cpSync(join(root, 'dist'), join(dir, 'dist'), { recursive: true });
      const out = execSync(`"${process.execPath}" dist/hook/main.js`, {
        cwd: dir,
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'bw list items' } }),
      }).toString();
      expect(JSON.parse(out).hookSpecificOutput.permissionDecision).toBe('deny');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
