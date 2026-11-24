import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
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
    expect(market.name).toBe('bitwarden-m365-local');
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
      'dist/exo/run-cmdlet.ps1',
    ]) {
      expect(existsSync(join(root, f)), f).toBe(true);
    }
  });
});
