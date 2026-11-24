import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { decide, type GuardEnv } from '../src/hook/guard.js';

const env: GuardEnv = {
  appData: 'C:\\Users\\sean\\AppData\\Roaming',
  localAppData: 'C:\\Users\\sean\\AppData\\Local',
  userProfile: 'C:\\Users\\sean',
  pluginRoot: 'C:\\Users\\sean\\.claude\\plugins\\bw-m365',
  projectDir: 'C:\\work\\proj',
};
const allowed = (t: string, i: Record<string, unknown>, e = env) => decide(t, i, e).allow;

describe('decide', () => {
  it('denies bw invocations', () => {
    expect(allowed('Bash', { command: 'bw get password x' })).toBe(false);
    expect(allowed('PowerShell', { command: '& BW.exe list items' })).toBe(false);
    expect(allowed('Bash', { command: 'npx @bitwarden/cli list' })).toBe(false);
    expect(allowed('Bash', { command: 'echo hi; bw.cmd status' })).toBe(false);
  });
  it('allows harmless commands', () => {
    expect(allowed('Bash', { command: 'echo bwlib && ls' })).toBe(true);
    expect(allowed('Bash', { command: 'git log' })).toBe(true);
  });
  it('denies protected file access in any case/slash style', () => {
    expect(allowed('Read', { file_path: 'c:/users/sean/appdata/roaming/bitwarden cli/data.json' })).toBe(false);
    expect(allowed('Read', { file_path: 'C:\\Users\\sean\\AppData\\Roaming\\claude-bw-broker\\config.json' })).toBe(false);
    expect(allowed('Edit', { file_path: 'C:\\Users\\sean\\.claude\\settings.json' })).toBe(false);
    expect(allowed('Edit', { file_path: 'C:\\work\\proj\\.claude\\settings.local.json' })).toBe(false);
    expect(allowed('Write', { file_path: `${env.pluginRoot}\\dist\\server.js` })).toBe(false);
    expect(allowed('Grep', { path: 'C:\\Users\\sean\\AppData\\Roaming\\Bitwarden' })).toBe(false);
  });
  it('resolves . and .. and duplicate slashes', () => {
    expect(allowed('Read', { file_path: 'C:\\work\\..\\Users\\sean\\\\AppData\\Roaming\\.\\Bitwarden CLI\\x' })).toBe(false);
    expect(allowed('Read', { file_path: 'C:\\Users\\sean\\AppData\\Roaming\\Bitwarden CLI\\..\\ok.txt' })).toBe(true);
  });
  it('allows reading the plugin but not writing it', () => {
    expect(allowed('Read', { file_path: `${env.pluginRoot}\\README.md` })).toBe(true);
    expect(allowed('Glob', { path: env.pluginRoot, pattern: '*.md' })).toBe(true);
    expect(allowed('MultiEdit', { file_path: `${env.pluginRoot}\\README.md` })).toBe(false);
  });
  it('allows unrelated files, sibling-prefix dirs, and unknown tools', () => {
    expect(allowed('Read', { file_path: 'C:\\work\\notes.txt' })).toBe(true);
    expect(allowed('Read', { file_path: 'C:\\Users\\sean\\AppData\\Roaming\\BitwardenX\\a' })).toBe(true);
    expect(allowed('WebFetch', { url: 'https://example.com' })).toBe(true);
  });
  it('denies UI automation', () => {
    expect(allowed('PowerShell', { command: '[System.Windows.Forms.SendKeys]::SendWait("{ENTER}")' })).toBe(false);
    expect(allowed('Bash', { command: 'nircmd.exe sendkeypress' })).toBe(false);
  });
  it('treats ~, %USERPROFILE%, $env:USERPROFILE as the profile', () => {
    expect(allowed('Bash', { command: 'cat ~/.claude/settings.json' }, { ...env, userProfile: '~' })).toBe(false);
    expect(allowed('Bash', { command: 'cat ~/.claude/settings.json' })).toBe(false);
    expect(allowed('Bash', { command: 'type %USERPROFILE%\\.claude\\settings.json' })).toBe(false);
    expect(allowed('PowerShell', { command: 'gc $env:USERPROFILE\\.claude\\settings.local.json' })).toBe(false);
    expect(allowed('PowerShell', { command: 'gc $env:APPDATA\\Bitwarden\\data.json' })).toBe(false);
  });
  it('denies shell commands that mention protected paths', () => {
    expect(allowed('Bash', { command: 'cat "C:\\Users\\sean\\AppData\\Roaming\\Bitwarden CLI\\data.json"' })).toBe(false);
    expect(allowed('Bash', { command: 'ls C:/work/proj/.claude/settings.json' })).toBe(false);
  });
  it('fails closed on malformed input', () => {
    expect(allowed('Read', { file_path: 42 })).toBe(false);
    expect(allowed('Bash', { command: ['bw'] })).toBe(false);
    expect(allowed('Bash', {})).toBe(false);
  });
});

describe('review fixes', () => {
  it('denies bw invoked by path', () => {
    expect(allowed('Bash', { command: './bw list' })).toBe(false);
    expect(allowed('PowerShell', { command: 'C:\\Users\\sean\\AppData\\Roaming\\npm\\bw.cmd get password x' })).toBe(false);
    expect(allowed('PowerShell', { command: '& "C:\\tools\\bw.exe" list' })).toBe(false);
  });
  it('denies relative settings paths in shell', () => {
    expect(allowed('Bash', { command: 'cat .claude/settings.json' })).toBe(false);
    expect(allowed('Bash', { command: 'echo x >> .claude/settings.local.json' })).toBe(false);
    expect(allowed('PowerShell', { command: 'gc .claude\\settings.json' })).toBe(false);
  });
  it('expands bash variable spellings and Git-Bash drive paths', () => {
    expect(allowed('Bash', { command: 'ls "$APPDATA/Bitwarden CLI"' })).toBe(false);
    expect(allowed('Bash', { command: 'ls ${APPDATA}/claude-bw-broker' })).toBe(false);
    expect(allowed('Bash', { command: 'cat $USERPROFILE/.claude/settings.json' })).toBe(false);
    expect(allowed('Bash', { command: 'ls "/c/Users/sean/AppData/Roaming/Bitwarden CLI"' })).toBe(false);
    expect(allowed('Bash', { command: 'ls /c/work/ok' })).toBe(true);
  });
  it('denies Grep/Glob on ancestors of protected roots', () => {
    expect(allowed('Grep', { path: 'C:\\Users\\sean\\AppData\\Roaming', pattern: 'x' })).toBe(false);
    expect(allowed('Glob', { path: 'C:\\Users\\sean', pattern: '**/*' })).toBe(false);
    expect(allowed('Glob', { pattern: 'C:\\Users\\sean\\AppData\\Roaming\\Bitwarden CLI\\*.json' })).toBe(false);
    expect(allowed('Glob', { pattern: 'C:\\Users\\sean\\AppData\\Roaming\\**\\data.json' })).toBe(false);
    expect(allowed('Grep', { pattern: 'x' }, { ...env, projectDir: 'C:\\Users\\sean' })).toBe(false);
    expect(allowed('Grep', { pattern: 'x' })).toBe(true);
    expect(allowed('Grep', { path: 'C:\\work\\proj', pattern: 'x' })).toBe(true);
    expect(allowed('Glob', { path: env.pluginRoot, pattern: '*.md' })).toBe(true);
  });
});

describe('HOME expansion', () => {
  it('denies $HOME and ${HOME} spellings', () => {
    expect(allowed('Bash', { command: 'cat $HOME/AppData/Roaming/"Bitwarden CLI"/data.json' })).toBe(false);
    expect(allowed('Bash', { command: 'cat ${HOME}/AppData/Roaming/claude-bw-broker/config.json' })).toBe(false);
    expect(allowed('Bash', { command: 'cat $HOME/.claude/settings.json' })).toBe(false);
  });
  it('does not mis-expand $HOMEPATH', () => {
    expect(allowed('Bash', { command: 'echo $HOMEPATH/AppData/Roaming/Bitwarden' })).toBe(true);
  });
});

describe('main.ts', () => {
  const run = (input: string) =>
    spawnSync('node', ['--import', 'tsx', 'src/hook/main.ts'], {
      input,
      encoding: 'utf8',
      env: { ...process.env, APPDATA: env.appData, USERPROFILE: env.userProfile, CLAUDE_PLUGIN_ROOT: env.pluginRoot },
    });
  it('denies bw', () => {
    const r = run('{"tool_name":"Bash","tool_input":{"command":"bw list"}}');
    expect(r.status).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
  });
  it('allows silently', () => {
    const r = run('{"tool_name":"Bash","tool_input":{"command":"git log"},"cwd":"C:\\\\work"}');
    expect(r.status).toBe(0);
    expect(r.stdout).toBe('');
  });
  it('denies malformed stdin', () => {
    for (const bad of ['not json', '', '{}', '{"tool_name":"Bash"}', '[]']) {
      const r = run(bad);
      expect(r.status).toBe(2);
      expect(r.stderr).toContain('fail closed');
      expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
    }
  });
  it('denies with exit 2 when the guard module fails to load', () => {
    const dir = mkdtempSync(join(tmpdir(), 'hook-'));
    copyFileSync(resolve('src/hook/main.ts'), join(dir, 'main.ts'));
    const r = spawnSync('node', ['--import', 'tsx', join(dir, 'main.ts')], {
      input: '{"tool_name":"Bash","tool_input":{"command":"git log"}}',
      encoding: 'utf8',
    });
    expect(r.status).toBe(2);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
  });
});
