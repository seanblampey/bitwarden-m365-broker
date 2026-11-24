export interface GuardEnv {
  appData: string;
  localAppData: string;
  userProfile: string;
  pluginRoot: string;
  projectDir: string;
}

export type Decision = { allow: true } | { allow: false; reason: string };

const FILE_TOOLS = new Set(['Read', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'Grep', 'Glob']);
const READ_ONLY_TOOLS = new Set(['Read', 'Grep', 'Glob']);
const SHELL_TOOLS = new Set(['Bash', 'PowerShell']);
const PATH_KEYS = ['file_path', 'path', 'notebook_path'];

const BW_WORD = /(^|[\s;&|(`'"/\\])bw(\.exe|\.cmd|\.ps1)?(?=$|[\s;&|)`'"])/i;
const UI_AUTOMATION =
  /SendKeys|UIAutomation|System\.Windows\.Automation|AutoHotkey|\bahk\b|wscript|cscript|nircmd|mouse_event|SetCursorPos/i;

/** Lowercase, `\` to `/`, collapse duplicate slashes, resolve `.` and `..`. Platform independent. */
export function normalizePath(p: string): string {
  const s = p.toLowerCase().replace(/\\/g, '/').replace(/\/{2,}/g, '/');
  const out: string[] = [];
  for (const seg of s.split('/')) {
    if (seg === '.') continue;
    if (seg === '..') {
      if (out.length > 1 || (out.length === 1 && out[0] !== '' && !/^[a-z]:$/.test(out[0]!))) out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.join('/').replace(/(.)\/$/, '$1');
}

function isInside(path: string, root: string): boolean {
  return path === root || path.startsWith(root + '/');
}

function protectedPaths(env: GuardEnv): { all: string[]; plugin: string } {
  // [base value, suffix]; entries whose base is empty are dropped (they would collapse to a bare "/suffix")
  const entries: Array<[string, string]> = [
    [env.appData, '\\Bitwarden CLI'],
    [env.appData, '\\Bitwarden'],
    [env.appData, '\\claude-bw-broker'],
    [env.pluginRoot, ''],
    [env.userProfile, '\\.claude\\settings.json'],
    [env.userProfile, '\\.claude\\settings.local.json'],
    [env.projectDir, '\\.claude\\settings.json'],
    [env.projectDir, '\\.claude\\settings.local.json'],
  ];
  const all = entries.filter(([base]) => !!base).map(([base, suffix]) => normalizePath(base + suffix));
  return { all, plugin: env.pluginRoot ? normalizePath(env.pluginRoot) : '' };
}

/** Replace profile/appdata shorthands in a shell command, then normalise for substring matching. */
function normalizeCommand(cmd: string, env: GuardEnv): string[] {
  const variants: string[] = [];
  const base = cmd.toLowerCase();
  const sub = (s: string, re: RegExp, val: string) => (val ? s.replace(re, () => val.toLowerCase()) : s);
  let expanded = base;
  expanded = sub(expanded, /%userprofile%|\$\{?(env:)?userprofile\}?|\$\{home\}|\$home(?![a-z0-9_])/g, env.userProfile);
  expanded = sub(expanded, /%localappdata%|\$\{?(env:)?localappdata\}?/g, env.localAppData);
  expanded = sub(expanded, /%appdata%|\$\{?(env:)?appdata\}?/g, env.appData);
  expanded = expanded.replace(/(^|[\s'"=:(])~(?=[\\/]|$|\s|['")])/g, (_m, pre: string) => pre + env.userProfile.toLowerCase());
  for (const s of new Set([base, expanded])) {
    const slashed = s.replace(/\\/g, '/').replace(/\/{2,}/g, '/');
    const dotless = slashed.replace(/\/\.(?=\/)/g, '');
    // Git-Bash drive form /c/users/... also matched as c:/users/...
    const drive = dotless.replace(/(^|[\s'"=(:])\/([a-z])\//g, '$1$2:/');
    variants.push(slashed, dotless, drive);
    // shell quoting can split a path (Roaming/"Bitwarden CLI"); also match with quotes removed
    variants.push(drive.replace(/["']/g, ''));
  }
  return variants;
}

const deny = (reason: string): Decision => ({ allow: false, reason });

export function decide(toolName: string, toolInput: Record<string, unknown>, env: GuardEnv): Decision {
  const { all, plugin } = protectedPaths(env);

  if (FILE_TOOLS.has(toolName)) {
    const targets: string[] = [];
    for (const key of PATH_KEYS) {
      const v = toolInput[key];
      if (v === undefined) continue;
      if (typeof v !== 'string') return deny('Blocked: malformed path argument.');
      targets.push(v);
    }
    if (toolName === 'Glob' && typeof toolInput['pattern'] === 'string') {
      const pat = toolInput['pattern'];
      if (/^([a-z]:)?[\\/]/i.test(pat) || pat.startsWith('~')) targets.push(pat.replace(/[\\/][^\\/]*[*?[{].*$/, '') || '/');
    }
    const searchTool = toolName === 'Grep' || toolName === 'Glob';
    const proj = env.projectDir ? normalizePath(env.projectDir) : '';
    // ancestor check: a search rooted above a protected root would read it.
    // Plugin root (readable) and project-level settings (always inside projectDir) are excluded.
    const ancestorRoots = all.filter((r) => r !== plugin && !(proj && r.startsWith(proj + '/.claude/')));
    const hasPath = PATH_KEYS.some((k) => toolInput[k] !== undefined);
    if (searchTool && !hasPath && env.projectDir) targets.push(env.projectDir);
    for (const t of targets) {
      const raw = /^([a-z]:)?[\\/]/i.test(t) || t.startsWith('~') ? t : `${env.projectDir}\\${t}`;
      const p = normalizePath(t.startsWith('~') ? env.userProfile + t.slice(1) : raw);
      const protectedHit = all.some((r) => isInside(p, r) && !(READ_ONLY_TOOLS.has(toolName) && r === plugin));
      const ancestorHit = searchTool && ancestorRoots.some((r) => isInside(r, p));
      if (protectedHit || ancestorHit) {
        return deny('Blocked: this path holds Bitwarden data, broker config/code or Claude settings and is off limits to Claude.');
      }
    }
    return { allow: true };
  }

  if (SHELL_TOOLS.has(toolName)) {
    const command = toolInput['command'];
    if (typeof command !== 'string') return deny('Blocked: malformed command argument.');
    if (BW_WORD.test(command)) return deny('Blocked: the Bitwarden CLI may not be run directly; use the broker tools.');
    if (/@bitwarden\/cli/i.test(command)) return deny('Blocked: the Bitwarden CLI may not be run directly; use the broker tools.');
    if (UI_AUTOMATION.test(command)) return deny('Blocked: UI automation could answer approval dialogs.');
    const variants = normalizeCommand(command, env);
    if (variants.some((v) => v.includes('.claude/settings.json') || v.includes('.claude/settings.local.json'))) {
      return deny('Blocked: command references Claude settings files.');
    }
    if (all.some((r) => variants.some((v) => v.includes(r)))) {
      return deny('Blocked: command references a protected path (Bitwarden data, broker files or Claude settings).');
    }
    return { allow: true };
  }

  return { allow: true };
}
