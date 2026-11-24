import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/hook/guard.ts
var guard_exports = {};
__export(guard_exports, {
  decide: () => decide,
  normalizePath: () => normalizePath
});
function normalizePath(p) {
  const s = p.toLowerCase().replace(/\\/g, "/").replace(/\/{2,}/g, "/");
  const out = [];
  for (const seg of s.split("/")) {
    if (seg === ".") continue;
    if (seg === "..") {
      if (out.length > 1 || out.length === 1 && out[0] !== "" && !/^[a-z]:$/.test(out[0])) out.pop();
      continue;
    }
    out.push(seg);
  }
  return out.join("/").replace(/(.)\/$/, "$1");
}
function isInside(path, root) {
  return path === root || path.startsWith(root + "/");
}
function protectedPaths(env) {
  const entries = [
    [env.appData, "\\Bitwarden CLI"],
    [env.appData, "\\Bitwarden"],
    [env.appData, "\\claude-bw-broker"],
    [env.localAppData, "\\claude-bw-broker"],
    [env.pluginRoot, ""],
    [env.userProfile, "\\.claude\\plugins"],
    [env.userProfile, "\\.claude\\settings.json"],
    [env.userProfile, "\\.claude\\settings.local.json"],
    [env.projectDir, "\\.claude\\settings.json"],
    [env.projectDir, "\\.claude\\settings.local.json"]
  ];
  const all = entries.filter(([base]) => !!base).map(([base, suffix]) => normalizePath(base + suffix));
  return { all, plugin: env.pluginRoot ? normalizePath(env.pluginRoot) : "" };
}
function normalizeCommand(cmd, env) {
  const variants = [];
  const base = cmd.toLowerCase();
  const sub = (s, re, val) => val ? s.replace(re, () => val.toLowerCase()) : s;
  let expanded = base;
  expanded = sub(expanded, /%userprofile%|\$\{?(env:)?userprofile\}?|\$\{home\}|\$home(?![a-z0-9_])/g, env.userProfile);
  expanded = sub(expanded, /%localappdata%|\$\{?(env:)?localappdata\}?/g, env.localAppData);
  expanded = sub(expanded, /%appdata%|\$\{?(env:)?appdata\}?/g, env.appData);
  expanded = expanded.replace(/(^|[\s'"=:(])~(?=[\\/]|$|\s|['")])/g, (_m, pre) => pre + env.userProfile.toLowerCase());
  for (const s of /* @__PURE__ */ new Set([base, expanded])) {
    const slashed = s.replace(/\\/g, "/").replace(/\/{2,}/g, "/");
    const dotless = slashed.replace(/\/\.(?=\/)/g, "");
    const drive = dotless.replace(/(^|[\s'"=(:])\/([a-z])\//g, "$1$2:/");
    variants.push(slashed, dotless, drive);
    variants.push(drive.replace(/["']/g, ""));
  }
  return variants;
}
function decide(toolName, toolInput, env) {
  const { all, plugin } = protectedPaths(env);
  if (FILE_TOOLS.has(toolName)) {
    const targets = [];
    for (const key of PATH_KEYS) {
      const v = toolInput[key];
      if (v === void 0) continue;
      if (typeof v !== "string") return deny("Blocked: malformed path argument.");
      targets.push(v);
    }
    if (toolName === "Glob" && typeof toolInput["pattern"] === "string") {
      const pat = toolInput["pattern"];
      if (/^([a-z]:)?[\\/]/i.test(pat) || pat.startsWith("~")) targets.push(pat.replace(/[\\/][^\\/]*[*?[{].*$/, "") || "/");
    }
    const searchTool = toolName === "Grep" || toolName === "Glob";
    const proj = env.projectDir ? normalizePath(env.projectDir) : "";
    const ancestorRoots = all.filter((r) => r !== plugin && !(proj && r.startsWith(proj + "/.claude/")));
    const hasPath = PATH_KEYS.some((k) => toolInput[k] !== void 0);
    if (searchTool && !hasPath && env.projectDir) targets.push(env.projectDir);
    for (const t of targets) {
      const raw = /^([a-z]:)?[\\/]/i.test(t) || t.startsWith("~") ? t : `${env.projectDir}\\${t}`;
      const p = normalizePath(t.startsWith("~") ? env.userProfile + t.slice(1) : raw);
      const pluginRead = READ_ONLY_TOOLS.has(toolName) && !!plugin && isInside(p, plugin);
      const protectedHit = !pluginRead && all.some((r) => isInside(p, r));
      const ancestorHit = searchTool && ancestorRoots.some((r) => isInside(r, p));
      if (protectedHit || ancestorHit) {
        return deny("Blocked: this path holds Bitwarden data, broker config/code/audit log, Claude settings or Claude plugins and is off limits to Claude.");
      }
    }
    return { allow: true };
  }
  if (SHELL_TOOLS.has(toolName)) {
    const command = toolInput["command"];
    if (typeof command !== "string") return deny("Blocked: malformed command argument.");
    if (BW_WORD.test(command)) return deny("Blocked: the Bitwarden CLI may not be run directly; use the broker tools.");
    if (/@bitwarden\/cli/i.test(command)) return deny("Blocked: the Bitwarden CLI may not be run directly; use the broker tools.");
    if (UI_AUTOMATION.test(command)) return deny("Blocked: UI automation could answer approval dialogs.");
    if (CLAUDE_DIR.test(command) && /settings|plugins/i.test(command)) {
      return deny("Blocked: command references Claude settings or plugin files.");
    }
    const variants = normalizeCommand(command, env);
    if (variants.some((v) => v.includes(".claude/settings.json") || v.includes(".claude/settings.local.json"))) {
      return deny("Blocked: command references Claude settings files.");
    }
    if (all.some((r) => variants.some((v) => v.includes(r)))) {
      return deny("Blocked: command references a protected path (Bitwarden data, broker files, audit log, Claude settings or plugins).");
    }
    return { allow: true };
  }
  return { allow: true };
}
var FILE_TOOLS, READ_ONLY_TOOLS, SHELL_TOOLS, PATH_KEYS, CLAUDE_DIR, BW_WORD, UI_AUTOMATION, deny;
var init_guard = __esm({
  "src/hook/guard.ts"() {
    "use strict";
    FILE_TOOLS = /* @__PURE__ */ new Set(["Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Grep", "Glob"]);
    READ_ONLY_TOOLS = /* @__PURE__ */ new Set(["Read", "Grep", "Glob"]);
    SHELL_TOOLS = /* @__PURE__ */ new Set(["Bash", "PowerShell"]);
    PATH_KEYS = ["file_path", "path", "notebook_path"];
    CLAUDE_DIR = /\.claude(?![\w-])/i;
    BW_WORD = /(^|[\s;&|(`'"/\\])bw(\.exe|\.cmd|\.ps1)?(?=$|[\s;&|)`'"])/i;
    UI_AUTOMATION = /SendKeys|UIAutomation|System\.Windows\.Automation|AutoHotkey|\bahk\b|wscript|cscript|nircmd|mouse_event|SetCursorPos/i;
    deny = (reason) => ({ allow: false, reason });
  }
});

// src/hook/main.ts
function emitDeny(reason, failure) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: reason
      }
    }) + "\n"
  );
  if (failure) {
    process.stderr.write(reason + "\n");
    process.exitCode = 2;
  }
}
async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks).toString("utf8");
}
async function run() {
  const { decide: decide2 } = await Promise.resolve().then(() => (init_guard(), guard_exports));
  const input = JSON.parse(await readStdin());
  if (typeof input !== "object" || input === null || Array.isArray(input)) throw new Error("bad input");
  const rec = input;
  const toolName = rec["tool_name"];
  const toolInput = rec["tool_input"];
  if (typeof toolName !== "string" || typeof toolInput !== "object" || toolInput === null || Array.isArray(toolInput)) {
    throw new Error("bad input");
  }
  const cwd = typeof rec["cwd"] === "string" ? rec["cwd"] : "";
  const e = process.env;
  const d = decide2(toolName, toolInput, {
    appData: e["APPDATA"] ?? "",
    localAppData: e["LOCALAPPDATA"] ?? "",
    userProfile: e["USERPROFILE"] ?? "",
    pluginRoot: e["CLAUDE_PLUGIN_ROOT"] ?? "",
    projectDir: e["CLAUDE_PROJECT_DIR"] || cwd
  });
  if (!d.allow) emitDeny(d.reason, false);
}
run().catch(() => emitDeny("Blocked: guard hook could not evaluate this tool call (fail closed).", true));
