import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);

// src/pi/extension.ts
import { homedir } from "node:os";
import { dirname, join, win32 } from "node:path";
import { fileURLToPath } from "node:url";

// src/hook/guard.ts
var FILE_TOOLS = /* @__PURE__ */ new Set(["Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Grep", "Glob"]);
var READ_ONLY_TOOLS = /* @__PURE__ */ new Set(["Read", "Grep", "Glob"]);
var SHELL_TOOLS = /* @__PURE__ */ new Set(["Bash", "PowerShell"]);
var PATH_KEYS = ["file_path", "path", "notebook_path"];
var CLAUDE_DIR = /\.claude(?![\w-])/i;
var PI_DIR = /(^|[\s'"`=:(\\/])\.pi(?=[\\/\s'"`)]|$)/i;
var BW_WORD = /(^|[\s;&|(`'"/\\])bw(\.exe|\.cmd|\.ps1)?(?=$|[\s;&|)`'"])/i;
var UI_AUTOMATION = /SendKeys|UIAutomation|System\.Windows\.Automation|AutoHotkey|\bahk\b|wscript|cscript|nircmd|mouse_event|SetCursorPos/i;
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
    [env.projectDir, "\\.claude\\settings.local.json"],
    // Pi: its settings, extensions, packages and mcp.json; a project's .pi folder
    [env.piAgentDir ?? "", ""],
    [env.piAgentDir ? env.projectDir : "", "\\.pi"]
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
var deny = (reason) => ({ allow: false, reason });
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
    const ancestorRoots = all.filter((r) => r !== plugin && !(proj && (r.startsWith(proj + "/.claude/") || r === proj + "/.pi")));
    const hasPath = PATH_KEYS.some((k) => toolInput[k] !== void 0);
    if (searchTool && !hasPath && env.projectDir) targets.push(env.projectDir);
    for (const t of targets) {
      const raw = /^([a-z]:)?[\\/]/i.test(t) || t.startsWith("~") ? t : `${env.projectDir}\\${t}`;
      const p = normalizePath(t.startsWith("~") ? env.userProfile + t.slice(1) : raw);
      const pluginRead = READ_ONLY_TOOLS.has(toolName) && !!plugin && isInside(p, plugin);
      const protectedHit = !pluginRead && all.some((r) => isInside(p, r));
      const ancestorHit = searchTool && ancestorRoots.some((r) => isInside(r, p));
      if (protectedHit || ancestorHit) {
        return deny("Blocked: this path holds Bitwarden data, broker config/code/audit log, or the agent's own settings, plugins or extensions, and is off limits to the AI assistant.");
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
    if (env.piAgentDir && PI_DIR.test(command)) {
      return deny("Blocked: command references Pi settings, extensions or packages.");
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

// src/pi/extension.ts
var MCP_SERVER_NAME = "bitwarden-m365";
var BROKER_TOOL_PREFIX = "mcp__bitwarden_m365__";
var allow = { allow: true };
var pathArg = (v) => typeof v === "string" ? v.replace(/^@/, "") : v;
function strings(value, out = [], depth = 0) {
  if (depth > 10) return out;
  if (typeof value === "string") out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out, depth + 1);
  else if (value && typeof value === "object") for (const v of Object.values(value)) strings(v, out, depth + 1);
  return out;
}
function decidePi(toolName, input, env) {
  if (toolName.startsWith(BROKER_TOOL_PREFIX) || toolName === "codemode") return allow;
  const withPath = (extra = {}) => input.path === void 0 ? extra : { ...extra, path: pathArg(input.path) };
  switch (toolName) {
    case "bash":
      return decide("Bash", { command: input.command }, env);
    case "powershell":
      return decide("PowerShell", { command: input.command }, env);
    case "read":
      return decide("Read", { file_path: pathArg(input.path) }, env);
    case "write":
      return decide("Write", { file_path: pathArg(input.path) }, env);
    case "edit":
      return decide("Edit", { file_path: pathArg(input.path) }, env);
    case "grep":
      return decide("Grep", withPath(), env);
    case "find":
      return decide("Glob", withPath({ pattern: input.pattern }), env);
    case "ls":
      return decide("Glob", withPath(), env);
  }
  for (const s of strings(input)) {
    const d = decide("Bash", { command: s }, env);
    if (!d.allow) return d;
  }
  return allow;
}
function piGuardEnv(env, pluginRoot, projectDir) {
  const userProfile = env.USERPROFILE || homedir();
  return {
    appData: env.APPDATA || win32.join(userProfile, "AppData", "Roaming"),
    localAppData: env.LOCALAPPDATA || win32.join(userProfile, "AppData", "Local"),
    userProfile,
    pluginRoot,
    projectDir,
    piAgentDir: env.PI_CODING_AGENT_DIR || win32.join(userProfile, ".pi", "agent")
  };
}
function packageRoot() {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..");
}
function bitwardenM365(pi) {
  const root = packageRoot();
  pi.registerMcpServer(MCP_SERVER_NAME, {
    command: "node",
    args: [join(root, "dist", "server.js")],
    exposure: "direct",
    description: "Microsoft 365 admin (Microsoft Graph, Exchange Online) using admin logins from Bitwarden. Reads run directly; every change needs the user to click Yes in a Windows dialog."
  });
  pi.on("tool_call", async (event, ctx) => {
    const env = piGuardEnv(process.env, root, ctx?.cwd || process.cwd());
    const d = decidePi(event.toolName, event.input ?? {}, env);
    return d.allow ? void 0 : { block: true, reason: d.reason };
  });
}
export {
  MCP_SERVER_NAME,
  decidePi,
  bitwardenM365 as default,
  piGuardEnv
};
