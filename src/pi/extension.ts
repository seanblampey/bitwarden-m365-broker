/**
 * Pi (pi.dev coding agent) extension: the same protection the Claude Code plugin gives.
 *  - registers the broker as an MCP server, so its six tools reach the model;
 *  - checks every tool call before it runs, with the same rules as the Claude Code hook,
 *    plus Pi's own config folders, so the model cannot read Bitwarden data, run `bw`,
 *    or switch this protection off.
 * A handler that throws makes Pi refuse the call ("Extension failed, blocking execution"),
 * so a failure here fails closed.
 */
import { homedir } from 'node:os';
import { dirname, join, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide, type Decision, type GuardEnv } from '../hook/guard.js';

export const MCP_SERVER_NAME = 'bitwarden-m365';
/** Pi names MCP tools mcp__<server>__<tool>, with `-` replaced by `_`. */
const BROKER_TOOL_PREFIX = 'mcp__bitwarden_m365__';

/** The parts of Pi's extension API this extension uses. */
export interface PiToolCallEvent {
  toolName: string;
  input: Record<string, unknown>;
}
export interface PiContext {
  cwd?: string;
}
export interface PiApi {
  on(
    event: 'tool_call',
    handler: (event: PiToolCallEvent, ctx: PiContext) => Promise<{ block: true; reason: string } | undefined>,
  ): void;
  registerMcpServer(name: string, config: Record<string, unknown>): void;
}

const allow: Decision = { allow: true };

/** Pi's built-in tools strip a leading @ from paths; do the same before checking. */
const pathArg = (v: unknown): unknown => (typeof v === 'string' ? v.replace(/^@/, '') : v);

function strings(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 10) return out;
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) for (const v of value) strings(v, out, depth + 1);
  else if (value && typeof value === 'object') for (const v of Object.values(value)) strings(v, out, depth + 1);
  return out;
}

/** Map a Pi tool call onto the Claude Code guard's rules. */
export function decidePi(toolName: string, input: Record<string, unknown>, env: GuardEnv): Decision {
  // The broker's own tools, and codemode (each tool a codemode script calls is checked on its own).
  if (toolName.startsWith(BROKER_TOOL_PREFIX) || toolName === 'codemode') return allow;
  const withPath = (extra: Record<string, unknown> = {}) =>
    input.path === undefined ? extra : { ...extra, path: pathArg(input.path) };
  switch (toolName) {
    case 'bash':
      return decide('Bash', { command: input.command }, env);
    case 'powershell':
      return decide('PowerShell', { command: input.command }, env);
    case 'read':
      return decide('Read', { file_path: pathArg(input.path) }, env);
    case 'write':
      return decide('Write', { file_path: pathArg(input.path) }, env);
    case 'edit':
      return decide('Edit', { file_path: pathArg(input.path) }, env);
    case 'grep':
      return decide('Grep', withPath(), env);
    case 'find':
      return decide('Glob', withPath({ pattern: input.pattern }), env);
    case 'ls':
      return decide('Glob', withPath(), env);
  }
  // Any other tool (another extension or MCP server): check every text value with the shell rules.
  // This over-blocks rather than letting an unknown tool reach protected files.
  for (const s of strings(input)) {
    const d = decide('Bash', { command: s }, env);
    if (!d.allow) return d;
  }
  return allow;
}

export function piGuardEnv(env: NodeJS.ProcessEnv, pluginRoot: string, projectDir: string): GuardEnv {
  const userProfile = env.USERPROFILE || homedir();
  return {
    appData: env.APPDATA || win32.join(userProfile, 'AppData', 'Roaming'),
    localAppData: env.LOCALAPPDATA || win32.join(userProfile, 'AppData', 'Local'),
    userProfile,
    pluginRoot,
    projectDir,
    piAgentDir: env.PI_CODING_AGENT_DIR || win32.join(userProfile, '.pi', 'agent'),
  };
}

/** Package root: this file is dist/pi/extension.js. */
function packageRoot(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '..', '..');
}

export default function bitwardenM365(pi: PiApi): void {
  const root = packageRoot();
  pi.registerMcpServer(MCP_SERVER_NAME, {
    command: 'node',
    args: [join(root, 'dist', 'server.js')],
    exposure: 'direct',
    description:
      'Microsoft 365 admin (Microsoft Graph, Exchange Online) using admin logins from Bitwarden. Reads run directly; every change needs the user to click Yes in a Windows dialog.',
  });
  pi.on('tool_call', async (event, ctx) => {
    const env = piGuardEnv(process.env, root, ctx?.cwd || process.cwd());
    const d = decidePi(event.toolName, event.input ?? {}, env);
    return d.allow ? undefined : { block: true, reason: d.reason };
  });
}
