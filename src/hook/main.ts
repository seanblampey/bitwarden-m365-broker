import { decide, type GuardEnv } from './guard.js';

function emitDeny(reason: string): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    }) + '\n',
  );
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks).toString('utf8');
}

async function run(): Promise<void> {
  const input: unknown = JSON.parse(await readStdin());
  if (typeof input !== 'object' || input === null || Array.isArray(input)) throw new Error('bad input');
  const rec = input as Record<string, unknown>;
  const toolName = rec['tool_name'];
  const toolInput = rec['tool_input'];
  if (typeof toolName !== 'string' || typeof toolInput !== 'object' || toolInput === null || Array.isArray(toolInput)) {
    throw new Error('bad input');
  }
  const cwd = typeof rec['cwd'] === 'string' ? rec['cwd'] : '';
  const e = process.env;
  const env: GuardEnv = {
    appData: e['APPDATA'] ?? '',
    localAppData: e['LOCALAPPDATA'] ?? '',
    userProfile: e['USERPROFILE'] ?? '',
    pluginRoot: e['CLAUDE_PLUGIN_ROOT'] ?? '',
    projectDir: e['CLAUDE_PROJECT_DIR'] || cwd,
  };
  const d = decide(toolName, toolInput as Record<string, unknown>, env);
  if (!d.allow) emitDeny(d.reason);
}

run().catch(() => emitDeny('Blocked: guard hook could not evaluate this tool call (fail closed).'));
