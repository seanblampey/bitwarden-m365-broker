function emitDeny(reason: string, failure: boolean): void {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    }) + '\n',
  );
  if (failure) {
    // exit code 2 is the blocking-error code in Claude Code; exit 1 would fail open
    process.stderr.write(reason + '\n');
    process.exitCode = 2;
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks).toString('utf8');
}

async function run(): Promise<void> {
  // dynamic import so a load failure of the guard is caught below and fails closed
  const { decide } = await import('./guard.js');
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
  const d = decide(toolName, toolInput as Record<string, unknown>, {
    appData: e['APPDATA'] ?? '',
    localAppData: e['LOCALAPPDATA'] ?? '',
    userProfile: e['USERPROFILE'] ?? '',
    pluginRoot: e['CLAUDE_PLUGIN_ROOT'] ?? '',
    projectDir: e['CLAUDE_PROJECT_DIR'] || cwd,
  });
  if (!d.allow) emitDeny(d.reason, false);
}

run().catch(() => emitDeny('Blocked: guard hook could not evaluate this tool call (fail closed).', true));
