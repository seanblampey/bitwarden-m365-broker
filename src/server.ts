import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AuditLog } from './audit.js';
import { defaultPsRunner as adminPsRunner } from './admin/runner.js';
import { SERVICES } from './admin/services.js';
import { Broker, makeConsentApprover } from './broker.js';
import { defaultPaths, loadConfig } from './config.js';
import { BrokerError } from './errors.js';
import { Redactor } from './redact.js';
import { SignInBrowser } from './auth/signin.js';
import { TokenManager } from './auth/tokens.js';
import { BwClient, nodeRunner } from './vault/bw.js';
import { Vault } from './vault/vault.js';
import { confirmAction, promptPassword } from './win/dialogs.js';

const APPROVAL = 'Anything other than a read opens a Yes/No dialog and runs only if the user approves.';

function result(text: string) {
  let isError = false;
  try {
    const v: unknown = JSON.parse(text);
    isError = !!v && typeof v === 'object' && 'error' in v;
  } catch {
    /* not an error envelope */
  }
  return { content: [{ type: 'text' as const, text }], ...(isError ? { isError: true } : {}) };
}

export function createServer(broker: Broker): McpServer {
  const server = new McpServer({ name: 'bitwarden-m365', version: '0.1.0' });
  const tenant = z.string().describe('Tenant alias (a name returned by list_tenants)');

  server.registerTool(
    'list_tenants',
    { description: 'List the tenant aliases the user has allowed (unlocks Bitwarden if needed); returns no secrets.', inputSchema: {} },
    async () => result(await broker.listTenants()),
  );
  server.registerTool(
    'connect',
    { description: 'Sign in to a tenant\'s Microsoft Graph with its stored admin login and return the signed-in account. Optional: graph_request and admin_cmdlet sign in by themselves.', inputSchema: { tenant } },
    async (a) => result(await broker.connect(a.tenant)),
  );
  server.registerTool(
    'graph_request',
    {
      description: `Call Microsoft Graph (https://graph.microsoft.com) for a tenant; GET is a read. Always use $select and $top (and $filter) to keep results small. ${APPROVAL}`,
      inputSchema: {
        tenant,
        method: z.enum(['GET', 'POST', 'PATCH', 'PUT', 'DELETE']),
        path: z.string().describe('Path after the API version, starting with "/", e.g. /users?$top=5'),
        body: z.any().optional().describe('JSON request body'),
        api_version: z.enum(['v1.0', 'beta']).default('v1.0'),
      },
    },
    async (a) => result(await broker.graphRequest(a.tenant, a.method, a.path, a.body, a.api_version)),
  );
  server.registerTool(
    'admin_cmdlet',
    {
      description:
        'Run one PowerShell admin cmdlet for a tenant: service "exchange" (Exchange Online), "compliance" (Security & Compliance / Purview), '
        + '"teams" (Microsoft Teams) or "sharepoint" (PnP PowerShell). Get- cmdlets are reads. '
        + `Always pass select (the properties you need) and first (how many items) to keep results small. ${APPROVAL}`,
      inputSchema: {
        tenant,
        service: z.enum(SERVICES),
        cmdlet: z.string().describe('Cmdlet name, e.g. Get-Mailbox, Get-RetentionCompliancePolicy, Get-CsTeamsMeetingPolicy, Get-PnPTenantSite'),
        parameters: z.record(z.string(), z.unknown()).optional().describe('Named parameters, e.g. {"Identity":"user@x.com"}'),
        select: z.array(z.string()).optional().describe('Property names to return, e.g. ["DisplayName","PrimarySmtpAddress"]; dotted paths allowed'),
        first: z.number().int().min(1).max(1000).optional().describe('Return at most this many items (default 200); the total count is still reported'),
        site: z.string().optional().describe('sharepoint only: site URL to work in, e.g. https://contoso.sharepoint.com/sites/Finance; default is the admin site'),
      },
    },
    async (a) => result(await broker.adminCmdlet(a.tenant, a.service, a.cmdlet, a.parameters, { select: a.select, first: a.first, site: a.site })),
  );
  server.registerTool(
    'disconnect',
    { description: 'Forget the cached Microsoft sign-in for one tenant, or for all tenants if none is given.', inputSchema: { tenant: tenant.optional() } },
    async (a) => result(await broker.disconnect(a.tenant)),
  );
  server.registerTool(
    'lock',
    { description: 'Lock the Bitwarden vault now; the next call will ask the user for the master password again.', inputSchema: {} },
    async () => result(await broker.lock()),
  );
  return server;
}

export async function main(): Promise<void> {
  const paths = defaultPaths();
  const config = loadConfig(paths.configFile);
  const redactor = new Redactor();
  const audit = new AuditLog(paths.auditFile, redactor);
  const vault = new Vault({
    bw: new BwClient(nodeRunner),
    promptPassword: () => promptPassword(),
    redactor,
    audit,
    folderName: config.folderName,
    idleMs: config.idleMinutes * 60_000,
  });
  const tokens = new TokenManager({
    authority: 'https://login.microsoftonline.com',
    getBrowser: () => SignInBrowser.launch({ channel: 'msedge', headless: !config.showSignInWindow }),
    fetch: globalThis.fetch,
    redactor,
    // Microsoft wants an app approved for the tenant: ask the user, never decide here.
    approveConsent: makeConsentApprover({ confirm: (r) => confirmAction(r), audit, redactor }),
    audit,
  });
  const broker = new Broker({
    vault,
    tokens,
    confirm: (r) => confirmAction(r),
    fetch: globalThis.fetch,
    ps: adminPsRunner(),
    audit,
    redactor,
    config,
  });

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    await tokens.drop().catch(() => undefined);
    await vault.lock().catch(() => undefined);
    process.exit(0);
  };
  process.stdin.on('close', () => void shutdown());
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());

  await createServer(broker).connect(new StdioServerTransport());
}

/** True when `metaUrl` is the script node was started with (symlinks resolved; case-insensitive on Windows). */
export function isEntryPoint(
  metaUrl: string,
  argv1: string | undefined,
  platform: NodeJS.Platform = process.platform,
  realpath: (p: string) => string = (p) => realpathSync(p),
): boolean {
  if (!argv1) return false;
  let self: string;
  let entry: string;
  try {
    self = realpath(fileURLToPath(metaUrl));
    entry = realpath(argv1);
  } catch {
    return false;
  }
  return platform === 'win32' ? self.toLowerCase() === entry.toLowerCase() : self === entry;
}

if (isEntryPoint(import.meta.url, process.argv[1])) {
  main().catch((e) => {
    // BrokerError messages are secret-free by contract; anything else is not echoed.
    process.stderr.write(`claude-bw-broker: failed to start${e instanceof BrokerError ? `: ${e.message}` : ''}\n`);
    process.exit(1);
  });
}
