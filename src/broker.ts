import type { AuditLog } from './audit.js';
import { buildGraphUrl, isCmdletRead, isGraphRead, validateCmdlet, validateParameters, type GraphMethod } from './classify.js';
import type { BrokerConfig } from './config.js';
import { BrokerError } from './errors.js';
import { runCmdlet, type PsRunner } from './exo.js';
import { graphRequest } from './graph.js';
import type { Redactor } from './redact.js';
import { EXO_RESOURCE, graphResource } from './auth/resources.js';
import { SignInError } from './auth/signin.js';
import type { TokenManager } from './auth/tokens.js';
import type { Credential, Vault } from './vault/vault.js';
import type { ApprovalRequest } from './win/dialogs.js';

export interface BrokerDeps {
  vault: Pick<Vault, 'listTenants' | 'getCredential' | 'lock'>;
  tokens: Pick<TokenManager, 'getAccessToken' | 'drop'>;
  confirm: (r: ApprovalRequest) => Promise<boolean>;
  fetch: typeof fetch;
  exo: PsRunner;
  audit: Pick<AuditLog, 'write'>;
  redactor: Redactor;
  config: BrokerConfig;
}

const GRAPH_METHODS: readonly GraphMethod[] = ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'];
const API_VERSIONS = ['v1.0', 'beta'] as const;
const MAX_ACTION_BODY = 1500;
const MAX_ACTION = 4000;

/** Thrown internally when the user answers No; converted to the `denied` result. */
class Denied extends BrokerError {
  constructor() {
    super('denied', 'The user declined this change.');
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** PowerShell-style rendering of one parameter value, for the approval dialog only. */
function psValue(v: unknown): string {
  if (v === null) return '$null';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') {
    return v !== '' && /^[\w.@:/+=-]+$/.test(v) ? v : `'${v.replace(/'/g, "''")}'`;
  }
  return JSON.stringify(v);
}

function cmdletAction(cmdlet: string, parameters: Record<string, unknown>): string {
  const parts = [cmdlet];
  for (const [k, v] of Object.entries(parameters)) {
    parts.push(typeof v === 'boolean' ? `-${k}:$${v}` : `-${k} ${psValue(v)}`);
  }
  return truncate(parts.join(' '), MAX_ACTION);
}

function graphAction(method: GraphMethod, path: string, body: unknown): string {
  const head = `Graph ${method} ${truncate(path, MAX_ACTION)}`;
  if (body === undefined) return head;
  return `${head}\n${truncate(JSON.stringify(body, null, 2) ?? String(body), MAX_ACTION_BODY)}`;
}

/** Ties vault, sign-in, approval and executors together. Every method returns redacted JSON text. */
export class Broker {
  constructor(private readonly deps: BrokerDeps) {}

  listTenants(): Promise<string> {
    return this.run(undefined, async () => ({ tenants: await this.deps.vault.listTenants() }));
  }

  connect(tenant: string): Promise<string> {
    return this.run(tenant, async () => {
      const cred = await this.deps.vault.getCredential(tenant);
      const { upn } = await this.deps.tokens.getAccessToken(cred, graphResource(this.deps.config.graphScopes));
      this.deps.audit.write({ type: 'connect', tenant, detail: upn });
      return { tenant, account: upn };
    });
  }

  graphRequest(
    tenant: string,
    method: GraphMethod,
    path: string,
    body?: unknown,
    apiVersion: 'v1.0' | 'beta' = 'v1.0',
  ): Promise<string> {
    return this.run(tenant, async () => {
      if (!GRAPH_METHODS.includes(method)) {
        throw new BrokerError('invalid_method', `Invalid Graph method: expected one of ${GRAPH_METHODS.join(', ')}`);
      }
      if (!(API_VERSIONS as readonly string[]).includes(apiVersion)) {
        throw new BrokerError('invalid_path', 'Invalid Graph API version: expected v1.0 or beta');
      }
      buildGraphUrl(path, apiVersion);
      const cred = await this.deps.vault.getCredential(tenant);
      const { token, upn } = await this.deps.tokens.getAccessToken(cred, graphResource(this.deps.config.graphScopes));
      if (!isGraphRead(method)) await this.approve(tenant, cred, upn, graphAction(method, path, body), `${method} ${path}`);
      this.deps.audit.write({ type: 'call', tenant, detail: `${method} ${path}` });
      return graphRequest(this.deps.fetch, token, { method, path, body, apiVersion });
    });
  }

  exoCmdlet(tenant: string, cmdlet: string, parameters?: Record<string, unknown>): Promise<string> {
    return this.run(tenant, async () => {
      validateCmdlet(cmdlet);
      const params = validateParameters(parameters ?? {});
      const cred = await this.deps.vault.getCredential(tenant);
      const { token, upn } = await this.deps.tokens.getAccessToken(cred, EXO_RESOURCE);
      if (!isCmdletRead(cmdlet)) await this.approve(tenant, cred, upn, cmdletAction(cmdlet, params), cmdlet);
      this.deps.audit.write({ type: 'call', tenant, detail: cmdlet });
      const result = await runCmdlet(this.deps.exo, { token, upn, organization: cred.tenant, cmdlet, parameters: params });
      return { result };
    });
  }

  disconnect(tenant?: string): Promise<string> {
    return this.run(tenant, async () => {
      await this.deps.tokens.drop(tenant);
      return { disconnected: tenant ?? 'all' };
    });
  }

  lock(): Promise<string> {
    return this.run(undefined, async () => {
      await this.deps.vault.lock();
      return { locked: true };
    });
  }

  /** Shows the Yes/No dialog; `detail` (no bodies or parameter values) is what the audit log records. */
  private async approve(tenant: string, cred: Credential, account: string, action: string, detail: string): Promise<void> {
    const shownTenant = cred.tenant === tenant ? tenant : `${tenant} (${cred.tenant})`;
    const ok = await this.deps.confirm({ tenant: shownTenant, account, action: this.deps.redactor.scrub(action) });
    this.deps.audit.write({ type: ok ? 'approved' : 'denied', tenant, detail });
    if (!ok) throw new Denied();
  }

  private async run(tenant: string | undefined, fn: () => Promise<unknown>): Promise<string> {
    const { redactor } = this.deps;
    let value: unknown;
    try {
      value = await fn();
    } catch (e) {
      value = this.toError(tenant, e);
    }
    return redactor.scrub(JSON.stringify(redactor.scrubDeep(value)) ?? 'null');
  }

  private toError(tenant: string | undefined, e: unknown): Record<string, string> {
    const { redactor, audit } = this.deps;
    if (e instanceof SignInError) {
      audit.write({ type: 'signin_failed', ...(tenant !== undefined ? { tenant } : {}), detail: e.category });
      return { error: e.code, message: redactor.scrub(e.message), category: e.category };
    }
    if (e instanceof BrokerError) return { error: e.code, message: redactor.scrub(e.message) };
    const stack = e instanceof Error ? (e.stack ?? `${e.name}: ${e.message}`) : String(e);
    audit.write({ type: 'error', ...(tenant !== undefined ? { tenant } : {}), detail: redactor.scrub(stack) });
    return { error: 'internal', message: 'Unexpected broker error (see audit log).' };
  }
}
