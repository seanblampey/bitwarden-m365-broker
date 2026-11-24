import type { AuditLog } from './audit.js';
import { buildGraphUrl, isCmdletRead, isGraphRead, validateCmdlet, validateParameters, type GraphMethod } from './classify.js';
import type { BrokerConfig } from './config.js';
import { BrokerError } from './errors.js';
import { assertNoForbiddenCommon, runCmdlet, type PsRunner } from './exo.js';
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
/** Longest action text the approval box shows in full; confirm.ps1 refuses anything much longer. */
export const MAX_ACTION = 1500;

/** Thrown internally when the user answers No; converted to the `denied` result. */
class Denied extends BrokerError {
  constructor() {
    super('denied', 'The user declined this change.');
  }
}

// C0/C1 controls, Arabic letter mark, Mongolian vowel separator, zero-width and bidi marks,
// line/paragraph separators, bidi embeddings/overrides/isolates and other invisible format chars, BOM.
const FORMAT_CHARS = '\\u007f-\\u009f\\u061C\\u180E\\u200B-\\u200F\\u2028-\\u202E\\u2060-\\u206F\\uFEFF';
const UNSAFE_CHARS = new RegExp(`[\\u0000-\\u001f${FORMAT_CHARS}]`, 'g');
/** JSON.stringify already escapes C0 controls inside strings; its raw newlines are layout. */
const UNSAFE_IN_JSON = new RegExp(`[${FORMAT_CHARS}]`, 'g');
const NAMED_ESCAPES: Record<string, string> = { '\n': '\\n', '\r': '\\r', '\t': '\\t' };

const hexEscape = (c: string) => NAMED_ESCAPES[c] ?? `\\u${c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0')}`;

/** Renders characters that could fake lines or reorder text as visible escapes (`\n`, `\u202E`). */
export function escapeForDisplay(s: string): string {
  return s.replace(UNSAFE_CHARS, hexEscape);
}

/** Same for JSON.stringify output, keeping its layout newlines. */
function escapeJsonForDisplay(json: string): string {
  return json.replace(UNSAFE_IN_JSON, hexEscape);
}

/** PowerShell-style rendering of one parameter value, for the approval dialog only. */
function psValue(v: unknown): string {
  if (v === null) return '$null';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') {
    return v !== '' && /^[\w.@:/+=-]+$/.test(v) ? v : `'${escapeForDisplay(v).replace(/'/g, "''")}'`;
  }
  // JSON escapes control characters itself; bidi/format characters still need escaping.
  return escapeJsonForDisplay(JSON.stringify(v) ?? String(v));
}

function cmdletAction(cmdlet: string, parameters: Record<string, unknown>): string {
  const parts = [escapeForDisplay(cmdlet)];
  for (const [k, v] of Object.entries(parameters)) {
    const name = escapeForDisplay(k);
    parts.push(typeof v === 'boolean' ? `-${name}:$${v}` : `-${name} ${psValue(v)}`);
  }
  return parts.join(' ');
}

function graphAction(method: GraphMethod, path: string, body: unknown): string {
  const head = `Graph ${method} ${escapeForDisplay(path)}`;
  if (body === undefined) return head;
  return `${head}\n${escapeJsonForDisplay(JSON.stringify(body, null, 2) ?? String(body))}`;
}

/** The approval box must show the whole action, so anything longer is refused, never truncated. */
function assertShowable(action: string): void {
  if (action.length > MAX_ACTION) {
    throw new BrokerError(
      'too_long_to_approve',
      'This change is too large to show in the approval box. Split it into smaller requests.',
    );
  }
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
      const action = isGraphRead(method) ? undefined : graphAction(method, path, body);
      if (action !== undefined) assertShowable(action);
      const cred = await this.deps.vault.getCredential(tenant);
      const { token, upn } = await this.deps.tokens.getAccessToken(cred, graphResource(this.deps.config.graphScopes));
      // Query strings can carry values ($filter=...), so the audit log records the path only.
      const detail = `${method} ${path.split('?')[0]}`;
      if (action !== undefined) await this.approve(tenant, cred, upn, action, detail);
      this.deps.audit.write({ type: 'call', tenant, detail });
      return graphRequest(this.deps.fetch, token, { method, path, body, apiVersion });
    });
  }

  exoCmdlet(tenant: string, cmdlet: string, parameters?: Record<string, unknown>): Promise<string> {
    return this.run(tenant, async () => {
      validateCmdlet(cmdlet);
      const params = validateParameters(parameters ?? {});
      assertNoForbiddenCommon(params);
      const action = isCmdletRead(cmdlet) ? undefined : cmdletAction(cmdlet, params);
      if (action !== undefined) assertShowable(action);
      const cred = await this.deps.vault.getCredential(tenant);
      const { token, upn } = await this.deps.tokens.getAccessToken(cred, EXO_RESOURCE);
      if (action !== undefined) await this.approve(tenant, cred, upn, action, cmdlet);
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
    const shownTenant = escapeForDisplay(cred.tenant === tenant ? tenant : `${tenant} (${cred.tenant})`);
    // Redaction can lengthen a short secret to "[REDACTED]", so the length is checked again.
    const shown = this.deps.redactor.scrub(action);
    assertShowable(shown);
    let ok: boolean;
    try {
      ok = await this.deps.confirm({ tenant: shownTenant, account: escapeForDisplay(account), action: shown });
    } catch (e) {
      this.deps.audit.write({ type: 'error', tenant, detail: `approval dialog failed: ${detail}` });
      throw e;
    }
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
      audit.write({ type: 'signin_failed', ...(tenant !== undefined ? { tenant } : {}), detail: e.detail ? `${e.category}: ${e.detail}` : e.category });
      return { error: e.code, message: redactor.scrub(e.message), category: e.category };
    }
    if (e instanceof BrokerError) return { error: e.code, message: redactor.scrub(e.message) };
    const stack = e instanceof Error ? (e.stack ?? `${e.name}: ${e.message}`) : String(e);
    audit.write({ type: 'error', ...(tenant !== undefined ? { tenant } : {}), detail: redactor.scrub(stack) });
    return { error: 'internal', message: 'Unexpected broker error (see audit log).' };
  }
}
