import type { AuditLog } from './audit.js';
import { assertNoForbiddenCommon, runAdminCmdlet, type PsRunner } from './admin/runner.js';
import { checkService, planFor } from './admin/services.js';
import {
  buildGraphUrl, isCmdletRead, isGraphRead, validateCmdlet, validateFirst, validateParameters, validateSelect, type GraphMethod,
} from './classify.js';
import type { BrokerConfig } from './config.js';
import { BrokerError } from './errors.js';
import { graphRequest } from './graph.js';
import type { Redactor } from './redact.js';
import { capResult } from './shape.js';
import { graphResource } from './auth/resources.js';
import { SignInError } from './auth/signin.js';
import type { ConsentRequest, TokenManager } from './auth/tokens.js';
import type { Credential, Vault } from './vault/vault.js';
import type { ApprovalRequest } from './win/dialogs.js';

export interface BrokerDeps {
  vault: Pick<Vault, 'listTenants' | 'getCredential' | 'lock'>;
  tokens: Pick<TokenManager, 'getAccessToken' | 'drop'>;
  confirm: (r: ApprovalRequest) => Promise<boolean>;
  fetch: typeof fetch;
  /** Runs the admin PowerShell script (Windows PowerShell or PowerShell 7). */
  ps: PsRunner;
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

/** Options of admin_cmdlet that shape the result or pick the SharePoint site. Validated by the broker. */
export interface AdminCmdletOptions {
  select?: unknown;
  first?: unknown;
  site?: unknown;
}

function isCutList(v: unknown): v is { truncated: true; totalItems: number; shownItems: number; note: string; items: unknown[] } {
  return !!v && typeof v === 'object' && (v as { truncated?: unknown }).truncated === true && Array.isArray((v as { items?: unknown }).items);
}

/**
 * Builds the question asked when Microsoft wants an app approved for a tenant: a Yes/No dialog naming
 * the app, the tenant and every permission. Anything but an explicit Yes (No, timeout, a request too long
 * to show in full) is a No. If the dialog cannot be shown it throws, so that is not mistaken for an answer.
 */
export function makeConsentApprover(deps: {
  confirm: (r: ApprovalRequest) => Promise<boolean>;
  audit: Pick<AuditLog, 'write'>;
  redactor: Redactor;
}): (r: ConsentRequest) => Promise<boolean> {
  return async (r) => {
    const tenant = escapeForDisplay(r.tenant === r.alias ? r.alias : `${r.alias} (${r.tenant})`);
    const action = deps.redactor.scrub(
      `Approve the Microsoft app "${escapeForDisplay(r.appName)}" for the whole organisation (admin consent), `
        + 'so the broker can sign in with it. It stays approved in this tenant until an admin removes it.\n'
        + `Permissions:\n${r.scopes.map((s) => `- ${escapeForDisplay(s)}`).join('\n')}`,
    );
    deps.audit.write({ type: 'consent_requested', tenant: r.alias, detail: r.appName });
    let ok = false;
    if (action.length <= MAX_ACTION) {
      try {
        ok = await deps.confirm({ tenant, account: escapeForDisplay(r.account), action });
      } catch (e) {
        // Not an answer: the box could not be shown. The caller may ask again later.
        deps.audit.write({ type: 'error', tenant: r.alias, detail: `consent dialog failed: ${r.appName}` });
        throw e;
      }
    }
    deps.audit.write({ type: ok ? 'consent_approved' : 'consent_denied', tenant: r.alias, detail: r.appName });
    return ok;
  };
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
      const res = await graphRequest(this.deps.fetch, token, { method, path, body, apiVersion });
      return { status: res.status, body: capResult(res.body) };
    });
  }

  /** Runs one cmdlet of one admin service (exchange, compliance, teams, sharepoint). */
  adminCmdlet(
    tenant: string,
    service: string,
    cmdlet: string,
    parameters?: Record<string, unknown>,
    opts: AdminCmdletOptions = {},
  ): Promise<string> {
    return this.run(tenant, async () => {
      // Everything that can be checked without the vault is checked first.
      const checked = checkService(service, opts.site ?? undefined);
      validateCmdlet(cmdlet);
      const params = validateParameters(parameters ?? {});
      assertNoForbiddenCommon(params);
      // Some models send null for options they are not using.
      const select = validateSelect(opts.select ?? undefined);
      const first = validateFirst(opts.first ?? undefined);
      const where = checked.site ? `${checked.service} ${checked.site}` : checked.service;
      const action = isCmdletRead(cmdlet, params) ? undefined : `[${escapeForDisplay(where)}] ${cmdletAction(cmdlet, params)}`;
      if (action !== undefined) assertShowable(action);

      const cred = await this.deps.vault.getCredential(tenant);
      // Needs the Bitwarden item: a SharePoint site must be on this tenant's own host.
      const plan = planFor(checked.service, cred, checked.site);
      const { token, upn } = await this.deps.tokens.getAccessToken(cred, plan.primary);
      const graphToken = plan.graph ? (await this.deps.tokens.getAccessToken(cred, plan.graph)).token : undefined;
      const detail = `${where} ${cmdlet}`;
      if (action !== undefined) await this.approve(tenant, cred, upn, action, detail);
      this.deps.audit.write({ type: 'call', tenant, detail });
      const out = await runAdminCmdlet(this.deps.ps, {
        service: plan.service,
        shell: plan.shell,
        token,
        ...(graphToken !== undefined ? { graphToken } : {}),
        upn,
        organization: cred.tenant,
        ...(plan.url !== undefined ? { url: plan.url } : {}),
        cmdlet,
        parameters: params,
        ...(select ? { select } : {}),
        ...(first !== undefined ? { first } : {}),
      });
      const capped = capResult(out.result, { total: out.total });
      const warnings = out.warnings ? { warnings: out.warnings } : {};
      if (isCutList(capped)) {
        return { result: capped.items, truncated: true, totalItems: capped.totalItems, shownItems: capped.shownItems, note: capped.note, ...warnings };
      }
      return { result: capped, ...(out.note ? { note: out.note } : {}), ...warnings };
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
