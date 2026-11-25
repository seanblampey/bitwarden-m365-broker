# Admin Portals and One-Click Consent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One `admin_cmdlet` tool that runs Exchange, Security & Compliance, Teams and SharePoint (PnP) cmdlets with the Bitwarden login, efficient output, and a one-click consent dialog.

**Architecture:** A per-service table (`src/admin/services.ts`) names each service's module, shell, sign-in app and tokens. One PowerShell script connects with broker-supplied tokens and runs one cmdlet after a module-origin check. `TokenManager` gets second tokens for the same app by refresh-token exchange, and on `needs_consent` asks the user (Yes/No) before granting admin consent in the sign-in browser.

**Tech Stack:** unchanged (TypeScript, MCP SDK, Playwright, vitest, PowerShell 5.1 and 7.4).

**Spec:** `docs/superpowers/specs/2026-11-25-admin-portals-design.md`

## Global Constraints

- No token, password or TOTP value in a tool result, error, audit line or command line. Tokens reach PowerShell on stdin only.
- Reads run without approval only when the cmdlet verb is `Get` and no parameter names a local file (`Out`, `OutFile`, `OutputFile`, `OutputPath`, `Path`, `LiteralPath`, `FilePath`, `Folder`); everything else needs the Yes/No dialog.
- Denied for every service: verbs `Connect`, `Disconnect` (plus the existing `Invoke`, `Start`, `Stop`, `Import`, `Export`, `Out`), names matching `AccessToken|Token$|Credential|Secret|Password|Certificate` (case-insensitive), `Get-PnPConnection`, `Get-PnPFile`.
- Module origin: exchange and compliance `tmpEXO_*` or `ExchangeOnlineManagement`; teams `MicrosoftTeams` or `Microsoft.Teams.*`; sharepoint `PnP.PowerShell`.
- Minimum versions: ExchangeOnlineManagement 3.1.0 (exchange) / 3.2.0 (compliance); MicrosoftTeams 6.0.0; PnP.PowerShell 3.0.0 on PowerShell 7.4.
- The assistant never installs modules; a missing or old module is error `module_missing` with the install command and shell.
- Output: at most 200 items serialised per cmdlet call unless `first` says otherwise (1–1000); results capped at 30,000 characters with `truncated`, `totalItems`, `shownItems` and a note.
- Consent is only ever granted after the user clicks Yes, for the client ID and scopes in `resources.ts`/config.
- Error code `exo_failed` becomes `cmdlet_failed`; tool `exo_cmdlet` becomes `admin_cmdlet`.

## Review Focus

1. A `Get-` cmdlet that returns or mints a secret (`Get-PnPAccessToken`, `Get-PnPStoredCredential`) — refused before anything runs. Test in Task 1.
2. SharePoint `site` on another host (`https://evil.example/`, `https://other.sharepoint.com`) — refused, so a token never goes to a host it wasn't issued for. Test in Task 2.
3. Consent page reached but the user clicks No, or the dialog fails — Accept is never clicked; the manual steps are returned. Tests in Tasks 5 and 6.
4. Huge result (10,000 items) — the model gets the first items, the true total and a hint, not 2 MB of JSON. Tests in Tasks 3 and 4.
5. PowerShell 7 or a module missing — a clear `module_missing` with the exact install command, not a generic failure. Test in Task 4.

---

## File Structure

```
src/classify.ts            + deny rules, isCmdletRead(name, params), validateSelect/First
src/shape.ts               capResult(): size cap with whole-item truncation
src/admin/services.ts      Service table, resources per service, SharePoint host rules
src/admin/runner.ts        PsRunner (shell-aware), runAdminCmdlet(), envelope parsing   (replaces src/exo.ts)
src/admin/run-admin-cmdlet.ps1   connect + origin check + run + shape                    (replaces src/exo/run-cmdlet.ps1)
src/auth/resources.ts      Resource gains appName, connectHint; new resources
src/auth/tokens.ts         per-alias cache, sibling refresh exchange, consent flow
src/auth/signin.ts         grantConsent(), consent_not_allowed, generic consentHelp
src/vault/vault.ts         optional `sharepoint` field on Credential
src/broker.ts              adminCmdlet(), consent approver, graph cap
src/server.ts              admin_cmdlet tool, wiring
skills/…/SKILL.md, README.md
```

### Task 1: Cmdlet rules (`src/classify.ts`)

**Produces:** `validateCmdlet(name)` (extended denies), `isCmdletRead(name: string, parameters?: Record<string, unknown>): boolean`, `validateSelect(v: unknown): string[] | undefined` (names `^[A-Za-z][A-Za-z0-9_.]*$`, max 50), `validateFirst(v: unknown): number | undefined` (integer 1–1000), both throwing `BrokerError('invalid_parameters')`.

- [ ] Tests in `tests/classify.test.ts`: each of `Connect-PnPOnline`, `Disconnect-ExchangeOnline`, `Get-PnPAccessToken`, `Get-PnPGraphAccessToken`, `Request-PnPAccessToken`, `Get-PnPStoredCredential`, `Get-PnPConnection`, `Get-PnPFile`, `Get-PnPAzureCertificate` throws `invalid_cmdlet`; `Get-PnPTenantSite`, `Get-CsTeamsMeetingPolicy`, `Get-RetentionCompliancePolicy`, `Set-PnPTenant` pass; `isCmdletRead('Get-PnPSiteTemplate', { Out: 'c:\\x.xml' })` is false, `isCmdletRead('Get-Mailbox', { Identity: 'a' })` true, `isCmdletRead('Set-Mailbox', {})` false; select/first bounds.
- [ ] Run, fail, implement, pass, commit `feat: cmdlet rules for all admin services`.

### Task 2: Service table (`src/admin/services.ts`, `src/auth/resources.ts`, `src/vault/vault.ts`)

**Produces:**
- `Resource { key: string; clientId: string; redirectUri: string; scopes: string[]; appName: string; connectHint?: string }`.
- `type Service = 'exchange' | 'compliance' | 'teams' | 'sharepoint'`; `SERVICES: readonly Service[]`.
- `interface ServiceTokens { primary: Resource; graph?: Resource }`.
- `interface ServicePlan { service: Service; shell: 'powershell' | 'pwsh'; tokens: ServiceTokens; url?: string }`.
- `planFor(service: string, cred: Credential, site?: string): ServicePlan` — throws `invalid_parameters` (unknown service, bad site, site on a non-sharepoint service) or `item_incomplete` (no SharePoint name).
- `sharePointName(cred: Credential): string`; `Credential.sharepoint?: string` read from an optional custom field `sharepoint` (`contoso` or `contoso.sharepoint.com`).
- Exact values: the table in the spec. Teams Graph scopes `https://graph.microsoft.com/.default`; Teams API scope `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation`; SharePoint redirect `https://oauth.spops.microsoft.com/`; every new resource also requests `offline_access openid profile`.
- SharePoint hosts allowed for `site`: `<name>.sharepoint.com`, `<name>-admin.sharepoint.com`, `<name>-my.sharepoint.com`; https only; no credentials, query or fragment. Without `site`: `https://<name>-admin.sharepoint.com`. Resource key `spo:<host>`, scope `https://<host>/.default`.

- [ ] Tests `tests/services.test.ts` (plan per service, key/scope/shell values, site on other hosts refused incl. `https://contoso.sharepoint.com.evil.example/`, name from `contoso.onmicrosoft.com`, from the field, and `item_incomplete` for a custom-domain tenant without the field) and a vault test for the `sharepoint` field.
- [ ] Fail, implement, pass, commit `feat: service table and sharepoint host rules`.

### Task 3: Output cap (`src/shape.ts`)

**Produces:** `capResult(value: unknown, opts?: { maxChars?: number; total?: number }): unknown` — default 30,000. Arrays and `{ value: [...] }` keep whole items; `totalItems` = `opts.total` ?? `@odata.count` ?? array length; other values over the cap become `{ truncated: true, note, text }`. Under the cap and `total` not above the item count: returned unchanged.

- [ ] Tests `tests/shape.test.ts`: small values unchanged; 10,000-item array → `truncated`, `totalItems: 10000`, `shownItems` < 10000, JSON length ≤ 31,000; Graph shape keeps `@odata.nextLink`; `total: 500` with 200 items → truncated with `totalItems: 500`; long string cut.
- [ ] Fail, implement, pass, commit `feat: cap large results with totals`.

### Task 4: Runner and script (`src/admin/runner.ts`, `src/admin/run-admin-cmdlet.ps1`; delete `src/exo.ts`, `src/exo/`)

**Produces:**
- `type PsRunner = (shell: 'powershell' | 'pwsh', stdin: string) => Promise<{ code: number; stdout: string; stderr: string }>`; `defaultPsRunner(): PsRunner` (5-minute kill timer; `pwsh.exe` not found → `BrokerError('module_missing', 'PowerShell 7 (pwsh) is not installed. Install it yourself: winget install Microsoft.PowerShell')`).
- `interface AdminCmdletArgs { service: Service; shell: 'powershell' | 'pwsh'; token: string; graphToken?: string; upn: string; organization: string; url?: string; cmdlet: string; parameters: Record<string, unknown>; select?: string[]; first?: number }`.
- `runAdminCmdlet(run: PsRunner, args: AdminCmdletArgs): Promise<{ result: unknown; total?: number }>`; envelope `{ ok, result?, total?, error?, code? }`; `code: 'module_missing'` → `BrokerError('module_missing', error)`; other failures `cmdlet_failed` (scrubbed, ≤1000 chars); `assertNoForbiddenCommon` moves here.
- Script: works in 5.1 and 7; per-service module check, connect, origin check, forced `ErrorAction Stop`, `Confirm:$false` on non-Get, `Force` on non-Get sharepoint cmdlets that have it; collects all results, `total = count`, then `Select-Object -First <first or 200> [-Property select]`; `ConvertTo-Json -Depth 4 -Compress`; disconnects in `finally`.

- [ ] Tests `tests/runner.test.ts` (rename of `tests/exo.test.ts`): stdin carries tokens and never args; shell passed through; `module_missing` mapping; token scrubbed from errors; forbidden common params; static checks that the script contains each connect command, each origin pattern, the version floors and `-First`.
- [ ] Fail, implement, pass, commit `feat: admin cmdlet runner for four services`.

### Task 5: Sign-in consent (`src/auth/signin.ts`, fake login site)

**Produces:**
- Category `consent_not_allowed`; `needs_consent` wording no longer says "never accepts".
- `consentHelp(authority, tenant, resource)`: admin-consent link for the resource's non-OIDC scopes for every resource, plus `Connect-MgGraph …` for `graph`, plus `resource.connectHint` when set.
- `SignInBrowser.grantConsent(p: SignInParams): Promise<void>` — opens `/<tenant>/v2.0/adminconsent?client_id&scope&redirect_uri&state`, drives sign-in pages as usual, clicks Accept (`#idSIButton9`) only on a consent page on the authority host, succeeds on redirect with `admin_consent=True` and matching state; `error` → `SignInError` (`AADSTS90094`/"Need admin approval" → `consent_not_allowed`).

- [ ] Tests in `tests/signin.test.ts` against the fake site (new `/v2.0/adminconsent` route recording accept posts; option `adminOnly`): grantConsent succeeds and the next authorize returns a code; authorize alone never posts accept; `consent_not_allowed`; wrong state → `page_changed`.
- [ ] Fail, implement, pass, commit `feat: grant admin consent in the sign-in browser on request`.

### Task 6: Token manager (`src/auth/tokens.ts`)

**Produces:** `TokenManagerDeps` gains `approveConsent?: (r: ConsentRequest) => Promise<boolean>` and `audit?`; `interface ConsentRequest { alias: string; tenant: string; account: string; appName: string; scopes: string[] }`. Cache is per alias then resource key. A cold key first tries a refresh-token exchange using any cached entry of the same alias and `clientId`. On `needs_consent`: ask once; Yes → `grantConsent`, short wait, retry authorize once; No or failure → the original error.

- [ ] Tests in `tests/tokens.test.ts`: sibling exchange makes no browser call and passes the UPN check; `drop(alias)` only drops that alias; consent Yes → grant then success; No → `needs_consent`, grant never called; no approver → unchanged behaviour; grant throws → that error.
- [ ] Fail, implement, pass, commit `feat: token exchange between resources and one-click consent`.

### Task 7: Broker and server (`src/broker.ts`, `src/server.ts`)

**Produces:** `Broker.adminCmdlet(tenant, service, cmdlet, parameters?, opts?: { select?: unknown; first?: unknown; site?: string })`; `makeConsentApprover(deps: { confirm; audit; redactor }): (r: ConsentRequest) => Promise<boolean>`; graph results through `capResult`; MCP tool `admin_cmdlet` (replaces `exo_cmdlet`).

- [ ] Tests: validation (service, select, first, site, denied cmdlets) happens before vault/sign-in/dialog; reads skip the dialog; a `Get-` with `Out` asks first; the dialog action starts with `[teams]` / `[sharepoint https://…]`; teams passes two tokens; result capped with `totalItems`; consent approver text lists the app and scopes and audits; server lists `admin_cmdlet` and not `exo_cmdlet`.
- [ ] Fail, implement, pass, commit `feat: admin_cmdlet tool`.

### Task 8: Skill, README, packaging

- [ ] `SKILL.md`: services, the task table, "Work efficiently" rules, `site`, consent dialog. `README.md`: per-service setup (module, shell, install command), `sharepoint` field, consent, checklist items, error codes (`module_missing`, `cmdlet_failed`, `consent_not_allowed`). Packaging test path `dist/admin/run-admin-cmdlet.ps1`. Version 0.5.0. `npm run build`.
- [ ] Full suite + `tsc --noEmit`, commit `feat: docs, skill and build for admin portals`.
