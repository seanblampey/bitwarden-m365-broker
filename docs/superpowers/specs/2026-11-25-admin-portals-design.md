# Admin portals through PowerShell — Design

Status: draft for approval, 2026-11-25.

## Intent

Let the assistant (Claude Code, or Pi with a local model) do admin work beyond Graph and Exchange, the portals a Microsoft 365 admin reaches for: Security & Compliance (Purview), Teams, and SharePoint. It uses the same Bitwarden logins, the same Yes/No approval for changes, and the same guard. Also teach the assistant to ask for only what it needs, so answers are faster and use fewer tokens.

## Goals

- Run cmdlets from these modules, signed in as the Bitwarden item's admin, with no password or token ever reaching the model:
  - **Exchange Online**: `ExchangeOnlineManagement` (today's `exo_cmdlet`).
  - **Security & Compliance**: `Connect-IPPSSession`, from the same module.
  - **Teams**: the `MicrosoftTeams` module.
  - **SharePoint**: the `PnP.PowerShell` module (user's choice; Microsoft's own SharePoint module cannot take a token).
- The same safety model as now: reads (verb `Get`) run directly, everything else shows the Yes/No box first, cmdlets must come from the expected module, and all output is scrubbed.
- Results are efficient by default: property selection, item limits, and a size cap with a clear note when output was cut.
- Works the same in Claude Code and Pi (Pi reaches the broker over MCP; nothing Pi-specific).

## Non-goals

- The assistant installing or updating modules. The user installs them. When one is missing or too old, the broker reports the exact command to run.
- Microsoft's `Microsoft.Online.SharePoint.PowerShell` module. `Connect-SPOService` has no token sign-in (checked against Microsoft Learn and the 16.0.27814 module).
- Other portals (Azure/Az, Power Platform, Intune beyond Graph). Can be added later through the same mechanism.
- Arbitrary PowerShell scripts. Still one cmdlet per call, parameters as data.

## Anti-goals

- Any token on a command line, in a tool result, in an error or in the audit log.
- A non-admin cmdlet (`Get-Content`, `Invoke-WebRequest`…) running through any service.
- A change running without the user's Yes.

## Facts established (from the modules themselves, 2026-11-25)

| Service | Module (min version) | Shell | Sign-in client app | Redirect URI | Token(s) | Connect |
|---|---|---|---|---|---|---|
| exchange | ExchangeOnlineManagement 3.1.0 | Windows PowerShell 5.1 | `fb78d390-0c51-40cd-8e17-fdbfab77341b` | `https://login.microsoftonline.com/organizations/oauth2/nativeclient` | `https://outlook.office365.com/.default` | `Connect-ExchangeOnline -AccessToken` (as now) |
| compliance | ExchangeOnlineManagement 3.2.0 (REST mode) | Windows PowerShell 5.1 | same as exchange | same | `https://ps.compliance.protection.outlook.com/.default` (the module derives the scope from its connection URI) | `Connect-IPPSSession -AccessToken -UserPrincipalName -Organization` |
| teams | MicrosoftTeams 6.x+ (8.1.0 checked) | Windows PowerShell 5.1 | `12128f48-ec9e-42f0-b203-ea49fb6af367` (Teams PowerShell) | `https://login.microsoftonline.com/common/oauth2/nativeclient` | `https://graph.microsoft.com/.default` and `48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation` | `Connect-MicrosoftTeams -AccessTokens @($graph, $teams)` |
| sharepoint | PnP.PowerShell 3.x | PowerShell 7.4+ (`pwsh.exe`) | `9bc3ab49-b65d-410a-85ad-de819febfddc` (SharePoint Online Management Shell) | `https://oauth.spops.microsoft.com` | `https://<name>-admin.sharepoint.com/.default` for tenant admin, `https://<name>.sharepoint.com/.default` for sites | `Connect-PnPOnline -Url <admin or site URL> -AccessToken` |

All four client apps are Microsoft first-party public clients, so they don't need the user's own app registration. Whether they are already consented varies by tenant. A consent page reuses the existing `needs_consent` handling.

## Approaches considered

- **A. One generic cmdlet tool with a `service` argument (chosen).** `admin_cmdlet(tenant, service, cmdlet, parameters?, select?, first?)` replaces `exo_cmdlet`. A per-service table in code holds the module, shell, connect step, allowed module origins and tokens. Fewer tools is better for local models, and adding a service later means adding a table row.
- B. One tool per service (`teams_cmdlet`, `spo_cmdlet`…). Clearer names, but more tools for the model to choose between, and the code is duplicated.
- C. A persistent PowerShell session per service (connect once, reuse). Faster after the first call, but a long-lived process holding tokens is more state, cleanup and failure modes. Not now. Each call stays a fresh, short-lived process, as today.

## Decided design

### Tool
- `admin_cmdlet` with:
  - `tenant`: alias;
  - `service`: `exchange` | `compliance` | `teams` | `sharepoint`;
  - `cmdlet`: Verb-Noun;
  - `parameters`: object, as now;
  - `select`: optional array of property names, applied with `Select-Object`;
  - `first`: optional integer 1–1000, applied with `Select-Object -First`;
  - `site`: optional, SharePoint only: a site URL to connect to instead of the admin site. It must be on the tenant's own `*.sharepoint.com` host.
- `exo_cmdlet` is removed. Its role becomes `service: "exchange"`. The skill and README are updated. (Claude's call: one user, no installed base to keep compatible.)
- Approval: non-`Get` cmdlets need a Yes. The dialog shows the service, cmdlet and full parameters, escaped and length-checked as today.
- Validation before any vault, sign-in or dialog: the cmdlet name rules, the parameter rules, the forbidden common parameters, plus:
  - `service` must be known;
  - `select` names must match `^[A-Za-z][A-Za-z0-9_.]*$`;
  - `first` must be an integer in range;
  - `site` must be on the tenant's host.

### Runner (PowerShell script per call)
- One script, `run-admin-cmdlet.ps1`, takes the service on stdin together with the tokens, UPN, organization, cmdlet and parameters. It is never put on a command line.
- Exchange, compliance and teams run under `powershell.exe`, and sharepoint runs under `pwsh.exe`. If `pwsh.exe` is missing: error `module_missing`, telling the user to install PowerShell 7.4.
- **Module checks.** Each service has a minimum version. If the module is missing or too old: error `module_missing`, with the exact command for the right shell, e.g. `Install-Module PnP.PowerShell -Scope CurrentUser (in PowerShell 7, pwsh)`.
- **Origin check per service.** After connecting, the cmdlet must resolve (Cmdlet or Function only) to that service's modules:
  - exchange and compliance: `tmpEXO_*` or `ExchangeOnlineManagement`;
  - teams: `MicrosoftTeams` and its `Microsoft.Teams.*` submodules;
  - sharepoint: `PnP.PowerShell`.
- Common parameters are still forced as today: `ErrorAction Stop`, and `Confirm:$false` on approved non-Get cmdlets. The forbidden-common list is unchanged.
- **Output.** Apply `select`/`first` in PowerShell, then `ConvertTo-Json -Depth 4 -Compress`. The broker caps the JSON at 30,000 characters. When cut, it returns `{ truncated: true, totalItems, shownItems, note: "…use select/first or a filter…" }` with the items that fit. The broker counts items before trimming, so the model knows the total.
- Always disconnect in `finally`, as today.

### Tokens and sign-in
- New resources in `resources.ts`, one per (client, scopes) pair from the table above. Each Bitwarden item signs in once per client app, in the existing per-account browser context. A second client in the same session reuses the browser sign-in cookie.
- **SharePoint host.** The default is the tenant field's `onmicrosoft.com` prefix (`contoso.onmicrosoft.com` → `contoso`). An optional Bitwarden custom field `sharepoint` (e.g. `contoso`) overrides it, for tenants whose SharePoint name differs. If the tenant field isn't an `onmicrosoft.com` domain and there's no `sharepoint` field: error `item_incomplete`, naming the `sharepoint` field.
- The account check (UPN equals the item's username) applies to every token.

### Graph
- `graph_request` gets the same output cap and truncation note. `$select`, `$top`, `$filter` and `$count` already pass through.

### Skill (efficiency rules)
A new "Work efficiently" section:
- Graph: always send `$select` with the fields needed and `$top`, and filter server-side with `$filter`. Use `$count=true` with `ConsistencyLevel` (the broker adds it) to count before listing.
- Cmdlets: always pass `select` and `first`. Use the cmdlet's own filter parameters (`-Filter`, `-ResultSize`, `-Identity`) rather than fetching everything.
- Answer counting questions with a count, not a list. Fetch details for one object after finding it.
- If a result says `truncated`, narrow the query instead of paging blindly.
- Summarise results for the user; don't paste raw JSON back.
- Pick the service that owns the setting: mail is exchange, DLP/retention/eDiscovery is compliance, Teams policies are teams, and site/sharing settings are sharepoint. Graph is for users, groups and licences.
- Also a short table of common tasks mapped to the service and cmdlet, e.g. mailbox forwarding → exchange `Get-Mailbox`, external sharing → sharepoint `Get-PnPTenant`, Teams meeting policy → teams `Get-CsTeamsMeetingPolicy`, retention → compliance `Get-RetentionCompliancePolicy`.

### Docs
- README: per-service requirements and install commands (with which shell), the `sharepoint` field, consent per client app, and new checklist items per service.
- Pi: no code change. The tools come through MCP.

## Calls made after builder review (Claude's)

1. **Secret-returning and session cmdlets are denied for every service, before anything runs:**
   - `Connect-*` and `Disconnect-*`;
   - anything matching `*AccessToken*` or `*Token` (e.g. `Get-PnPAccessToken`, `Get-PnPGraphAccessToken`, `Get-PnPAppAuthAccessToken`);
   - `Get-PnPConnection`;
   - `Get-PnPFile`, which can write files to the local disk or return file content.

   Separately, every result already goes through the JWT-shaped-string redactor, so a token a module mints itself is still removed. There are tests for each.
2. **SharePoint `site`.** Without `site`, the broker connects to the admin site (tenant cmdlets). Site-level cmdlets need `site`, and the skill says so. Tokens are cached per host (admin host, root host). `site` is shown in the approval dialog and recorded in the audit log.
3. **A second token for the same client app** (Teams' Graph token plus its Teams token; SharePoint's admin host plus its root host) comes from a refresh-token exchange for the new scope, not a second browser sign-in. The UPN check applies to it too. A browser sign-in happens only when there's no usable refresh token.
4. **Consent help per service:**
   - compliance: run `Connect-IPPSSession` once yourself;
   - teams: run `Connect-MicrosoftTeams` once yourself;
   - sharepoint: a v2 admin-consent link for the SharePoint Management Shell app with the admin-host scope, or run `Connect-SPOService -Url https://<name>-admin.sharepoint.com` once yourself (it uses the same app);
   - exchange and graph: unchanged.
5. **Truncation.**
   - Top-level arrays and Graph `{ value: [...] }` responses keep whole items until the cap. `totalItems` is the array length, or `@odata.count` when Graph supplied it.
   - Any other value is cut at the character cap, with `truncated: true` and a note.
6. **Error code.** `exo_failed` is renamed to `cmdlet_failed`, and the README and skill are updated to match.

## Left to the builder
- The exact ps1 structure (one script with a per-service switch is expected).
- How truncation picks items (keep the first N whole items).
- The Teams minimum version (pick the oldest documented with `-AccessTokens` for delegated use; 6.x).
- The tests. Unit tests with fakes, and static checks of the script. The script can't be run here (no PowerShell).

## Risks to verify on the PC (checklist)
- The compliance scope `https://ps.compliance.protection.outlook.com/.default` is accepted.
- The SharePoint redirect `https://oauth.spops.microsoft.com` is accepted, with or without a trailing slash. On `AADSTS50011` the error shows the code.
- The Teams delegated `-AccessTokens` flow works with the Teams PowerShell client's tokens.
- PnP with `-AccessToken` works for both the admin site and a regular site.
