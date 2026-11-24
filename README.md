# Bitwarden M365 broker (Claude Code plugin)

## What it does

This plugin lets Claude Code do Microsoft 365 admin work (Microsoft Graph and Exchange Online PowerShell) in your tenants, using admin logins stored in Bitwarden.

How it keeps secrets away from Claude:

- Claude only gets six tools: `list_tenants`, `connect`, `graph_request`, `exo_cmdlet`, `disconnect`, `lock`. None of them returns a password, MFA code or token.
- A small local program (the "broker") unlocks Bitwarden after you type your master password into a Windows dialog, signs in to Microsoft in a hidden Edge window, generates the MFA code itself, and keeps the tokens in memory only.
- Reads (Graph `GET`, Exchange `Get-` cmdlets) run straight away. Anything else shows a Yes/No dialog, with No pre-selected, and only runs if you click Yes.
- Every result is scrubbed of anything that looks like a secret. A hook stops Claude from running the `bw` command, and from touching (with its file tools or in a shell command) the Bitwarden data folders, the broker's config folder (`%APPDATA%\claude-bw-broker`) and audit log folder (`%LOCALAPPDATA%\claude-bw-broker`), Claude's `settings.json`/`settings.local.json` files (user and project), and `%USERPROFILE%\.claude\plugins` (Claude may still read this plugin's own files). Any shell command that mentions `.claude` together with `settings` or `plugins` is also blocked.
- Only things in the Bitwarden folder `Claude Access` are usable.

## Requirements

- Windows 10 or 11, Node.js 20 or newer
- Claude Code running on that PC
- Bitwarden CLI
- Microsoft Edge
- PowerShell with the ExchangeOnlineManagement module (version 3.1.0 or newer) and Microsoft.Graph.Authentication

## One-time setup

1. Install the Bitwarden CLI: `npm i -g @bitwarden/cli`
2. In your own terminal (not through Claude) run `bw login` once.
3. In Bitwarden, create a folder named exactly `Claude Access`.
4. For each tenant admin account, create a login item in that folder:
   - Item name: a short alias, such as `contoso`. This is what Claude sees.
   - Username and password of the admin account.
   - Authenticator key (TOTP): the secret seed from the account's authenticator-app setup. Only authenticator-app codes are supported.
   - A custom field of type Text named `tenant`, with the tenant's domain (for example `contoso.onmicrosoft.com`).
5. Install the Exchange module: `Install-Module ExchangeOnlineManagement -Scope CurrentUser` (needs 3.1.0 or newer).
6. Install the Graph sign-in module used for the consent step: `Install-Module Microsoft.Graph.Authentication -Scope CurrentUser`.

## Install

The project must be built before it is installed, because the hook and server run from `dist/`.

```
npm ci
npm run build
```

Then in Claude Code:

```
/plugin marketplace add <path to this folder>
/plugin install bitwarden-m365@bitwarden-m365-local
```

Restart Claude Code if prompted.

## Config file (optional)

Path: `%APPDATA%\claude-bw-broker\config.json`. If it is missing, defaults are used. Claude is blocked from reading or editing it.

| Field | Default | Meaning |
|---|---|---|
| `folderName` | `Claude Access` | Bitwarden folder that holds the allowed items |
| `idleMinutes` | `30` | Minutes of inactivity before the vault locks (you are asked for the master password again) |
| `graphScopes` | User, Group, Directory, MailboxSettings, TeamSettings (ReadWrite), Organization, Reports, AuditLog (Read), plus `offline_access`, `openid`, `profile` | Graph permissions requested at sign-in |

Example: `{ "idleMinutes": 15 }`

The audit log (what was called, approved or denied; never secrets) is at `%LOCALAPPDATA%\claude-bw-broker\audit.jsonl`. Claude is blocked from reading, editing or deleting it.

## Per-tenant consent

The broker signs in using Microsoft's own public apps (Microsoft Graph Command Line Tools and Exchange Online PowerShell). It never clicks "Accept" on a consent page. If a tenant has not yet allowed those apps for the admin account, `connect` returns `signin_failed` with category `needs_consent`.

To fix it once per tenant, in your own PowerShell (not through Claude), sign in as that admin and accept the consent prompt yourself, asking for the same permissions the broker requests:

```
Connect-MgGraph -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All","MailboxSettings.ReadWrite","Organization.Read.All","Reports.Read.All","AuditLog.Read.All","TeamSettings.ReadWrite.All"
```

Tick "Consent on behalf of your organization" on the Microsoft page. Alternatively grant admin consent to "Microsoft Graph Command Line Tools" in Entra admin center under Enterprise applications. If you changed `graphScopes` in the config, change this list to match. For Exchange, run `Connect-ExchangeOnline` once the same way if sign-in still reports consent. Then try `connect` again.

## Using it

Just ask Claude, naming the tenant alias:

- "List my tenants, then connect to contoso."
- "In contoso, show the five most recently created users."
- "Which mailboxes in contoso have a forwarding address set?"
- "Show the inbox rules for jane@contoso.com."
- "Set CustomAttribute15 to 'reviewed' on the mailbox test@contoso.com." (you will get a Yes/No box)

Claude is told to explain every change in chat before the Yes/No box appears.

## Limits and accepted risks

- Claude Code runs as your Windows user, as does the broker. Another process of the same user could, in principle, reach the same things. The hook only blocks Claude's own tools.
- The approval dialog is a plain Yes/No box. It shows the tenant, account and action, but you must read it.
- Only authenticator-app (TOTP) MFA is supported. Federated sign-in is not.
- The hook blocks plain use of `bw`, but deliberately obfuscated calls are not caught.
- The PowerShell scripts and the Microsoft sign-in page automation have only been tested against fakes, not against real Windows or real Microsoft pages. The checklist below is the real test. Microsoft changing its sign-in page can break sign-in (reported as `signin_failed` with category `page_changed`).

## Windows verification checklist

Run these on a real Windows PC with a test tenant before relying on it.

1. Ask Claude to run `list_tenants`. Expected: a password dialog takes keyboard focus; typing the master password and pressing Enter returns your aliases.
2. Run `lock`, then `list_tenants` again and click Cancel in the dialog. Expected: error `unlock_cancelled`, no hang.
3. `connect` to a real tenant. Expected: returns the admin's account name, no visible browser window.
4. `graph_request` GET `/organization`. Expected: tenant details, no dialog.
5. `exo_cmdlet Get-Mailbox -ResultSize 1`. Expected: one mailbox, no dialog.
6. `exo_cmdlet Get-Mailbox -Identity nosuchuser`. Expected: an error (`exo_failed`), not an empty result.
7. `exo_cmdlet Set-Mailbox` on a test mailbox, `CustomAttribute15`. Expected: Yes/No dialog opens on top with No focused.
   - Click No: result `denied`, value unchanged.
   - Repeat and click Yes: value changes.
8. `graph_request` PATCH on a test user, click No. Expected: `denied`, the object is unchanged.
9. `exo_cmdlet Get-Content`. Expected: refused (it is not an Exchange cmdlet).
10. Ask Claude to run `bw list items`. Expected: blocked by the hook.
11. Set `"idleMinutes": 1` in the config, restart Claude Code, use a tenant, wait 2 minutes, call `list_tenants`. Expected: the password dialog appears again.
12. Open `audit.jsonl` and run `Select-String -Path "$env:LOCALAPPDATA\claude-bw-broker\audit.jsonl" -Pattern "<your password>"`. Expected: no matches (also try the TOTP seed).

## Troubleshooting

| Error | Meaning and fix |
|---|---|
| `not_logged_in` | Bitwarden CLI is not logged in. Run `bw login` in your own terminal, then retry. |
| `unlock_cancelled` | You closed the master password dialog. Retry and enter it. |
| `wrong_master_password` | Bitwarden rejected the master password (3 tries). Retry. |
| `folder_missing` | No Bitwarden folder with the configured name (default `Claude Access`). Create it, or set `folderName`. Sync the vault with `bw sync` if you just made it. |
| `not_allowed` | The alias is not an item in that folder. Check the name with `list_tenants`. |
| `item_incomplete` | The Bitwarden item lacks username, password, TOTP key or the `tenant` field; the message says which. |
| `signin_failed` | Microsoft sign-in did not complete. The `category` says why: `wrong_password`, `mfa_not_totp` (account has no authenticator-app option), `needs_consent`, `conditional_access` (policy blocked a non-compliant or non-trusted sign-in), `federated` (unsupported), `account_locked`, `page_changed` (sign-in page unexpected or timed out). |
| `signin_failed` with category `needs_consent` | See "Per-tenant consent". |
| `wrong_account` | Microsoft signed in as a different account than the Bitwarden item. Fix the item. |
| `token_failed` | The token request failed (network or Microsoft error code in the message). Retry; check connectivity. |
| `exo_failed` | The Exchange cmdlet failed; the message has the PowerShell error. Check module version (3.1.0+) and the cmdlet's parameters. |
| `bw_not_found` | Bitwarden CLI is not on PATH. Install it (`npm i -g @bitwarden/cli`) and restart Claude Code. |
| `denied` | You clicked No on the approval dialog (or it was closed). Nothing was changed. |
| `graph_failed` | Microsoft Graph could not be reached (network). Retry; check connectivity or proxy. |
| `bw_failed` | The Bitwarden CLI failed, timed out or returned something unexpected. Run `bw status` in your own terminal, then retry. |
| `bad_config` | `config.json` is unreadable, not valid JSON, or a field has the wrong type; the message names it. Fix or delete the file. |
| `bad_totp_seed` | The item's authenticator key is not a valid base32 seed or otpauth link. Re-copy it from the account's MFA setup. |
| `invalid_method` | Claude used a Graph method other than GET, POST, PATCH, PUT, DELETE. Ask it to retry. |
| `invalid_path` | The Graph path or API version was rejected (must start with "/", stay on graph.microsoft.com, version v1.0 or beta). |
| `invalid_cmdlet` | The cmdlet name is malformed or not an Exchange Online cmdlet (for example `Get-Content`). |
| `invalid_parameters` | The cmdlet parameters were rejected (names must be plain; some common parameters are not allowed). |
| `internal` | Unexpected broker error. Details are in `audit.jsonl`; report it. |
