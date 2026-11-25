# Bitwarden M365 broker (Claude Code plugin and Pi package)

## What it does

This plugin lets Claude Code, or the Pi coding agent (see "Using it with Pi"), do Microsoft 365 admin work in your tenants (Microsoft Graph, plus the Exchange Online, Security & Compliance, Teams and SharePoint PowerShell modules), using admin logins stored in Bitwarden.

How it keeps secrets away from Claude:

- Claude only gets six tools: `list_tenants`, `connect`, `graph_request`, `admin_cmdlet`, `disconnect`, `lock`. None of them returns a password, MFA code or token.
- A small local program (the "broker") unlocks Bitwarden after you type your master password into a Windows dialog, signs in to Microsoft in a hidden Edge window (you can make it visible, see the config), generates the MFA code itself, and keeps the tokens in memory only.
- Reads (Graph `GET`, `Get-` cmdlets) run straight away. Anything else shows a Yes/No dialog, with No pre-selected, and only runs if you click Yes.
- Every result is scrubbed of anything that looks like a secret. A hook stops Claude from running the `bw` command, and from touching (with its file tools or in a shell command) the Bitwarden data folders, the broker's config folder (`%APPDATA%\claude-bw-broker`) and audit log folder (`%LOCALAPPDATA%\claude-bw-broker`), Claude's `settings.json`/`settings.local.json` files (user and project), and `%USERPROFILE%\.claude\plugins` (Claude may still read this plugin's own files). Any shell command that mentions `.claude` together with `settings` or `plugins` is also blocked.
- Only things in the Bitwarden folder `Claude Access` are usable.

## Requirements

- Windows 10 or 11, Node.js 20 or newer
- Claude Code (or Pi) running on that PC
- Bitwarden CLI
- Microsoft Edge
- The PowerShell modules for the services you want to use (you install them; the assistant never does):

| Service (`admin_cmdlet` `service`) | Module | Runs in | Install, in that shell |
|---|---|---|---|
| `exchange`: Exchange Online | ExchangeOnlineManagement 3.1.0+ | Windows PowerShell 5.1 (`powershell.exe`) | `Install-Module ExchangeOnlineManagement -Scope CurrentUser` |
| `compliance`: Security & Compliance (Purview) | ExchangeOnlineManagement 3.2.0+ (the same module) | Windows PowerShell 5.1 | as above |
| `teams`: Microsoft Teams | MicrosoftTeams 6.0.0+ | Windows PowerShell 5.1 | `Install-Module MicrosoftTeams -Scope CurrentUser` |
| `sharepoint`: SharePoint Online | PnP.PowerShell 3.0.0+ | PowerShell 7.4+ (`pwsh.exe`) | `winget install Microsoft.PowerShell`, then in `pwsh`: `Install-Module PnP.PowerShell -Scope CurrentUser` |

Graph needs no module. If a module is missing or too old, the tool returns `module_missing` with the exact command to run and the shell to run it in.

SharePoint uses PnP PowerShell, not Microsoft's `Microsoft.Online.SharePoint.PowerShell` module, because that module cannot sign in with a token the broker supplies.

## One-time setup

1. Install the Bitwarden CLI: `npm i -g @bitwarden/cli`
2. In your own terminal (not through Claude) run `bw login` once.
3. In Bitwarden, create a folder named exactly `Claude Access`.
4. For each tenant admin account, create a login item in that folder:
   - Item name: a short alias, such as `contoso`. This is what Claude sees.
   - Username and password of the admin account.
   - Authenticator key (TOTP): the secret seed from the account's authenticator-app setup. Only authenticator-app codes are supported.
   - A custom field of type Text named `tenant`, with the tenant's domain (for example `contoso.onmicrosoft.com`).
5. Install the PowerShell modules you need from the table above, each in the shell named there.

   Why the shell matters: a module installed with `-Scope CurrentUser` from PowerShell 7 goes to `Documents\PowerShell\Modules`, which Windows PowerShell 5.1 does not search, and the other way round. Check with `powershell.exe -NoProfile -Command "Get-Module -ListAvailable ExchangeOnlineManagement, MicrosoftTeams"` and `pwsh -NoProfile -Command "Get-Module -ListAvailable PnP.PowerShell"`.
6. SharePoint only, and only for a tenant whose SharePoint address does not match its tenant name: add a custom Text field named `sharepoint` to the item, with the name in the address (for `https://contosoltd.sharepoint.com`, the value is `contosoltd`). When the `tenant` field is `<name>.onmicrosoft.com`, the broker uses `<name>` and no extra field is needed.

## Install

There is nothing to build or download: the ready-to-run plugin is committed in `dist/`. In Claude Code (the desktop app or the terminal), run:

```
/plugin marketplace add seanblampey/bitwarden-m365-broker
/plugin install bitwarden-m365@bitwarden-m365
```

Restart Claude Code if prompted. Node.js 20+ must be on your PATH, because Claude Code starts the broker and the hook with `node`.

To update later: `/plugin marketplace update bitwarden-m365`, then restart Claude Code. If the update fails, remove and re-add the marketplace:

```
/plugin marketplace remove bitwarden-m365
/plugin marketplace add seanblampey/bitwarden-m365-broker
/plugin install bitwarden-m365@bitwarden-m365
```

Claude Code runs whatever is on this repository's `master` branch, and that code handles your logins once you unlock Bitwarden. Only install or update from a source you trust, and look at what changed before updating.

### For developers

`dist/` is generated by `npm run build` (an esbuild bundle plus the PowerShell scripts and a copy of `playwright-core`). After changing anything in `src/`, run `npm ci && npm run build` and commit `dist/` with your change; `npm run check:dist` fails if the committed `dist/` is out of date.

## Using it with Pi

The same repository is also a [Pi](https://pi.dev) package. Pi has no Claude Code hooks, so the package brings its own guard: a Pi extension that checks every tool call before it runs, with the same rules as the Claude Code hook, plus Pi's own folders. It also starts the broker for you, so there is no MCP server to add by hand.

Requirements and one-time setup are the same as above (Bitwarden CLI, the `Claude Access` folder, the PowerShell modules, Node.js 20+). Pi 1.6 or newer is needed. Install:

```
pi install git:github.com/seanblampey/bitwarden-m365-broker
```

Then restart Pi (or run `/reload`). Any model works, including a local one; the model never receives a password, MFA code or token.

What the Pi extension does:

- Registers the broker as the MCP server `bitwarden-m365`, with its six tools offered to the model directly (`mcp__bitwarden_m365__list_tenants` and so on).
- Blocks the same things as the Claude Code hook, for Pi's tools (`bash`, `powershell`, `read`, `write`, `edit`, `grep`, `find`, `ls`): running `bw`, the Bitwarden data folders, the broker's config and audit log, and this package's own files (reading them is allowed).
- Also blocks Pi's own config, so the model cannot switch the guard off: `~/.pi/agent` (or `PI_CODING_AGENT_DIR`) and the project's `.pi` folder, including any shell command that mentions a `.pi` folder.
- Tools it does not know (from other extensions or MCP servers) have every text value in their input checked with the shell rules, which blocks more than strictly needed rather than less.
- Calls made from inside `codemode` scripts are checked one by one, like any other call.
- If the guard itself fails, Pi refuses the call.

Check it after installing: ask the model to run `bw list items` (must be blocked), then to list your tenants (the Bitwarden unlock box should appear). `/mcp` should show `bitwarden-m365` connected.

Limits specific to Pi:

- Pi extensions run in load order and may change a tool call's input. An extension that rewrites a call after this guard has checked it could undo the check, so only install Pi extensions you trust.
- Turning the package off with `pi config`, `pi remove` or by editing Pi's settings yourself turns the guard off too, and the broker with it.
- The Claude Code verification checklist below applies to Pi as well; the tool names differ only by the `mcp__bitwarden_m365__` prefix.

To update: `pi update --extensions`.

## Config file (optional)

Path: `%APPDATA%\claude-bw-broker\config.json`. If it is missing, defaults are used. Claude is blocked from reading or editing it.

| Field | Default | Meaning |
|---|---|---|
| `folderName` | `Claude Access` | Bitwarden folder that holds the allowed items |
| `showSignInWindow` | `false` | Show the Microsoft sign-in window instead of running it hidden. Turn on to watch where a failing sign-in stops. |
| `idleMinutes` | `30` | Minutes of inactivity before the vault locks (you are asked for the master password again) |
| `graphScopes` | User, Group, Directory, MailboxSettings, TeamSettings (ReadWrite), Organization, Reports, AuditLog (Read), plus `offline_access`, `openid`, `profile` | Graph permissions requested at sign-in |

Example: `{ "idleMinutes": 15 }`

The audit log (what was called, approved or denied; never secrets) is at `%LOCALAPPDATA%\claude-bw-broker\audit.jsonl`. Claude is blocked from reading, editing or deleting it.

## Approving Microsoft's apps (consent)

The broker signs in with Microsoft's own public apps. It never needs an app registration of your own:

| Used for | Microsoft app |
|---|---|
| Graph | Microsoft Graph Command Line Tools |
| Exchange, Security & Compliance | Microsoft Exchange Online PowerShell |
| Teams | Microsoft Teams PowerShell Cmdlets |
| SharePoint | Microsoft SharePoint Online Management Shell |

The first time a tenant uses one of these, Microsoft may ask for the app to be approved for the organisation. When that happens:

1. A Yes/No box appears (No is the default). It names the app, the tenant and every permission.
2. If you click **Yes**, the broker approves the app for the organisation on Microsoft's admin-consent page, in its hidden browser, and then finishes signing in. Nothing to copy or run.
3. If you click **No** (or the box times out), nothing is approved. The tool returns `signin_failed` with category `needs_consent` and the steps to do it by hand: a consent link, and the PowerShell command for that app. You are not asked again for that app and tenant until you `disconnect`.

The broker only ever asks for the apps above, with the permissions fixed in its code and your config (`graphScopes`); the assistant cannot choose them or trigger consent directly. Approval is a lasting, tenant-wide setting: it stays until an admin removes the app's permissions in the Entra admin center (Enterprise applications).

If the account cannot approve apps, the result is `consent_not_allowed`: it needs the Global Administrator, Privileged Role Administrator or Cloud Application Administrator role.

## Using it

Each Bitwarden item in the folder appears under its own name. If two items share a name, they appear as "name (username)", with "#2", "#3" added if that still repeats, so every name `list_tenants` returns is unique.

Just ask Claude, naming the tenant alias:

- "List my tenants, then connect to contoso."
- "In contoso, show the five most recently created users."
- "Which mailboxes in contoso have a forwarding address set?"
- "Show the inbox rules for jane@contoso.com."
- "What is contoso's SharePoint external sharing setting?"
- "List contoso's retention policies." / "Which Teams meeting policies allow recording?"
- "Set CustomAttribute15 to 'reviewed' on the mailbox test@contoso.com." (you will get a Yes/No box)

Claude is told to explain every change in chat before the Yes/No box appears.

## Limits and accepted risks

- Claude Code runs as your Windows user, as does the broker. Another process of the same user could, in principle, reach the same things. The hook only blocks Claude's own tools.
- The approval dialog is a plain Yes/No box. It shows the tenant, account and the complete action, but you must read it. Line breaks, tabs, other control characters and invisible or text-direction (bidi) characters in values are shown as escapes such as `\n` or `\u202E`, so a value cannot fake extra lines. A change whose action text is longer than 1500 characters is refused (`too_long_to_approve`) rather than shown cut off. An unanswered dialog closes after 5 minutes (a password dialog then fails with `dialog_failed`; an approval counts as No).
- Approved cmdlets run with `-Confirm:$false` (your Yes is the confirmation), so `Remove-*` cmdlets do not prompt again. Claude cannot pass `Confirm` itself; `WhatIf` is allowed. Approved SharePoint (PnP) cmdlets also get `-Force` when they have it, for the same reason.
- Only authenticator-app (TOTP) MFA is supported. Federated sign-in is not.
- Cmdlets are limited to each service's own module. Some are refused outright because they hand back secrets or sessions, or write files to this PC: `Connect-*`, `Disconnect-*`, anything with `AccessToken`, `Token`, `Credential`, `Secret`, `Password` or `Certificate` in its name, `Get-PnPConnection` and `Get-PnPFile`. A `Get-` cmdlet given a local-file parameter (such as `-Out` or `-Path`) needs your Yes like a change does.
- Parameter names must be written in full. PowerShell's abbreviations (`-O` for `-Out`) and aliases are refused, so the name the broker checked is the one that is used.
- Large results are cut before the assistant sees them: at most 200 items per cmdlet call unless it asks for another number (up to 1000), and about 30,000 characters per result. The result says how many items the cmdlet returned, and passes on the cmdlet's own warnings (Exchange, for example, stops at 1000 results unless asked for more, and says so). A cmdlet that runs for more than 5 minutes is stopped.
- PnP cmdlets that call Microsoft Graph behind the scenes (some Microsoft 365 Group cmdlets) fail, because the broker gives PnP a SharePoint token only. Use `graph_request` for those.
- The hook blocks plain use of `bw`, but deliberately obfuscated calls are not caught.
- Tested on real Windows 11 so far: the plugin installs from GitHub, the Bitwarden unlock dialog and `list_tenants` work, and Microsoft sign-in runs through to the consent prompt. Not yet confirmed on a real tenant: completed sign-in, Graph calls, any of the four PowerShell services, one-click consent, and the approval dialog. The sign-in details for Teams, Security & Compliance and SharePoint were read from Microsoft's modules but have never been run. Work through the checklist below before relying on it.
- Microsoft can change its sign-in pages at any time. When the broker meets a page it does not recognise, it stops with `signin_failed`, category `page_changed`, and the message says which page it was.

## Windows verification checklist

Run these on a real Windows PC with a test tenant before relying on it.

1. Ask Claude to run `list_tenants`. Expected: a password dialog appears on top (not hidden, no stray console window) and takes keyboard focus even while Claude Code's terminal is in the foreground; typing the master password and pressing Enter returns your aliases.
2. Run `lock`, then `list_tenants` again and click Cancel in the dialog. Expected: error `unlock_cancelled`, no hang.
3. `connect` to a real tenant. Expected: returns the admin's account name, no visible browser window. The first time, a Yes/No box may ask you to approve Microsoft's app for the tenant (see "Approving Microsoft's apps (consent)").
4. `graph_request` GET `/organization`. Expected: tenant details, no dialog.
5. `admin_cmdlet` service `exchange`, `Get-Mailbox -ResultSize 1`. Expected: one mailbox, no dialog.
6. `admin_cmdlet` exchange `Get-Mailbox -Identity nosuchuser`. Expected: an error (`cmdlet_failed`), not an empty result.
7. `admin_cmdlet` exchange `Set-Mailbox` on a test mailbox, `CustomAttribute15`. Expected: Yes/No dialog opens on top with No focused.
   - Click No: result `denied`, value unchanged.
   - Repeat and click Yes: value changes.
8. `graph_request` PATCH on a test user, click No. Expected: `denied`, the object is unchanged.
9. `admin_cmdlet` exchange `Get-Content`. Expected: refused with `cmdlet_failed` (it is not an Exchange cmdlet); nothing is read.
10. Ask Claude to run `bw list items`. Expected: blocked by the hook.
11. Set `"idleMinutes": 1` in the config, restart Claude Code, use a tenant, wait 2 minutes, call `list_tenants`. Expected: the password dialog appears again.
12. Open `audit.jsonl` (yourself, not through Claude) and run `Select-String -Path "$env:LOCALAPPDATA\claude-bw-broker\audit.jsonl" -Pattern "<your password>"`. Expected: no matches (also try the TOTP seed).
13. With two Bitwarden items for different tenants and different admin accounts, `connect` to the first, then to the second, in the same Claude Code session. Expected: both return their own account; no `page_changed`. Then run a `Get-` cmdlet in each tenant again: no new sign-in.
14. Create a test inbox rule, then `admin_cmdlet` exchange `Remove-InboxRule -Identity <rule>` on a test mailbox and click Yes. Expected: the rule is removed (no "NonInteractive mode" error, no second dialog).
15. Ask Claude to run `Set-Mailbox` on a test mailbox with a value containing a line break. Expected: the dialog shows `\n` inside the value, not a new line.
16. Close Microsoft Edge completely, then `disconnect` and `connect` again. Expected: sign-in still works (the broker starts its own hidden Edge). If Edge is not installed: error `browser_failed`, and a retry after installing Edge works without restarting Claude Code.
17. Install ExchangeOnlineManagement only from PowerShell 7 (`pwsh`) on a test PC. Expected: `module_missing` saying to install it in Windows PowerShell (powershell.exe).
18. `admin_cmdlet` service `compliance`, `Get-RetentionCompliancePolicy`, `first: 5`. Expected: policies (or an empty list), no dialog. This is the first real test of the Security & Compliance sign-in.
19. `admin_cmdlet` service `teams`, `Get-CsTeamsMeetingPolicy`, `select: ["Identity","AllowCloudRecording"]`. Expected: policies with just those two fields. First real test of the Teams sign-in (two tokens).
20. `admin_cmdlet` service `sharepoint`, `Get-PnPTenantSite`, `select: ["Url","Title"]`, `first: 5`. Expected: five sites and a `totalItems` count. First real test of the SharePoint sign-in. If it fails with `AADSTS50011` (redirect address), send that message: the redirect value needs adjusting.
21. `admin_cmdlet` service `sharepoint` with `site` set to one site's URL, `Get-PnPList`, `select: ["Title","ItemCount"]`. Expected: that site's lists.
22. `admin_cmdlet` service `sharepoint` with `site: "https://<another tenant>.sharepoint.com"`. Expected: refused (`invalid_parameters`), no sign-in.
23. `admin_cmdlet` sharepoint `Get-PnPAccessToken`. Expected: refused (`invalid_cmdlet`).
24. On a tenant that has never used one of the apps: run a tool that needs it. Expected: a Yes/No box naming the app and permissions. Click No: `needs_consent` with manual steps, and the app is not in Entra > Enterprise applications. `disconnect`, retry, click Yes: the call completes with no further steps.
25. Uninstall or rename a module (for example MicrosoftTeams) and call its service. Expected: `module_missing` with the install command; nothing is installed for you.

## Troubleshooting

| Error | Meaning and fix |
|---|---|
| `not_logged_in` | Bitwarden CLI is not logged in. Run `bw login` in your own terminal, then retry. |
| `unlock_cancelled` | You closed the master password dialog. Retry and enter it. |
| `dialog_failed` | The Windows password or approval dialog could not be shown (for example PowerShell could not start, or a policy blocks scripts), or the password dialog was not answered within 5 minutes. Nothing was changed. Check that `powershell.exe` runs, then retry. |
| `wrong_master_password` | Bitwarden rejected the master password (3 tries). Retry. |
| `folder_missing` | No Bitwarden folder with the configured name (default `Claude Access`). Create it, or set `folderName`. Sync the vault with `bw sync` if you just made it. |
| `not_allowed` | The alias is not an item in that folder. Check the name with `list_tenants`. |
| `item_incomplete` | The Bitwarden item lacks username, password, TOTP key or the `tenant` field; the message says which. For SharePoint it can also ask for the `sharepoint` field (see setup step 6). |
| `signin_failed` | Microsoft sign-in did not complete. The `category` says why: `wrong_password`, `mfa_not_totp` (account has no authenticator-app option), `needs_consent`, `conditional_access` (policy blocked a non-compliant or non-trusted sign-in), `federated` (unsupported), `account_locked` (locked or disabled), `mfa_setup_required` (Microsoft wants the account to set up its MFA methods: sign in once yourself and finish it), `wrong_tenant` (the account does not exist in that tenant: check the username and `tenant` field), `page_changed` (a sign-in page the broker does not recognise, or a timeout). The message ends with "Stopped at:" and the page address, title, heading and any `AADSTS` code, so you can see which page it was. To watch it happen, set `"showSignInWindow": true` in the config and restart Claude Code. |
| `signin_failed` with category `needs_consent` | Microsoft wants the app approved for this tenant and it was not (you clicked No, or the box could not be shown). Follow the steps in the message, or `disconnect` and try again to be asked once more. See "Approving Microsoft's apps (consent)". |
| `signin_failed` with category `consent_not_allowed` | The account cannot approve apps for the organisation. Give it a role that can (Global Administrator, Privileged Role Administrator or Cloud Application Administrator), or have such an admin approve the app using the link in the `needs_consent` message. |
| `wrong_account` | Microsoft signed in as a different account than the Bitwarden item. Fix the item. |
| `token_failed` | The token request failed (network or Microsoft error code in the message). Retry; check connectivity. |
| `cmdlet_failed` | The cmdlet failed; the message has the PowerShell error. Check the cmdlet's parameters and that the account has the admin role for that service. |
| `module_missing` | A PowerShell module (or PowerShell 7, for SharePoint) is missing or too old. Run the command in the message yourself, in the shell it names, then retry. |
| `bw_not_found` | Bitwarden CLI is not on PATH. Install it (`npm i -g @bitwarden/cli`) and restart Claude Code. |
| `denied` | You clicked No on the approval dialog (or it was closed, or left unanswered for 5 minutes). Nothing was changed. |
| `too_long_to_approve` | The change is too large to show in full in the approval box (over 1500 characters), so it was refused before anything happened. Ask Claude to split it into smaller requests. |
| `browser_failed` | Microsoft Edge could not be started for sign-in. Check that Edge is installed and starts normally, then retry (no restart needed). |
| `graph_failed` | Microsoft Graph could not be reached (network). Retry; check connectivity or proxy. |
| `bw_failed` | The Bitwarden CLI failed, timed out or returned something unexpected. Run `bw status` in your own terminal, then retry. |
| `bad_config` | `config.json` is unreadable, not valid JSON, or a field has the wrong type; the message names it. Fix or delete the file. |
| `bad_totp_seed` | The item's authenticator key is not a valid base32 seed or otpauth link. Re-copy it from the account's MFA setup. |
| `invalid_method` | Claude used a Graph method other than GET, POST, PATCH, PUT, DELETE. Ask it to retry. |
| `invalid_path` | The Graph path or API version was rejected (must start with "/", stay on graph.microsoft.com, version v1.0 or beta). |
| `invalid_cmdlet` | The cmdlet name is malformed, or it is one the broker refuses (session, token, credential or local-file cmdlets). A cmdlet from the wrong module (for example `Get-Content`) fails with `cmdlet_failed`. |
| `invalid_parameters` | Something in the request was rejected: parameter names must be plain; common parameters that redirect output, and `Confirm`, are not allowed; `service` must be one of the four; `select` must be plain property names; `first` 1 to 1000; `site` must be on the tenant's own SharePoint. |
| `internal` | Unexpected broker error. Details are in `audit.jsonl`; report it. |
