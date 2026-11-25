/** One sign-in target: a Microsoft public client app and the scopes requested from it. */
export interface Resource {
  /** Cache key; unique per (app, scopes). */
  key: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
  /** The app's name as Microsoft shows it, for the consent dialog. */
  appName: string;
  /** What the user can run once themselves to approve the app by hand. */
  connectHint?: string;
}

const OIDC = ['offline_access', 'openid', 'profile'];

/** Scopes that name permissions (everything except the OpenID Connect ones). */
export function permissionScopes(resource: Resource): string[] {
  return resource.scopes.filter((s) => !OIDC.includes(s));
}

/**
 * Microsoft Graph Command Line Tools (the Microsoft Graph PowerShell SDK's public client).
 * Redirect URI: the SDK (Microsoft.Graph.Authentication 2.41.2, checked 2026-11-24) signs in with
 * Azure.Identity's InteractiveBrowserCredential, whose default redirect is `http://localhost`
 * (MSAL system-browser loopback; Entra accepts any port on http://localhost for public clients).
 */
export function graphResource(scopes: string[]): Resource {
  return {
    key: 'graph',
    clientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e',
    redirectUri: 'http://localhost',
    scopes,
    appName: 'Microsoft Graph Command Line Tools',
  };
}

const EXO_CLIENT = 'fb78d390-0c51-40cd-8e17-fdbfab77341b';
const EXO_REDIRECT = 'https://login.microsoftonline.com/organizations/oauth2/nativeclient';

/**
 * Exchange Online PowerShell public client. Redirect URI: ExchangeOnlineManagement 3.11.1
 * (Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll, checked 2026-11-24) builds
 * `<AzureADAuthorizationEndpointUri>/organizations/oauth2/nativeclient` with the default
 * endpoint https://login.microsoftonline.com.
 */
export const EXO_RESOURCE: Resource = {
  key: 'exo',
  clientId: EXO_CLIENT,
  redirectUri: EXO_REDIRECT,
  scopes: ['https://outlook.office365.com/.default', 'offline_access'],
  appName: 'Microsoft Exchange Online PowerShell',
  connectHint: 'Connect-ExchangeOnline',
};

/**
 * Security & Compliance PowerShell: same module and app as Exchange. Connect-IPPSSession's default
 * ConnectionUri is https://ps.compliance.protection.outlook.com/PowerShell-LiveId (ExchangeOnlineManagement.psm1,
 * 3.11.1, checked 2026-11-25) and the module asks for `<that host>/.default`.
 */
export const COMPLIANCE_RESOURCE: Resource = {
  key: 'compliance',
  clientId: EXO_CLIENT,
  redirectUri: EXO_REDIRECT,
  scopes: ['https://ps.compliance.protection.outlook.com/.default', ...OIDC],
  appName: 'Microsoft Exchange Online PowerShell',
  connectHint: 'Connect-IPPSSession',
};

// Microsoft Teams PowerShell public client and its redirect, from MicrosoftTeams 8.1.0
// (Microsoft.TeamsCmdlets.PowerShell.Connect.dll, checked 2026-11-25).
const TEAMS_CLIENT = '12128f48-ec9e-42f0-b203-ea49fb6af367';
const TEAMS_REDIRECT = 'https://login.microsoftonline.com/common/oauth2/nativeclient';

/** "Skype and Teams Tenant Admin API" token: the second of Connect-MicrosoftTeams -AccessTokens. */
export const TEAMS_API_RESOURCE: Resource = {
  key: 'teams-api',
  clientId: TEAMS_CLIENT,
  redirectUri: TEAMS_REDIRECT,
  scopes: ['48ac35b8-9aa8-4d74-927d-1f4a14a0b239/user_impersonation', ...OIDC],
  appName: 'Microsoft Teams PowerShell Cmdlets',
  connectHint: 'Connect-MicrosoftTeams',
};

/** Graph token issued to the Teams PowerShell app: the first of Connect-MicrosoftTeams -AccessTokens. */
export const TEAMS_GRAPH_RESOURCE: Resource = {
  key: 'teams-graph',
  clientId: TEAMS_CLIENT,
  redirectUri: TEAMS_REDIRECT,
  scopes: ['https://graph.microsoft.com/.default', ...OIDC],
  appName: 'Microsoft Teams PowerShell Cmdlets',
  connectHint: 'Connect-MicrosoftTeams',
};

/**
 * SharePoint Online Management Shell public client, used to get a SharePoint token for PnP PowerShell.
 * Client ID and redirect are the strings in Microsoft.Online.SharePoint.PowerShell.dll (16.0.27814.12015,
 * checked 2026-11-25); the redirect is sent exactly as the module has it, without a trailing slash.
 * A SharePoint token is only valid for the one host it names.
 */
export function sharePointResource(host: string, adminHost: string): Resource {
  return {
    key: `spo:${host}`,
    clientId: '9bc3ab49-b65d-410a-85ad-de819febfddc',
    redirectUri: 'https://oauth.spops.microsoft.com',
    scopes: [`https://${host}/.default`, ...OIDC],
    appName: 'Microsoft SharePoint Online Management Shell',
    connectHint: `Connect-SPOService -Url https://${adminHost}`,
  };
}
