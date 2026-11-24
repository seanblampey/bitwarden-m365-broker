export interface Resource {
  key: 'graph' | 'exo';
  clientId: string;
  redirectUri: string;
  scopes: string[];
}

/**
 * Microsoft Graph Command Line Tools (the Microsoft Graph PowerShell SDK's public client).
 * Redirect URI: the SDK (Microsoft.Graph.Authentication 2.41.2, checked 2026-11-24) signs in with
 * Azure.Identity's InteractiveBrowserCredential, whose default redirect is `http://localhost`
 * (MSAL system-browser loopback; Entra accepts any port on http://localhost for public clients).
 */
export function graphResource(scopes: string[]): Resource {
  return { key: 'graph', clientId: '14d82eec-204b-4c2f-b7e8-296a70dab67e', redirectUri: 'http://localhost', scopes };
}

/**
 * Exchange Online PowerShell public client. Redirect URI: ExchangeOnlineManagement 3.11.1
 * (Microsoft.Exchange.Management.ExoPowershellGalleryModule.dll, checked 2026-11-24) builds
 * `<AzureADAuthorizationEndpointUri>/organizations/oauth2/nativeclient` with the default
 * endpoint https://login.microsoftonline.com.
 */
export const EXO_RESOURCE: Resource = {
  key: 'exo',
  clientId: 'fb78d390-0c51-40cd-8e17-fdbfab77341b',
  redirectUri: 'https://login.microsoftonline.com/organizations/oauth2/nativeclient',
  scopes: ['https://outlook.office365.com/.default', 'offline_access'],
};
