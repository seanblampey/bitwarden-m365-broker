import { BrokerError } from '../errors.js';
import {
  COMPLIANCE_RESOURCE, EXO_RESOURCE, TEAMS_API_RESOURCE, TEAMS_GRAPH_RESOURCE, sharePointResource, type Resource,
} from '../auth/resources.js';
import type { Credential } from '../vault/vault.js';

export const SERVICES = ['exchange', 'compliance', 'teams', 'sharepoint'] as const;
export type Service = (typeof SERVICES)[number];
/** Windows PowerShell 5.1 (powershell.exe) or PowerShell 7 (pwsh.exe). */
export type Shell = 'powershell' | 'pwsh';

/** Everything needed to run one cmdlet against one service for one tenant. */
export interface ServicePlan {
  service: Service;
  shell: Shell;
  /** The token the service's connect cmdlet takes. */
  primary: Resource;
  /** Teams only: the Graph token Connect-MicrosoftTeams wants alongside the Teams one. */
  graph?: Resource;
  /** SharePoint only: the site PnP connects to. */
  url?: string;
}

const invalid = (why: string): never => {
  throw new BrokerError('invalid_parameters', `Invalid parameters: ${why}`);
};

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

/** The "contoso" in contoso.sharepoint.com: the item's `sharepoint` field, else the onmicrosoft.com tenant name. */
export function sharePointName(cred: Credential): string {
  const incomplete = (): never => {
    throw new BrokerError(
      'item_incomplete',
      `Bitwarden item "${cred.alias}" needs a custom field "sharepoint" with the tenant's SharePoint name `
        + '(the "contoso" in contoso.sharepoint.com), because it cannot be worked out from the tenant field.',
    );
  };
  let name: string | undefined;
  if (cred.sharepoint) {
    name = cred.sharepoint.trim().toLowerCase()
      .replace(/^https:\/\//, '')
      .replace(/\/+$/, '')
      .replace(/\.sharepoint\.com$/, '')
      .replace(/-(admin|my)$/, '');
  } else {
    name = /^([a-z0-9-]+)\.onmicrosoft\.com$/i.exec(cred.tenant.trim())?.[1]?.toLowerCase();
  }
  if (!name || !NAME_RE.test(name)) return incomplete();
  return name;
}

function sharePointPlan(cred: Credential, site: unknown): ServicePlan {
  const name = sharePointName(cred);
  const adminHost = `${name}-admin.sharepoint.com`;
  let host = adminHost;
  let url = `https://${adminHost}`;
  if (site !== undefined) {
    if (typeof site !== 'string') return invalid('site must be a URL');
    let u: URL;
    try {
      u = new URL(site);
    } catch {
      return invalid('site must be a full https URL');
    }
    const allowed = [`${name}.sharepoint.com`, adminHost, `${name}-my.sharepoint.com`];
    // A SharePoint token must only ever be sent to the host it was issued for.
    if (u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash || !allowed.includes(u.hostname)) {
      return invalid(`site must be an https URL on ${allowed.join(', ')} with no query`);
    }
    host = u.hostname;
    url = `https://${host}${u.pathname.replace(/\/+$/, '')}`;
  }
  return { service: 'sharepoint', shell: 'pwsh', primary: sharePointResource(host, adminHost), url };
}

export function planFor(service: unknown, cred: Credential, site?: unknown): ServicePlan {
  if (typeof service !== 'string' || !(SERVICES as readonly string[]).includes(service)) {
    return invalid(`service must be one of ${SERVICES.join(', ')}`);
  }
  if (service === 'sharepoint') return sharePointPlan(cred, site);
  if (site !== undefined) return invalid('site is only for the sharepoint service');
  switch (service as Service) {
    case 'exchange':
      return { service: 'exchange', shell: 'powershell', primary: EXO_RESOURCE };
    case 'compliance':
      return { service: 'compliance', shell: 'powershell', primary: COMPLIANCE_RESOURCE };
    default:
      return { service: 'teams', shell: 'powershell', primary: TEAMS_API_RESOURCE, graph: TEAMS_GRAPH_RESOURCE };
  }
}
