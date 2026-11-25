import { BrokerError } from './errors.js';

export type GraphMethod = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';

const GRAPH_HOST = 'graph.microsoft.com';
const MAX_PATH = 2048;
const MAX_DEPTH = 10;

/** Build a Graph URL; guarantees the host is graph.microsoft.com. */
export function buildGraphUrl(path: string, apiVersion: 'v1.0' | 'beta'): string {
  const bad = (why: string): never => {
    throw new BrokerError('invalid_path', `Invalid Graph path: ${why}`);
  };
  if (typeof path !== 'string' || path.length === 0) return bad('must be a non-empty string');
  if (path.length > MAX_PATH) return bad('too long');
  if (!path.startsWith('/')) return bad('must start with "/"');
  if (path.startsWith('//')) return bad('must not start with "//"');
  if (path.includes('\\')) return bad('must not contain backslashes');
  if (path.includes('#')) return bad('must not contain "#"');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(path)) return bad('must not contain control characters');
  const beforeQuery = path.split('?')[0];
  for (const seg of beforeQuery.split('/')) {
    let decoded = seg;
    try { decoded = decodeURIComponent(seg); } catch { /* keep raw */ }
    if (decoded === '..' || decoded === '.') return bad('must not contain "." or ".." segments');
  }
  let url: URL;
  try {
    url = new URL(`https://${GRAPH_HOST}/${apiVersion}${path}`);
  } catch {
    return bad('not a valid URL path');
  }
  if (url.protocol !== 'https:' || url.host !== GRAPH_HOST || !url.pathname.startsWith(`/${apiVersion}/`)) {
    return bad('does not resolve to Microsoft Graph');
  }
  return url.href;
}

export function isGraphRead(method: GraphMethod): boolean {
  return method === 'GET';
}

const CMDLET_RE = /^[A-Z][a-z]+-[A-Za-z0-9]+$/;
// Connect/Disconnect: the broker owns every session. The rest could run code or touch local files.
const DENIED_VERBS = new Set(['Invoke', 'Start', 'Stop', 'Import', 'Export', 'Out', 'Connect', 'Disconnect']);
const DENIED_NAMES = new Set([
  'Add-Type', 'New-Object', 'Set-ExecutionPolicy',
  // PnP: hands back the live connection (with its token) / reads or writes local files.
  'Get-PnPConnection', 'Get-PnPFile',
]);
/** Cmdlets that return or store secrets, in any module (Get-PnPAccessToken, Get-PnPStoredCredential, ...). */
const DENIED_PATTERN = /AccessToken|Token$|Credential|Secret|Password|Certificate/i;

/**
 * Name rules shared by every admin service. The guarantee that a cmdlet belongs to the service's
 * own module is the module-origin check in the PowerShell script.
 */
export function validateCmdlet(name: string): void {
  if (typeof name !== 'string' || name.length > 100 || !CMDLET_RE.test(name)) {
    throw new BrokerError('invalid_cmdlet', 'Invalid cmdlet name: expected Verb-Noun (letters and digits only)');
  }
  if (DENIED_VERBS.has(name.split('-')[0]) || DENIED_NAMES.has(name) || DENIED_PATTERN.test(name)) {
    throw new BrokerError('invalid_cmdlet', 'This cmdlet is not permitted');
  }
}

/** Parameters that make a cmdlet read or write a file on this PC. */
const LOCAL_FILE_PARAMS = new Set(['out', 'outfile', 'outputfile', 'outputpath', 'path', 'literalpath', 'filepath', 'folder']);

/** A read runs without approval: a Get- cmdlet that names no local file. */
export function isCmdletRead(name: string, parameters: Record<string, unknown> = {}): boolean {
  if (!name.startsWith('Get-')) return false;
  return !Object.keys(parameters).some((k) => LOCAL_FILE_PARAMS.has(k.toLowerCase()));
}

const SELECT_RE = /^[A-Za-z][A-Za-z0-9_.]*$/;

/** Property names for Select-Object; plain names only, never expressions. */
export function validateSelect(v: unknown): string[] | undefined {
  if (v === undefined) return undefined;
  const ok = Array.isArray(v) && v.length > 0 && v.length <= 50
    && v.every((x) => typeof x === 'string' && x.length <= 100 && SELECT_RE.test(x));
  if (!ok) throw new BrokerError('invalid_parameters', 'Invalid parameters: select must be 1 to 50 plain property names');
  return v as string[];
}

export function validateFirst(v: unknown): number | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== 'number' || !Number.isInteger(v) || v < 1 || v > 1000) {
    throw new BrokerError('invalid_parameters', 'Invalid parameters: first must be a whole number from 1 to 1000');
  }
  return v;
}

const KEY_RE = /^[A-Za-z][A-Za-z0-9]*$/;

function isJsonValue(v: unknown, depth: number): boolean {
  if (depth > MAX_DEPTH) return false;
  if (v === null || typeof v === 'string' || typeof v === 'boolean') return true;
  if (typeof v === 'number') return Number.isFinite(v);
  if (Array.isArray(v)) return v.every((x) => isJsonValue(x, depth + 1));
  if (typeof v === 'object') {
    const proto = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return false;
    return Object.values(v as object).every((x) => isJsonValue(x, depth + 1));
  }
  return false;
}

export function validateParameters(p: unknown): Record<string, unknown> {
  const bad = (why: string): never => {
    throw new BrokerError('invalid_parameters', `Invalid parameters: ${why}`);
  };
  if (p === null || typeof p !== 'object' || Array.isArray(p)) return bad('must be an object');
  const proto = Object.getPrototypeOf(p);
  if (proto !== Object.prototype && proto !== null) return bad('must be a plain object');
  for (const [k, v] of Object.entries(p)) {
    if (!KEY_RE.test(k) || k.length > 100) return bad('parameter names must be letters and digits, starting with a letter');
    if (!isJsonValue(v, 0)) return bad('parameter values must be JSON (string, number, boolean, null, array, object)');
  }
  return p as Record<string, unknown>;
}
