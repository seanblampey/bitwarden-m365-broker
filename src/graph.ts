import { BrokerError } from './errors.js';
import { buildGraphUrl, type GraphMethod } from './classify.js';

const MAX_TEXT = 100 * 1024;

export interface GraphRequest {
  method: GraphMethod;
  path: string;
  body?: unknown;
  apiVersion: 'v1.0' | 'beta';
}

/** Sends a Graph request. The token only ever goes to https://graph.microsoft.com (buildGraphUrl). */
export async function graphRequest(
  fetchFn: typeof fetch,
  token: string,
  req: GraphRequest,
): Promise<{ status: number; body: unknown }> {
  const url = buildGraphUrl(req.path, req.apiVersion);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/json',
  };
  if (/\$count|\$search/.test(req.path)) headers['ConsistencyLevel'] = 'eventual';
  const init: RequestInit = { method: req.method, headers, redirect: 'manual' };
  if (req.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(req.body);
  }
  let res: Response;
  try {
    res = await fetchFn(url, init);
  } catch {
    throw new BrokerError('graph_failed', 'Could not reach Microsoft Graph.');
  }
  if (res.status >= 300 && res.status < 400) return { status: res.status, body: { redirected: true } };
  let text = '';
  try {
    text = await res.text();
  } catch {
    throw new BrokerError('graph_failed', 'Could not reach Microsoft Graph.');
  }
  if (text === '') return { status: res.status, body: null };
  try {
    return { status: res.status, body: JSON.parse(text) };
  } catch {
    return { status: res.status, body: text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text };
  }
}
