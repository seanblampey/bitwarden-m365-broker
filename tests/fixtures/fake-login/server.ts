import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomBytes } from 'node:crypto';
import { totp } from '../../../src/crypto.js';

export interface FakeLoginOpts {
  username: string;
  password: string;
  seed: string;
  mfa?: 'totp' | 'push-default-totp-available' | 'push-only';
  wrongPassword?: boolean;
  consent?: boolean;
  federated?: boolean;
  kmsi?: boolean;
  /** AADSTS error returned to redirect_uri straight from /authorize. */
  error?: string;
  /** Serve a page none of the known selectors match. */
  unknownPage?: boolean;
  /** Extra accounts (username -> password) besides `username`. */
  users?: Record<string, string>;
  /** Echo a state that does not match the request's. */
  wrongState?: boolean;
}

export interface FakeLogin {
  url: string;
  close(): Promise<void>;
  acceptPosted: () => boolean;
  lastOtc: () => string | undefined;
  passwordPageViews: () => number;
}

interface Flow { redirectUri: string; hint: string; state: string; user?: string }

const page = (body: string) =>
  `<!doctype html><html><body>${body}</body></html>`;
const form = (flow: string, step: string, inner: string) =>
  `<form method="post" action="/login"><input type="hidden" name="flow" value="${flow}"><input type="hidden" name="step" value="${step}">${inner}</form>`;

async function body(req: IncomingMessage): Promise<URLSearchParams> {
  let s = '';
  for await (const c of req) s += c;
  return new URLSearchParams(s);
}

export async function startFakeLogin(opts: FakeLoginOpts): Promise<FakeLogin> {
  const flows = new Map<string, Flow>();
  let accepted = false;
  let otc: string | undefined;
  let pwViews = 0;
  let port = 0;

  const send = (res: ServerResponse, html: string, headers: Record<string, string> = {}) => {
    res.writeHead(200, { 'content-type': 'text/html', ...headers });
    res.end(html);
  };
  const redirect = (res: ServerResponse, to: string, headers: Record<string, string> = {}) => {
    res.writeHead(302, { location: to, ...headers });
    res.end();
  };
  const accounts: Record<string, string> = { [opts.username]: opts.password, ...opts.users };
  const state = (f: Flow) => (opts.wrongState ? 'not-the-state' : f.state);
  /** Code is `CODE-<base64url(user)>-<random>` so tests can tell whose session produced it. */
  let sessionUsers: string[] = [];
  const finish = (res: ServerResponse, f: Flow) => {
    const user = f.user ?? '';
    sessionUsers = [...new Set([...sessionUsers, user])];
    const q = new URLSearchParams({ code: `CODE-${Buffer.from(user).toString('base64url')}-${randomBytes(6).toString('hex')}`, state: state(f) });
    redirect(res, `${f.redirectUri}?${q}`, { 'set-cookie': `fakesession=${encodeURIComponent(sessionUsers.join(','))}; Path=/; HttpOnly` });
  };

  const passwordPage = (id: string, error: boolean) => {
    pwViews++;
    return page(form(id, 'password',
      `${error ? '<div id="passwordError">Your account or password is incorrect.</div>' : ''}<input name="passwd" type="password"><input type="submit" id="idSIButton9" value="Sign in">`));
  };
  const otcPage = (id: string) =>
    page(form(id, 'otc', '<input name="otc"><input type="submit" id="idSubmit_SAOTCC_Continue" value="Verify">'));
  const afterMfa = (res: ServerResponse, id: string, f: Flow) => {
    if (opts.kmsi) return send(res, page(form(id, 'kmsi',
      '<input type="checkbox" id="KmsiCheckboxField"><button type="submit" name="kmsi" value="no" id="idBtn_Back">No</button><button type="submit" name="kmsi" value="yes" id="idSIButton9">Yes</button>')));
    afterKmsi(res, id, f);
  };
  const afterKmsi = (res: ServerResponse, id: string, f: Flow) => {
    if (opts.consent) return redirect(res, `/Consent/Set?flow=${id}`);
    finish(res, f);
  };

  const server = createServer(async (req, res) => {
    const u = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
    const cookie = req.headers.cookie ?? '';
    const path = u.pathname;

    if (req.method === 'GET' && /\/oauth2\/v2\.0\/authorize$/.test(path)) {
      const f: Flow = { redirectUri: u.searchParams.get('redirect_uri') ?? '', hint: u.searchParams.get('login_hint') ?? '', state: u.searchParams.get('state') ?? '' };
      if (opts.error) {
        const q = new URLSearchParams({ error: 'access_denied', error_description: `${opts.error}: blocked for ${f.hint}`, state: state(f) });
        return redirect(res, `${f.redirectUri}?${q}`);
      }
      if (opts.federated) return redirect(res, `http://localhost:${port}/adfs/ls`);
      if (opts.unknownPage) return send(res, page('<h1>Something new</h1><p>Unrecognised page.</p>'));
      const id = randomBytes(8).toString('hex');
      flows.set(id, f);
      const session = decodeURIComponent(/fakesession=([^;]*)/.exec(cookie)?.[1] ?? '').split(',').filter(Boolean);
      // Without prompt an existing session is used silently: the hinted account if signed in,
      // otherwise (pessimistically) the first signed-in account. With prompt=select_account and
      // any session, real Entra shows "Pick an account" (signed-in tiles plus "Use another account"),
      // even when the hinted account is not among them; the login page appears only with no session.
      if (session.length && u.searchParams.get('prompt') !== 'select_account') {
        f.user = session.includes(f.hint) ? f.hint : session[0];
        return finish(res, f);
      }
      if (session.length) {
        const tiles = session.map((s) => `<button type="submit" name="pick" value="${s}" data-test-id="${s}">${s}</button>`).join('');
        return send(res, page(form(id, 'pick', `${tiles}<div id="otherTile">Use another account</div>`)));
      }
      return send(res, page(form(id, 'user', '<input name="loginfmt" type="email"><input type="submit" id="idSIButton9" value="Next">')));
    }
    if (req.method === 'GET' && path === '/adfs/ls') return send(res, page('<form><input name="UserName"><input name="Password" type="password"></form>'));
    if (req.method === 'GET' && path === '/Consent/Set') {
      const id = u.searchParams.get('flow') ?? '';
      return send(res, page(`<h1 id="consentHeader">Permissions requested</h1><form method="post" action="/consent/accept"><input type="hidden" name="flow" value="${id}"><input type="submit" id="idBtn_Accept" value="Accept"></form>`));
    }
    if (req.method === 'POST' && path === '/consent/accept') {
      accepted = true;
      const f = flows.get((await body(req)).get('flow') ?? '');
      return f ? finish(res, f) : send(res, page('gone'));
    }
    if (req.method === 'GET' && path === '/proofs') {
      const id = u.searchParams.get('flow') ?? '';
      const otp = opts.mfa === 'push-default-totp-available'
        ? `<button type="submit" name="method" value="otp" data-value="PhoneAppOTP">Use a verification code</button>` : '';
      return send(res, page(form(id, 'proof', `<button type="submit" name="method" value="push" data-value="PhoneAppNotification">Approve a request</button>${otp}`)));
    }
    if (req.method === 'POST' && path === '/login') {
      const b = await body(req);
      const id = b.get('flow') ?? '';
      const f = flows.get(id);
      if (!f) return send(res, page('unknown flow'));
      switch (b.get('step')) {
        case 'user':
          if (!(b.get('loginfmt')! in accounts)) return send(res, page('<div id="usernameError">No account.</div>'));
          f.user = b.get('loginfmt')!;
          return send(res, passwordPage(id, false));
        case 'password':
          if (opts.wrongPassword || !f.user || b.get('passwd') !== accounts[f.user]) return send(res, passwordPage(id, true));
          if ((opts.mfa ?? 'totp') === 'totp') return send(res, otcPage(id));
          return send(res, page(`<div id="idDiv_SAOTCAS_Title">Approve sign in request</div><a id="signInAnotherWay" href="/proofs?flow=${id}">I can't use my Microsoft Authenticator app right now</a>`));
        case 'proof':
          if (b.get('method') === 'otp' && opts.mfa === 'push-default-totp-available') return send(res, otcPage(id));
          return send(res, page('<p>Waiting for approval...</p>'));
        case 'otc': {
          otc = b.get('otc') ?? undefined;
          const now = Date.now();
          if (otc !== totp(opts.seed, now) && otc !== totp(opts.seed, now - 30_000)) return send(res, page('<div id="idSpan_SAOTCC_Error_OTC">Wrong code</div>'));
          return afterMfa(res, id, f);
        }
        case 'kmsi':
          return afterKmsi(res, id, f);
        case 'pick':
          f.user = b.get('pick') ?? '';
          return finish(res, f);
      }
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((r) => { server.closeAllConnections(); server.close(() => r()); }),
    acceptPosted: () => accepted,
    lastOtc: () => otc,
    passwordPageViews: () => pwViews,
  };
}
