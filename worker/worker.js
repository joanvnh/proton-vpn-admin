/* Proton VPN admin — Cloudflare Worker backend (single file, dashboard-pasteable).
 *
 * What it does:
 *  - Validates Telegram Mini App initData (HMAC-SHA256 with the bot token) and
 *    only serves one Telegram user (OWNER_ID).
 *  - Holds Proton sessions (per account label) in KV; the SRP math itself runs
 *    in the Mini App frontend (the phone has no CPU limits; Workers free does).
 *  - Proxies the Proton API (api.proton.me) with the right headers, so the
 *    browser never hits CORS issues.
 *  - Caches the VPN server list for 10 minutes.
 *
 * Required bindings / secrets:
 *  - KV namespace bound as SESS
 *  - Secret BOT_TOKEN (Telegram bot token)
 *  - Var OWNER_ID (Telegram numeric user id, e.g. 775842719)
 *  - Var PAGES_ORIGIN (default https://joanvnh.github.io)
 */

const PROTON_API = 'https://vpn-api.proton.me';
const APP_VERSION = 'linux-vpn@4.13.1';
const USER_AGENT = 'ProtonVPN/4.13.1 (Linux; Ubuntu)';
const SERVER_CACHE_TTL = 10 * 60; // seconds

// ------------------------------------------------------------------ CORS

function corsHeaders(env, req) {
  const origin = req.headers.get('Origin') || '';
  const allowed = env.PAGES_ORIGIN || 'https://joanvnh.github.io';
  const h = {
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Telegram-Init-Data',
    'Access-Control-Max-Age': '86400',
  };
  if (origin === allowed) {
    h['Access-Control-Allow-Origin'] = allowed;
    h['Vary'] = 'Origin';
  }
  return h;
}

function json(data, status, env, req) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: Object.assign({ 'Content-Type': 'application/json' }, corsHeaders(env, req)),
  });
}

// ------------------------------------------------------- Telegram auth

async function validateInitData(initData, botToken) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    params.delete('hash');
    const keys = [...params.keys()].sort();
    const dataCheckString = keys.map((k) => k + '=' + params.get(k)).join('\n');
    const enc = new TextEncoder();
    const secretKey = await crypto.subtle.importKey(
      'raw', enc.encode('WebAppData'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const secret = await crypto.subtle.sign('HMAC', secretKey, enc.encode(botToken));
    const key = await crypto.subtle.importKey(
      'raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, enc.encode(dataCheckString));
    const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
    if (hex !== hash) return null;
    const authDate = parseInt(params.get('auth_date') || '0', 10);
    if (!authDate || Date.now() / 1000 - authDate > 86400) return null;
    const user = JSON.parse(params.get('user') || '{}');
    return user;
  } catch (e) {
    return null;
  }
}

// ------------------------------------------------------- Proton API

function protonHeaders(session) {
  const h = {
    'Content-Type': 'application/json',
    'x-pm-appversion': APP_VERSION,
    'User-Agent': USER_AGENT,
  };
  if (session) {
    h['Authorization'] = 'Bearer ' + session.accessToken;
    h['x-pm-uid'] = session.uid;
  }
  return h;
}

async function proton(path, opts, session) {
  opts = opts || {};
  const res = await fetch(PROTON_API + path, {
    method: opts.method || 'GET',
    headers: protonHeaders(session),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

function apiError(data, httpStatus) {
  const code = data && data.Code;
  const messages = {
    8002: 'Contraseña incorrecta.',
    9001: 'Proton pide verificación humana (captcha). Entra una vez a account.proton.me y reintenta.',
    9100: 'La sesión no tiene los permisos necesarios.',
    10013: 'Esta cuenta usa el modo legacy de 2 contraseñas, no soportado por la API.',
    5003: 'Versión de app rechazada por Proton.',
  };
  const base = messages[code] || (data && data.Error) || 'Error de la API de Proton.';
  // Always surface the raw code + HTTP status so failures are diagnosable
  const suffix = ' (código ' + (code || 0) + (httpStatus ? ', http ' + httpStatus : '') + ')';
  return {
    error: 'proton_error',
    code: code || 0,
    httpStatus: httpStatus || 0,
    message: messages[code] ? base : base + suffix,
  };
}

// Strip the PGP clearsign armor from the modulus, return raw base64 (or null)
function stripModulusArmor(signed) {
  if (!signed) return null;
  const m = signed.match(/\n\n([A-Za-z0-9+/=\r\n]+)\n-----BEGIN PGP SIGNATURE-----/);
  if (!m) return null;
  return m[1].replace(/\s+/g, '');
}

// ------------------------------------------------------- sessions

async function getSession(env, tgId, label) {
  return env.SESS.get('sess:' + tgId + ':' + label, 'json');
}

async function putSession(env, tgId, label, sess) {
  await env.SESS.put('sess:' + tgId + ':' + label, JSON.stringify(sess));
}

async function refreshSession(env, tgId, label) {
  const sess = await getSession(env, tgId, label);
  if (!sess || !sess.refreshToken) return null;
  const r = await proton('/auth/refresh', {
    method: 'POST',
    body: {
      ResponseType: 'token',
      GrantType: 'refresh_token',
      RefreshToken: sess.refreshToken,
      RedirectURI: 'http://protonmail.ch',
    },
  });
  if (r.data && (r.data.Code === 1000 || r.data.Code === 1001) && r.data.AccessToken) {
    const fresh = {
      uid: r.data.UID || sess.uid,
      accessToken: r.data.AccessToken,
      refreshToken: r.data.RefreshToken || sess.refreshToken,
      expiresAt: Date.now() + (r.data.ExpiresIn || 0) * 1000,
      scopes: r.data.Scopes || sess.scopes || [],
    };
    await putSession(env, tgId, label, fresh);
    return fresh;
  }
  return null;
}

// Returns a working session or null (caller answers 401 login_required)
async function ensureSession(env, tgId, label) {
  let sess = await getSession(env, tgId, label);
  if (sess && sess.expiresAt && sess.expiresAt - Date.now() > 5 * 60 * 1000) return sess;
  sess = await refreshSession(env, tgId, label);
  return sess;
}

// ------------------------------------------------------- router

async function handle(req, env) {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(env, req) });
  }

  if (path === '/api/health') {
    return json({ ok: true, ts: Date.now() }, 200, env, req);
  }

  // ---- auth gate for everything else ----
  const initData = req.headers.get('X-Telegram-Init-Data') || '';
  const tgUser = await validateInitData(initData, env.BOT_TOKEN || '');
  if (!tgUser || String(tgUser.id) !== String(env.OWNER_ID || '')) {
    return json({ error: 'unauthorized' }, 401, env, req);
  }
  const tgId = String(tgUser.id);

  const body = await req.json().catch(() => ({}));

  // ---- POST /api/auth/info : SRP parameters (no session needed) ----
  if (path === '/api/auth/info' && req.method === 'POST') {
    if (!body.username) return json({ error: 'missing_username' }, 400, env, req);
    const r = await proton('/core/v4/auth/info', {
      method: 'POST',
      body: { Username: body.username },
    });
    const d = r.data || {};
    if (d.Code !== 1000 && d.Code !== 1001) return json(apiError(d, r.status), 502, env, req);
    return json({
      version: d.Version,
      salt: d.Salt,
      modulus: stripModulusArmor(d.Modulus),
      serverEphemeral: d.ServerEphemeral,
      srpSession: d.SRPSession,
      twoFA: d['2FA'] || { Enabled: 0, TOTP: 0 },
    }, 200, env, req);
  }

  // ---- POST /api/auth : exchange SRP proofs for a session ----
  if (path === '/api/auth' && req.method === 'POST') {
    const { label, username, clientEphemeral, clientProof, srpSession, expectedServerProof, totp } = body;
    if (!label || !username || !clientEphemeral || !clientProof || !srpSession) {
      return json({ error: 'missing_fields' }, 400, env, req);
    }
    const authBody = {
      Username: username,
      ClientEphemeral: clientEphemeral,
      ClientProof: clientProof,
      SRPSession: srpSession,
    };
    if (totp) authBody.TwoFactorCode = totp;
    const r = await proton('/core/v4/auth', { method: 'POST', body: authBody });
    const d = r.data || {};
    if ((d.Code !== 1000 && d.Code !== 1001) || !d.AccessToken) {
      return json(apiError(d, r.status), 502, env, req);
    }
    if (d.ServerProof !== expectedServerProof) {
      return json({ error: 'server_proof_mismatch', message: 'El servidor no pasó la verificación.' }, 502, env, req);
    }
    const sess = {
      uid: d.UID,
      accessToken: d.AccessToken,
      refreshToken: d.RefreshToken,
      expiresAt: Date.now() + (d.ExpiresIn || 0) * 1000,
      scopes: d.Scopes || [],
    };
    await putSession(env, tgId, label, sess);
    return json({ ok: true, scopes: sess.scopes }, 200, env, req);
  }

  // ---- POST /api/session/refresh ----
  if (path === '/api/session/refresh' && req.method === 'POST') {
    const sess = await refreshSession(env, tgId, body.label);
    if (!sess) return json({ error: 'login_required' }, 401, env, req);
    return json({ ok: true, scopes: sess.scopes }, 200, env, req);
  }

  // ---- POST /api/session/drop : forget a session ----
  if (path === '/api/session/drop' && req.method === 'POST') {
    await env.SESS.delete('sess:' + tgId + ':' + body.label);
    return json({ ok: true }, 200, env, req);
  }

  // ---- from here on a working session is required ----
  const needSession = async (label) => {
    if (!label) return { err: json({ error: 'missing_label' }, 400, env, req) };
    const sess = await ensureSession(env, tgId, label);
    if (!sess) return { err: json({ error: 'login_required' }, 401, env, req) };
    return { sess };
  };

  // ---- GET /api/servers : cached logical server list ----
  if (path === '/api/servers' && req.method === 'GET') {
    const cached = await env.SESS.get('servers_cache', 'json');
    if (cached && Date.now() - cached.ts < SERVER_CACHE_TTL * 1000) {
      return json({ servers: cached.servers, cached: true }, 200, env, req);
    }
    const label = url.searchParams.get('label');
    const s = await needSession(label);
    if (s.err) return s.err;
    const r = await proton('/vpn/v1/logicals', {}, s.sess);
    const d = r.data || {};
    if ((d.Code !== 1000 && d.Code !== 1001) || !d.LogicalServers) {
      return json(apiError(d, r.status), 502, env, req);
    }
    await env.SESS.put('servers_cache', JSON.stringify({ ts: Date.now(), servers: d.LogicalServers }),
      { expirationTtl: SERVER_CACHE_TTL });
    return json({ servers: d.LogicalServers, cached: false }, 200, env, req);
  }

  // ---- GET /api/configs?label= : list persistent WireGuard configs ----
  if (path === '/api/configs' && req.method === 'GET') {
    const label = url.searchParams.get('label');
    const s = await needSession(label);
    if (s.err) return s.err;
    const all = [];
    let beginId = '';
    for (let page = 0; page < 20; page++) {
      let p = '/vpn/v1/certificate/all?Mode=persistent&Limit=50';
      if (beginId) p += '&BeginID=' + encodeURIComponent(beginId);
      const r = await proton(p, {}, s.sess);
      const d = r.data || {};
      if ((d.Code !== 1000 && d.Code !== 1001) || !d.Certificates) {
        return json(apiError(d, r.status), 502, env, req);
      }
      all.push(...d.Certificates);
      if (d.Certificates.length < 50) break;
      beginId = d.Certificates[d.Certificates.length - 1].SerialNumber;
    }
    return json({ configs: all }, 200, env, req);
  }

  // ---- POST /api/configs : create a persistent WireGuard config ----
  if (path === '/api/configs' && req.method === 'POST') {
    const s = await needSession(body.label);
    if (s.err) return s.err;
    const f = body.features || {};
    const certReq = {
      ClientPublicKey: body.clientPublicKeyPem,
      ClientPublicKeyMode: 'EC',
      Mode: 'persistent',
      DeviceName: body.deviceName || ('WireGuard-' + Date.now()),
      Duration: (body.durationMin || 525600) + ' min',
      Features: {
        NetShieldLevel: f.netShieldLevel || 0,
        RandomNAT: !!f.moderateNat,
        PortForwarding: !!f.portForwarding,
        SplitTCP: f.vpnAccelerator !== false,
      },
    };
    const r = await proton('/vpn/v1/certificate', { method: 'POST', body: certReq }, s.sess);
    const d = r.data || {};
    if ((d.Code !== 1000 && d.Code !== 1001) || !d.SerialNumber) {
      return json(apiError(d, r.status), 502, env, req);
    }
    return json({
      serialNumber: d.SerialNumber,
      deviceName: d.DeviceName,
      expirationTime: d.ExpirationTime,
      fingerprint: d.ClientKeyFingerprint,
      features: d.Features,
    }, 200, env, req);
  }

  // ---- DELETE /api/configs/:serial?label= : revoke a config ----
  const delMatch = path.match(/^\/api\/configs\/([^/]+)$/);
  if (delMatch && req.method === 'DELETE') {
    const label = url.searchParams.get('label');
    const s = await needSession(label);
    if (s.err) return s.err;
    const serial = decodeURIComponent(delMatch[1]);
    const r = await proton('/vpn/v1/certificate/' + encodeURIComponent(serial),
      { method: 'DELETE' }, s.sess);
    const d = r.data || {};
    if (d.Code !== 1000 && d.Code !== 1001) return json(apiError(d, r.status), 502, env, req);
    return json({ ok: true }, 200, env, req);
  }

  return json({ error: 'not_found' }, 404, env, req);
}

export default {
  async fetch(req, env) {
    try {
      return await handle(req, env);
    } catch (e) {
      return json({ error: 'worker_error', message: String((e && e.message) || e) }, 500, env, req);
    }
  },
};
