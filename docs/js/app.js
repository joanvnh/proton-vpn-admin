import { srpProofs } from './srp.js?v=1.0.8';

/* ============================== config ============================== */
const WORKER_URL = 'https://proton-vpn-admin.joanvnh.workers.dev'; // v1.0.1
const FEATURE_NAMES = { 1: 'SecureCore', 2: 'Tor', 4: 'P2P', 8: 'Streaming', 16: 'IPv6' };
const TIER_NAMES = { 0: 'Free', 2: 'Plus', 3: 'Visionary' };

/* ============================== state =============================== */
const S = {
  initData: '', tgUser: null,
  pinKey: null, accounts: [], activeLabel: null, theme: 'auto',
  servers: [], configs: [], createServer: null,
  regionNames: new Intl.DisplayNames(['es'], { type: 'region' }),
};

/* ============================== helpers ============================= */
const $ = (id) => document.getElementById(id);
function show(id) {
  document.querySelectorAll('.screen').forEach((el) => el.classList.add('hidden'));
  $(id).classList.remove('hidden');
  window.scrollTo(0, 0);
}
function toast(msg) {
  const t = $('toast');
  t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(t._h); t._h = setTimeout(() => t.classList.add('hidden'), 2200);
}
function showLoading(text) {
  $('loading-text').textContent = text || 'Cargando…';
  $('loading').classList.remove('hidden');
}
function hideLoading() { $('loading').classList.add('hidden'); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function b64(u8) {
  let s = ''; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}
function unb64(b64s) {
  const s = atob(b64s.replace(/\s+/g, ''));
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}
function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' });
}
function countryName(code) {
  try { return S.regionNames.of(code) || code; } catch (e) { return code; }
}
function loadColor(pct) {
  return pct < 50 ? '#4caf50' : pct < 80 ? '#ff9800' : '#f44336';
}

/* ============================== modal =============================== */
function modal(title, bodyHTML, buttons) {
  // buttons: [{label, cls, onClick(close)}]
  $('modal-title').textContent = title;
  $('modal-body').innerHTML = bodyHTML;
  const box = $('modal-btns'); box.innerHTML = '';
  const close = () => $('modal').classList.add('hidden');
  for (const b of buttons) {
    const btn = document.createElement('button');
    btn.className = 'btn ' + (b.cls || '');
    btn.textContent = b.label;
    btn.onclick = () => b.onClick(close);
    box.appendChild(btn);
  }
  $('modal').classList.remove('hidden');
}
function modalInput(title, fields, okLabel) {
  // fields: [{id, label, type, placeholder}]
  return new Promise((resolve) => {
    const body = fields.map((f) =>
      '<label>' + esc(f.label) + '<input id="m-' + f.id + '" type="' + (f.type || 'text') +
      '" placeholder="' + esc(f.placeholder || '') + '"></label>').join('');
    modal(title, body, [
      { label: 'Cancelar', onClick: (c) => { c(); resolve(null); } },
      {
        label: okLabel || 'Aceptar', cls: 'primary',
        onClick: (c) => {
          const vals = {};
          for (const f of fields) vals[f.id] = $('m-' + f.id).value;
          c(); resolve(vals);
        },
      },
    ]);
  });
}

/* ============================== professional errors ================= */
function showError(title, userMsg, technical) {
  // Professional in-app error notification with optional email report.
  const tech = technical || userMsg;
  const body =
    '<div class="center error-modal"><div class="error-icon">⚠️</div>' +
    '<p>' + esc(userMsg) + '</p></div>' +
    (technical ? '<div class="error-detail">' + esc(tech) + '</div>' : '');
  modal('❌ ' + title, body, [
    { label: 'Cerrar', onClick: (c) => c() },
    {
      label: '📧 Enviar reporte', cls: 'primary',
      onClick: (c) => {
        c();
        const subject = encodeURIComponent('[Proton VPN Admin] Error: ' + title);
        const bodyTxt = encodeURIComponent(
          'Reporte de error — Proton VPN Admin\n' +
          'Fecha: ' + new Date().toISOString() + '\n' +
          'Cuenta: ' + (S.activeLabel || '(ninguna)') + '\n' +
          'Usuario Telegram: ' + (S.tgUser && S.tgUser.id ? S.tgUser.id : '?') + '\n' +
          'App v1.0.8\n\n' +
          'Mensaje: ' + userMsg + '\n\n' +
          'Detalle técnico:\n' + tech + '\n');
        window.open('mailto:joanvnh@gmail.com?subject=' + subject + '&body=' + bodyTxt, '_blank');
        toast('Abriendo tu app de correo…');
      },
    },
  ]);
}

/* ============================== CloudStorage ======================== */
function tg() { return window.Telegram && Telegram.WebApp ? Telegram.WebApp : null; }
function csGetItems(keys) {
  return new Promise((resolve, reject) => {
    tg().CloudStorage.getItems(keys, (err, vals) => err ? reject(new Error(err)) : resolve(vals || {}));
  });
}
function csSetItem(k, v) {
  return new Promise((resolve, reject) => {
    tg().CloudStorage.setItem(k, v, (err, ok) => err || !ok ? reject(new Error(err || 'cs')) : resolve());
  });
}
function csRemoveItem(k) {
  return new Promise((resolve) => tg().CloudStorage.removeItem(k, () => resolve()));
}

/* ============================== PIN vault ========================= */
async function getPinKey(pin, saltB64) {
  const salt = unb64(saltB64);
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 150000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function vaultEncrypt(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.pinKey,
    new TextEncoder().encode(JSON.stringify(obj)));
  return JSON.stringify({ iv: b64(iv), data: b64(new Uint8Array(data)) });
}
async function vaultDecrypt(blob) {
  const o = JSON.parse(blob);
  const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, S.pinKey, unb64(o.data));
  return JSON.parse(new TextDecoder().decode(data));
}
async function loadAccounts() {
  const vals = await csGetItems(['pv_accounts']);
  const labels = JSON.parse(vals.pv_accounts || '[]');
  S.accounts = [];
  for (const label of labels) {
    const v = await csGetItems(['pv_acct_' + label]);
    if (!v['pv_acct_' + label]) continue;
    const dec = await vaultDecrypt(v['pv_acct_' + label]);
    S.accounts.push({ label, username: dec.username });
  }
}
async function saveAccount(label, username, password) {
  const blob = await vaultEncrypt({ username, password });
  await csSetItem('pv_acct_' + label, blob);
  const labels = S.accounts.map((a) => a.label);
  if (!labels.includes(label)) labels.push(label);
  await csSetItem('pv_accounts', JSON.stringify(labels));
  await loadAccounts();
}
async function getAccountSecret(label) {
  const v = await csGetItems(['pv_acct_' + label]);
  if (!v['pv_acct_' + label]) return null;
  return vaultDecrypt(v['pv_acct_' + label]);
}
async function deleteAccount(label) {
  await csRemoveItem('pv_acct_' + label);
  await csRemoveItem('pv_cfgidx_' + label).catch(() => {});
  // remove stored .confs for this account
  try {
    const vals = await csGetItems(['pv_conflist_' + label]);
    const serials = JSON.parse(vals['pv_conflist_' + label] || '[]');
    for (const s of serials) await csRemoveItem('pv_conf_' + label + '_' + s).catch(() => {});
    await csRemoveItem('pv_conflist_' + label).catch(() => {});
  } catch (e) {}
  try { await api('/api/session/drop', { method: 'POST', body: { label } }); } catch (e) {}
  const labels = S.accounts.map((a) => a.label).filter((l) => l !== label);
  await csSetItem('pv_accounts', JSON.stringify(labels));
  await loadAccounts();
}

/* ============================== API client ======================== */
async function api(path, opts) {
  opts = opts || {};
  const res = await fetch(WORKER_URL + path, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'X-Telegram-Init-Data': S.initData },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

/* ============================== login =============================== */
async function ensureLogin(label) {
  // Fast path: is there already a working session?
  const probe = await api('/api/configs?label=' + encodeURIComponent(label));
  if (probe.status === 200) return true;
  if (!(probe.status === 401 && probe.data.error === 'login_required')) {
    throw new Error(probe.data.message || 'Error de sesión');
  }
  // Full SRP login from the phone
  const sec = await getAccountSecret(label);
  if (!sec) throw new Error('No hay credenciales guardadas para esta cuenta.');
  showLoading('Obteniendo parámetros SRP…');
  try {
    const info = await api('/api/auth/info', { method: 'POST', body: { username: sec.username } });
    if (info.status !== 200) throw new Error(info.data.message || 'Falló /auth/info');
    const twoFA = info.data.twoFA || {};
    let totp = null;
    if (twoFA.Enabled && twoFA.TOTP) {
      hideLoading();
      const v = await modalInput('Verificación en 2 pasos', [
        { id: 'code', label: 'Código de tu app autenticadora', type: 'text', placeholder: '123456' },
      ], 'Continuar');
      if (!v || !v.code) throw new Error('Login cancelado');
      totp = v.code.trim();
      showLoading('Verificando…');
    } else {
      showLoading('Calculando pruebas SRP…');
    }
    const proofs = await srpProofs({
      password: sec.password,
      saltB64: info.data.salt,
      modulusB64: info.data.modulus,
      serverEphemeralB64: info.data.serverEphemeral,
    });
    showLoading('Verificando con Proton…');
    const auth = await api('/api/auth', {
      method: 'POST',
      body: {
        label, username: sec.username,
        clientEphemeral: proofs.clientEphemeral,
        clientProof: proofs.clientProof,
        srpSession: info.data.srpSession,
        expectedServerProof: proofs.expectedServerProof,
        totp,
      },
    });
    if (auth.status !== 200) throw new Error(auth.data.message || 'Falló el login');
    return true;
  } finally {
    hideLoading();
  }
}

/* ============================== accounts screen ===================== */
function renderAccounts() {
  const list = $('acct-list');
  list.innerHTML = '';
  if (!S.accounts.length) {
    list.innerHTML = '<div class="item empty"><div class="empty-icon">👤</div><div class="s">Aún no hay cuentas.<br>Añade la primera abajo.</div></div>';
  }
  for (const a of S.accounts) {
    const div = document.createElement('div');
    div.className = 'item account-card';
    div.innerHTML = '<div class="t">👤 ' + esc(a.label) + '</div><div class="s">✉️ ' + esc(a.username) + '</div>' +
      '<div class="row"><button class="btn primary" data-open>▶️ Abrir</button>' +
      '<button class="btn danger" data-del>🗑️ Eliminar</button></div>';
    div.querySelector('[data-open]').onclick = () => openAccount(a.label);
    div.querySelector('[data-del]').onclick = () => confirmDeleteAccount(a.label);
    list.appendChild(div);
  }
}

function confirmDeleteAccount(label) {
  modal('🗑️ Eliminar cuenta',
    '<p>Se borrará <b>' + esc(label) + '</b> de la bóveda y su sesión del servidor. ¿Seguro?</p>',
    [
      { label: 'Cancelar', onClick: (c) => c() },
      {
        label: '🗑️ Eliminar', cls: 'danger',
        onClick: async (c) => {
          c(); await deleteAccount(label); renderAccounts(); toast('Cuenta eliminada');
        },
      },
    ]);
}

function clearAccountCache() {
  // Reset ALL account-specific state so no data leaks between accounts.
  // Called before loading a different account's data.
  S.configs = [];
  S.servers = [];
  S.createServer = null;
  S.lastConf = null;
  S.lastConfName = null;
  // Clear rendered lists immediately
  $('cfg-list').innerHTML = '';
  $('srv-list').innerHTML = '';
}

async function openAccount(label) {
  if (S.activeLabel === label) return; // already on this account
  clearAccountCache();
  S.activeLabel = label;
  $('main-title').textContent = '🔑 ' + label;
  show('scr-main');
  renderAccountSwitcher();
  renderConfigs(); // shows empty state while loading
  showLoading('Cargando datos de ' + label + '…');
  try {
    await refreshConfigs();
  } finally {
    hideLoading();
  }
}

/* ============================== theme =============================== */
async function loadTheme() {
  try {
    const vals = await csGetItems(['pv_theme']);
    applyTheme(vals.pv_theme || 'auto');
  } catch (e) { applyTheme('auto'); }
}
function applyTheme(mode) {
  // mode: 'auto' | 'light' | 'dark'
  const root = document.documentElement;
  if (mode === 'auto') root.removeAttribute('data-theme');
  else root.setAttribute('data-theme', mode);
  S.theme = mode;
  const icon = mode === 'dark' ? '☀️' : '🌙';
  const b1 = $('btn-theme'), b2 = $('btn-theme2');
  if (b1) b1.textContent = icon;
  if (b2) b2.textContent = icon;
  try { tg().CloudStorage.setItem('pv_theme', mode, () => {}); } catch (e) {}
}
function cycleTheme() {
  const next = S.theme === 'light' ? 'dark' : S.theme === 'dark' ? 'auto' : 'light';
  applyTheme(next);
  toast(next === 'auto' ? 'Tema: automático (Telegram)' : next === 'light' ? 'Tema: claro' : 'Tema: oscuro');
}

/* ============================== account switcher ==================== */
function renderAccountSwitcher() {
  const label = S.activeLabel;
  $('acct-current-label').textContent = label || '—';
  const dd = $('acct-dropdown');
  dd.innerHTML = '';
  dd.classList.add('hidden');
  for (const a of S.accounts) {
    const b = document.createElement('button');
    b.className = 'acct-option';
    const active = a.label === label;
    b.innerHTML = '<span class="pv-logo"></span><span>' + esc(a.label) +
      '<span class="sub">' + esc(a.username) + '</span></span>' +
      (active ? '<span class="check">✓</span>' : '');
    if (!active) b.onclick = () => { dd.classList.add('hidden'); openAccount(a.label); };
    dd.appendChild(b);
  }
}
function toggleAccountDropdown() {
  $('acct-dropdown').classList.toggle('hidden');
}

/* ============================== servers ============================= */
function featureBadges(features) {
  let h = '';
  for (const bit of [1, 2, 4, 8, 16]) {
    if (features & bit) h += '<span class="badge">' + FEATURE_NAMES[bit] + '</span>';
  }
  return h;
}

async function loadServers() {
  const r = await api('/api/servers?label=' + encodeURIComponent(S.activeLabel));
  if (r.status === 401 && r.data.error === 'login_required') {
    await ensureLogin(S.activeLabel);
    return loadServers();
  }
  if (r.status !== 200) throw new Error(r.data.message || 'No se pudo cargar servidores');
  S.servers = r.data.servers || [];
}

function renderServers() {
  // Simplified: top 4 least-loaded FREE (Tier 0) servers in the USA
  const list = $('srv-list');
  list.innerHTML = '';
  const us = S.servers.filter((s) =>
    s.Status === 1 && (s.ExitCountry || '').toUpperCase() === 'US' && (s.Tier || 0) === 0);
  us.sort((a, b) => (a.Load || 999) - (b.Load || 999));
  const top = us.slice(0, 4);
  if (!top.length) {
    list.innerHTML = '<div class="item empty"><div class="empty-icon">🖥️</div><div class="s">No hay servidores gratuitos de EE.UU. disponibles.</div></div>';
    return;
  }
  const h = document.createElement('div');
  h.className = 'country';
  h.textContent = '🇺🇸 Estados Unidos · gratuitos · top 4 por menor carga';
  list.appendChild(h);
  for (const s of top) {
    const online = (s.Servers || []).filter((p) => p.Status === 1);
    if (!online.length) continue;
    const div = document.createElement('div');
    div.className = 'item server-card';
    div.innerHTML =
      '<div class="t">🖥️ ' + esc(s.Name) + ' <span class="badge">' + esc(TIER_NAMES[s.Tier] || s.Tier) + '</span></div>' +
      '<div class="s">📍 ' + esc(s.City || '') + ' · 📊 score ' + Number(s.Score).toFixed(1) + '</div>' +
      '<div>' + featureBadges(s.Features) + '</div>' +
      '<div class="loadbar"><div style="width:' + s.Load + '%;background:' + loadColor(s.Load) + '"></div></div>' +
      '<div class="s">📶 Carga: ' + s.Load + '%</div>';
    div.onclick = () => startCreate(s);
    list.appendChild(div);
  }
  if (list.children.length <= 1) list.innerHTML = '<div class="item empty"><div class="empty-icon">🔍</div><div class="s">Sin resultados.</div></div>';
}

/* ============================== create ============================== */
function getPlatform() {
  const el = document.querySelector('#f-platform input[name="platform"]:checked');
  return el ? el.value : 'Android';
}

function startCreate(server) {
  S.createServer = server;
  const online = (server.Servers || []).filter((p) => p.Status === 1);
  S.createServer._phys = online.slice().sort((a, b) => a.EntryIP.localeCompare(b.EntryIP))[0];
  $('create-srv').innerHTML =
    '<b>' + esc(server.Name) + '</b> · ' + esc(countryName(server.ExitCountry)) +
    '<br><span class="meta">Carga ' + server.Load + '% · ' + esc(S.createServer._phys.EntryIP) + '</span>';
  const plat = getPlatform().toLowerCase().replace(/[^a-z0-9]+/g, '');
  $('f-name').value = 'joan-' + plat + '-' + (server.ExitCountry || 'xx').toLowerCase() + '-' + Date.now().toString(36);
  $('create-err').textContent = '';
  show('scr-create');
}

function genKeypair() {
  // Ed25519 seed -> X25519 (same conversion as Proton's official clients)
  const seed = nacl.randomBytes(32);
  const ed = nacl.sign.keyPair.fromSeed(seed);
  const h = nacl.hash(seed);
  const xsk = h.slice(0, 32);
  xsk[0] &= 248; xsk[31] &= 127; xsk[31] |= 64;
  const derPrefix = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const der = new Uint8Array(derPrefix.length + ed.publicKey.length);
  der.set(derPrefix, 0); der.set(ed.publicKey, derPrefix.length);
  let pem = '-----BEGIN PUBLIC KEY-----\n';
  const b = b64(der);
  for (let i = 0; i < b.length; i += 64) pem += b.slice(i, i + 64) + '\n';
  pem += '-----END PUBLIC KEY-----\n';
  return { pem, xPrivB64: b64(xsk) };
}

function buildConf(server, phys, xPrivB64, deviceName, platform) {
  const meta = [
    '# ProtonVPN WireGuard — generado por Proton VPN Admin',
    '# Device: ' + deviceName,
    '# Platform: ' + (platform || '-'),
    '# Server: ' + server.Name + ' (' + countryName(server.ExitCountry) + ')',
    '# Load: ' + server.Load + '%',
    '',
  ].join('\n');
  return meta +
    '[Interface]\n' +
    'PrivateKey = ' + xPrivB64 + '\n' +
    'Address = 10.2.0.2/32\n' +
    'DNS = 10.2.0.1\n\n' +
    '[Peer]\n' +
    'PublicKey = ' + phys.X25519PublicKey + '\n' +
    'AllowedIPs = 0.0.0.0/0\n' +
    'Endpoint = ' + phys.EntryIP + ':51820\n';
}

async function doCreate() {
  const err = $('create-err');
  err.textContent = '';
  const btn = $('btn-create');
  btn.disabled = true;
  showLoading('Creando configuración…');
  try {
    const kp = genKeypair();
    const r = await api('/api/configs', {
      method: 'POST',
      body: {
        label: S.activeLabel,
        deviceName: $('f-name').value.trim() || undefined,
        durationMin: parseInt($('f-duration').value, 10),
        clientPublicKeyPem: kp.pem,
        features: {
          netShieldLevel: parseInt($('f-netshield').value, 10),
          moderateNat: $('f-nat').checked,
          portForwarding: $('f-pf').checked,
          vpnAccelerator: $('f-acc').checked,
        },
      },
    });
    if (r.status === 401 && r.data.error === 'login_required') {
      await ensureLogin(S.activeLabel);
      btn.disabled = false;
      return doCreate();
    }
    if (r.status !== 200) throw new Error(r.data.message || 'No se pudo crear');
    const platform = getPlatform();
    const conf = buildConf(S.createServer, S.createServer._phys, kp.xPrivB64, r.data.deviceName, platform);
    S.lastConf = conf;
    S.lastConfName = (r.data.deviceName || 'proton').replace(/[^a-zA-Z0-9._-]+/g, '_') + '.conf';
    $('result-meta').textContent =
      r.data.deviceName + ' · expira ' + fmtDate(r.data.expirationTime) +
      ' · ' + S.createServer.Name;
    $('result-conf').textContent = conf;
    $('qr-box').classList.add('hidden');
    // remember which server this cert was made for (cert list doesn't say)
    // and store the .conf ENCRYPTED so it can be downloaded / QR'd later
    try {
      const idx = JSON.parse((await csGetItems(['pv_cfgidx_' + S.activeLabel]))['pv_cfgidx_' + S.activeLabel] || '{}');
      idx[r.data.serialNumber] = S.createServer.Name + ' · ' + countryName(S.createServer.ExitCountry);
      await csSetItem('pv_cfgidx_' + S.activeLabel, JSON.stringify(idx));
      const encConf = await vaultEncrypt({ conf, name: S.lastConfName });
      await csSetItem('pv_conf_' + S.activeLabel + '_' + r.data.serialNumber, encConf);
      const clKey = 'pv_conflist_' + S.activeLabel;
      const clVals = await csGetItems([clKey]);
      const clList = JSON.parse(clVals[clKey] || '[]');
      if (!clList.includes(r.data.serialNumber)) {
        clList.push(r.data.serialNumber);
        await csSetItem(clKey, JSON.stringify(clList));
      }
    } catch (e) {}
    show('scr-result');
    await refreshConfigs(true);
  } catch (e) {
    err.textContent = e.message;
  } finally {
    btn.disabled = false;
    hideLoading();
  }
}

/* ============================== configs ============================= */
async function refreshConfigs(silent) {
  try {
    const r = await api('/api/configs?label=' + encodeURIComponent(S.activeLabel));
    if (r.status === 401 && r.data.error === 'login_required') {
      await ensureLogin(S.activeLabel);
      return refreshConfigs(silent);
    }
    if (r.status !== 200) throw new Error(r.data.message || 'Error');
    S.configs = r.data.configs || [];
    renderConfigs();
  } catch (e) {
    if (!silent) {
      const tech = 'refreshConfigs(' + S.activeLabel + '): ' + e.message +
        (e.stack ? '\n' + String(e.stack).split('\n').slice(0, 3).join('\n') : '');
      showError('Error al cargar', e.message, tech);
    }
  }
}

async function renderConfigs() {
  const list = $('cfg-list');
  let idx = {};
  try {
    idx = JSON.parse((await csGetItems(['pv_cfgidx_' + S.activeLabel]))['pv_cfgidx_' + S.activeLabel] || '{}');
  } catch (e) {}
  list.innerHTML = '';
  if (!S.configs.length) {
    list.innerHTML = '<div class="item empty"><div class="empty-icon">🔑</div><div class="s">No hay configuraciones WireGuard en esta cuenta.<br>Toca <b>➕ Nueva config</b> para crear una.</div></div>';
    return;
  }
  const sorted = S.configs.slice().sort((a, b) => (b.ExpirationTime || 0) - (a.ExpirationTime || 0));
  for (const c of sorted) {
    const div = document.createElement('div');
    div.className = 'item config-card';
    const fp = (c.ClientKeyFingerprint || '').replace(/=+$/, '').slice(0, 12);
    div.innerHTML =
      '<div class="t">🔑 ' + esc(c.DeviceName || '(sin nombre)') + '</div>' +
      '<div class="s">🖥️ ' + esc(idx[c.SerialNumber] || 'servidor no registrado') +
      ' · 📅 expira ' + fmtDate(c.ExpirationTime) + '<br>🔒 huella ' + esc(fp) + '…</div>' +
      '<div class="row">' +
      '<button class="btn" data-dl>⬇️</button>' +
      '<button class="btn" data-qr>📷</button>' +
      '<button class="btn danger" data-del>🗑️ Eliminar</button></div>';
    div.querySelector('[data-del]').onclick = () => confirmDeleteConfig(c);
    div.querySelector('[data-dl]').onclick = () => downloadStoredConfig(c);
    div.querySelector('[data-qr]').onclick = () => qrStoredConfig(c);
    list.appendChild(div);
  }
}

async function getStoredConf(serial) {
  // Returns {conf, name} or null if not stored (e.g. created outside the app)
  try {
    const key = 'pv_conf_' + S.activeLabel + '_' + serial;
    const vals = await csGetItems([key]);
    if (!vals[key]) return null;
    return await vaultDecrypt(vals[key]);
  } catch (e) { return null; }
}

async function downloadStoredConfig(c) {
  showLoading('Preparando descarga…');
  try {
    const stored = await getStoredConf(c.SerialNumber);
    if (!stored) {
      showError('Config no disponible',
        'Esta configuración fue creada fuera de la app y no tenemos su clave privada guardada.',
        'serial=' + c.SerialNumber + ' — sin pv_conf_* en CloudStorage');
      return;
    }
    const blob = new Blob([stored.conf], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = stored.name || 'proton.conf';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    toast('Descargado');
  } finally { hideLoading(); }
}

async function qrStoredConfig(c) {
  showLoading('Generando QR…');
  try {
    const stored = await getStoredConf(c.SerialNumber);
    if (!stored) {
      showError('Config no disponible',
        'Esta configuración fue creada fuera de la app y no tenemos su clave privada guardada.',
        'serial=' + c.SerialNumber + ' — sin pv_conf_* en CloudStorage');
      return;
    }
    const qr = qrcode(0, 'L');
    qr.addData(stored.conf);
    qr.make();
    modal('📷 ' + (c.DeviceName || 'QR'),
      '<div class="center">' + qr.createSvgTag({ cellSize: 4, margin: 8, scalable: true }) +
      '<p class="meta">Escanea con tu app WireGuard</p></div>',
      [{ label: 'Cerrar', onClick: (x) => x() }]);
  } finally { hideLoading(); }
}

function confirmDeleteConfig(c) {
  modal('🗑️ Eliminar configuración',
    '<p>Se revocará <b>🔑 ' + esc(c.DeviceName || c.SerialNumber) + '</b> en Proton. Esta acción no se puede deshacer.</p>',
    [
      { label: 'Cancelar', onClick: (c2) => c2() },
      {
        label: '🗑️ Eliminar', cls: 'danger',
        onClick: async (c2) => {
          c2();
          try {
            const r = await api('/api/configs/' + encodeURIComponent(c.SerialNumber) +
              '?label=' + encodeURIComponent(S.activeLabel), { method: 'DELETE' });
            if (r.status === 401 && r.data.error === 'login_required') {
              await ensureLogin(S.activeLabel);
              return confirmDeleteConfig(c);
            }
            if (r.status !== 200) throw new Error(r.data.message || 'No se pudo eliminar');
            toast('Configuración eliminada');
            await refreshConfigs(true);
          } catch (e) { toast('Error: ' + e.message); }
        },
      },
    ]);
}

/* ============================== boot ================================ */
function wireUI() {
  $('pin-ok').onclick = unlock;
  $('pin-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  $('add-acct').onclick = async () => {
    const label = $('new-label').value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const username = $('new-user').value.trim();
    const password = $('new-pass').value;
    $('acct-err').textContent = '';
    if (!label || !username || !password) { $('acct-err').textContent = 'Completa los tres campos.'; return; }
    try {
      await saveAccount(label, username, password);
      $('new-label').value = ''; $('new-user').value = ''; $('new-pass').value = '';
      renderAccounts(); toast('Cuenta guardada');
    } catch (e) { $('acct-err').textContent = e.message; }
  };
  $('back-accounts').onclick = () => { show('scr-accounts'); };
  $('btn-new').onclick = async () => {
    try {
      showLoading('Cargando servidores…');
      await loadServers();
      renderServers();
      show('scr-servers');
    } catch (e) { toast('Error: ' + e.message); }
    finally { hideLoading(); }
  };
  $('btn-refresh').onclick = () => refreshConfigs();
  $('acct-current').onclick = toggleAccountDropdown;
  const bt1 = $('btn-theme'), bt2 = $('btn-theme2');
  if (bt1) bt1.onclick = cycleTheme;
  if (bt2) bt2.onclick = cycleTheme;
  // close dropdown when tapping elsewhere
  document.addEventListener('click', (e) => {
    const dd = $('acct-dropdown');
    if (!dd || dd.classList.contains('hidden')) return;
    if (!e.target.closest('.acct-switcher')) dd.classList.add('hidden');
  });
  $('back-main1').onclick = () => show('scr-main');
  $('back-servers').onclick = () => show('scr-servers');
  $('back-main2').onclick = () => show('scr-main');
  $('btn-create').onclick = doCreate;
  $('btn-copy').onclick = async () => {
    try { await navigator.clipboard.writeText(S.lastConf); toast('Copiado'); }
    catch (e) { toast('No se pudo copiar'); }
  };
  $('btn-dl').onclick = () => {
    const blob = new Blob([S.lastConf], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = S.lastConfName || 'proton.conf';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  };
  $('btn-qr').onclick = () => {
    const box = $('qr-box');
    if (!box.classList.contains('hidden')) { box.classList.add('hidden'); return; }
    const qr = qrcode(0, 'L');
    qr.addData(S.lastConf);
    qr.make();
    box.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 8, scalable: true });
    box.classList.remove('hidden');
  };
  const w = tg();
  if (w) {
    w.BackButton.onClick(() => {
      if (!$('scr-result').classList.contains('hidden')) show('scr-main');
      else if (!$('scr-create').classList.contains('hidden')) show('scr-servers');
      else if (!$('scr-servers').classList.contains('hidden')) show('scr-main');
      else if (!$('scr-main').classList.contains('hidden')) show('scr-accounts');
    });
  }
}

async function unlock() {
  const pin = $('pin-input').value;
  $('pin-err').textContent = '';
  if (pin.length < 4) { $('pin-err').textContent = 'El PIN debe tener al menos 4 caracteres.'; return; }
  try {
    const vals = await csGetItems(['pv_salt']);
    let saltB64 = vals.pv_salt;
    if (!saltB64) {
      // first run: create vault
      const salt = crypto.getRandomValues(new Uint8Array(16));
      saltB64 = b64(salt);
      await csSetItem('pv_salt', saltB64);
    }
    const key = await getPinKey(pin, saltB64);
    // verify: try decrypting a known canary
    const cvals = await csGetItems(['pv_canary']);
    if (cvals.pv_canary) {
      const testKey = key;
      const o = JSON.parse(cvals.pv_canary);
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(o.iv) }, testKey, unb64(o.data));
    } else {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key,
        new TextEncoder().encode('canary'));
      await csSetItem('pv_canary', JSON.stringify({ iv: b64(iv), data: b64(new Uint8Array(data)) }));
    }
    S.pinKey = key;
    $('pin-input').value = '';
    await loadAccounts();
    renderAccounts();
    show('scr-accounts');
  } catch (e) {
    $('pin-err').textContent = 'PIN incorrecto o bóveda dañada.';
  }
}

(function boot() {
  const w = tg();
  if (!w) {
    document.body.innerHTML = '<div style="padding:40px;text-align:center">' +
      'Esta app solo funciona dentro de Telegram.</div>';
    return;
  }
  S.initData = w.initData || '';
  try { S.tgUser = JSON.parse(new URLSearchParams(S.initData).get('user') || '{}'); } catch (e) {}
  w.ready();
  w.expand();
  wireUI();
  loadTheme();
  // health check (no auth needed)
  fetch(WORKER_URL + '/api/health').catch(() => {});
  show('scr-pin');
  $('pin-input').focus();
})();
