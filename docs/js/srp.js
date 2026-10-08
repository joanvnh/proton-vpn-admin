/* Proton SRP-6a client (little-endian wire format).
 * Ported from ProtonMail/go-srp (MIT) for browsers / workers.
 * Only auth version 4 (current) is supported.
 */

// ---------------------------------------------------------------- helpers

function u8ToB64(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s);
}

function b64ToU8(b64) {
  const s = atob(b64.replace(/\s+/g, ''));
  const u8 = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
  return u8;
}

// little-endian bytes -> BigInt
function leToBig(u8) {
  let h = '';
  for (let i = u8.length - 1; i >= 0; i--) h += u8[i].toString(16).padStart(2, '0');
  return BigInt('0x' + h);
}

// BigInt -> little-endian bytes of fixed length
function bigToLe(n, len) {
  let h = n.toString(16);
  if (h.length > len * 2) throw new Error('srp: integer overflow');
  h = h.padStart(len * 2, '0');
  const u8 = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    u8[i] = parseInt(h.slice(h.length - 2 * (i + 1), h.length - 2 * i), 16);
  }
  return u8;
}

function concatBytes(...arrs) {
  let total = 0;
  for (const a of arrs) total += a.length;
  const out = new Uint8Array(total);
  let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}

function modPow(base, exp, mod) {
  let r = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

// expandHash: SHA-512(data||0) || SHA-512(data||1) || SHA-512(data||2) || SHA-512(data||3)
export async function expandHash(data) {
  const out = new Uint8Array(256);
  for (let i = 0; i < 4; i++) {
    const d = new Uint8Array(
      await crypto.subtle.digest('SHA-512', concatBytes(data, Uint8Array.of(i)))
    );
    out.set(d, i * 64);
  }
  return out;
}

// Proton's bcrypt base64 alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
const BCRYPT_B64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export function bcryptB64Encode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 3) {
    const b0 = u8[i], b1 = i + 1 < u8.length ? u8[i + 1] : 0, b2 = i + 2 < u8.length ? u8[i + 2] : 0;
    s += BCRYPT_B64[b0 >> 2];
    s += BCRYPT_B64[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < u8.length) s += BCRYPT_B64[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < u8.length) s += BCRYPT_B64[b2 & 63];
  }
  return s;
}

// hashPassword version 4: bcrypt(password, b64(salt||"proton")) then expandHash(crypted || modulus)
export async function hashPasswordV4(password, saltB64, modulusLe) {
  const salt = b64ToU8(saltB64); // 16 bytes
  const encSalt = bcryptB64Encode(
    concatBytes(salt, new TextEncoder().encode('proton')) // 22 bytes -> 30 chars
  );
  // bcryptjs is loaded globally as `bcrypt` (vendored)
  const crypted = bcrypt.hashSync(password, '$2y$10$' + encSalt);
  return expandHash(concatBytes(new TextEncoder().encode(crypted), modulusLe));
}

function randomSecret(N) {
  const nMinus1 = N - 1n;
  const bitLen = nMinus1.toString(2).length;
  const byteLen = Math.ceil(bitLen / 8);
  const excess = byteLen * 8 - bitLen;
  for (;;) {
    const u8 = new Uint8Array(byteLen);
    crypto.getRandomValues(u8);
    if (excess) u8[0] >>= excess; // big-endian top byte mask
    let h = '';
    for (const b of u8) h += b.toString(16).padStart(2, '0');
    const n = BigInt('0x' + h);
    if (n > 4096n && n < nMinus1) return n;
  }
}

/**
 * Compute SRP proofs.
 * @param {object} o - { password, saltB64, modulusB64, serverEphemeralB64, fixedA?, fixedXb64? }
 *   fixedXb64: test hook — base64 of the 256-byte little-endian x (skips password hashing)
 * @returns {Promise<{clientEphemeral, clientProof, expectedServerProof}>} base64 strings
 */
export async function srpProofs(o) {
  const modulusLe = b64ToU8(o.modulusB64);
  if (modulusLe.length !== 256) throw new Error('srp: bad modulus length');
  const N = leToBig(modulusLe);
  if (N.toString(2).length !== 2048 || N % 8n !== 3n) {
    throw new Error('srp: modulus failed sanity check');
  }
  const serverEph = b64ToU8(o.serverEphemeralB64);
  const bInt = leToBig(serverEph);
  if (!(bInt > 1n && bInt < N - 1n)) throw new Error('srp: server ephemeral out of bounds');

  const x = o.fixedXb64 !== undefined
    ? leToBig(b64ToU8(o.fixedXb64))
    : leToBig(await hashPasswordV4(o.password, o.saltB64, modulusLe));
  const k = leToBig(await expandHash(concatBytes(bigToLe(2n, 256), modulusLe))) % N;

  const a = o.fixedA !== undefined ? BigInt(o.fixedA) : randomSecret(N);
  const A = modPow(2n, a, N);
  const Abytes = bigToLe(A, 256);

  const u = leToBig(await expandHash(concatBytes(Abytes, serverEph)));
  if (u === 0n) throw new Error('srp: unlucky scramble, retry');

  const gx = modPow(2n, x, N);
  let base = (bInt - ((k * gx) % N)) % N;
  if (base < 0n) base += N;
  const exp = (u * x + a) % (N - 1n);
  const S = modPow(base, exp, N);
  const Sbytes = bigToLe(S, 256);

  const M1 = await expandHash(concatBytes(Abytes, serverEph, Sbytes));
  const M2 = await expandHash(concatBytes(Abytes, M1, Sbytes));

  return {
    clientEphemeral: u8ToB64(Abytes),
    clientProof: u8ToB64(M1),
    expectedServerProof: u8ToB64(M2),
  };
}

export const _test = { leToBig, bigToLe, u8ToB64, b64ToU8, modPow, concatBytes };
