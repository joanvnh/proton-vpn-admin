// Node verification of docs/js/srp.js against Go test vectors + Python reference.
import { createRequire } from 'module';
import { readFileSync } from 'fs';
const require = createRequire(import.meta.url);
const bcrypt = require('../docs/vendor/bcrypt.js');
globalThis.bcrypt = bcrypt;

const { srpProofs, expandHash, bcryptB64Encode, _test } = await import('../docs/js/srp.js');

let failures = 0;
function check(name, cond, extra = '') {
  console.log((cond ? 'PASS' : 'FAIL') + ' | ' + name + (extra ? ' | ' + extra : ''));
  if (!cond) failures++;
}

// --- 1. bcrypt vectors from ProtonMail/go-srp hash_test.go ---
const bcryptVectors = [
  ['PTTsDBs/mlLnSk6VmtFghe', '$2y$10$PTTsDBs/mlLnSk6VmtFgheNSiK/lSwtJsrBLLDK3kZYI7193nInqy'],
  ['4DZHd6WZX4fEaWKtCfYdde', '$2y$10$4DZHd6WZX4fEaWKtCfYddeZfcryISo9eEMgbA90O.Wnnz1s1VKmKC'],
  ['RpyeXO7K2eD3r/ZZ/B63V.', '$2y$10$RpyeXO7K2eD3r/ZZ/B63V.Tya53OExbyO8LR7TB93KYP4PvC.EPMW'],
  ['/.3KXCwRnsrxURMGxN7.R.', '$2y$10$/.3KXCwRnsrxURMGxN7.R.GLpVq0zyBbI9wgS0wB2U/g2btx1RYoy'],
];
for (const [salt, want] of bcryptVectors) {
  const got = bcrypt.hashSync('test!!!', '$2y$10$' + salt);
  check('bcrypt vector ' + salt.slice(0, 8), got === want, got.slice(0, 30));
}

// --- 2. expandHash + full chain vs Python reference ---
const ref = JSON.parse(readFileSync(new URL('./srp_ref.json', import.meta.url)));
const helloBytes = new TextEncoder().encode('hello');
const eh = await expandHash(helloBytes);
check('expandHash("hello") == python',
  Buffer.from(eh).toString('base64') === ref.expand_hash_hello);

const proofs = await srpProofs({
  modulusB64: ref.mod_b64,
  serverEphemeralB64: ref.srv_eph_b64,
  fixedXb64: ref.x_b64,
  fixedA: ref.a_dec,
});
check('A == python', proofs.clientEphemeral === ref.A);
check('M1 == python', proofs.clientProof === ref.M1);
check('M2 == python', proofs.expectedServerProof === ref.M2);

// --- 3. bcryptB64Encode sanity: 22 bytes -> 30 chars, alphabet check ---
const enc = bcryptB64Encode(new Uint8Array(22).fill(0xab));
check('bcryptB64Encode length/alphabet',
  enc.length === 30 && /^[./A-Za-z0-9]+$/.test(enc), enc);

console.log(failures === 0 ? '\nALL TESTS PASSED' : `\n${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
