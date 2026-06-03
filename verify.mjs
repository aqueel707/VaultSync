/**
 * verify.mjs — crypto-utils.js test harness
 * Run:  npm i hash-wasm && node verify.mjs
 *
 * Exercises the real module (Argon2id + envelope + vault). The only
 * environment difference vs the browser is how "hash-wasm" resolves:
 * here via node_modules, in the browser via the <script type="importmap">.
 */

import {
  sealFileWithPassword, openFileWithPassword,
  sealFileWithKey, openFileWithKey, openMetadataWithKey,
  createVault, unlockVault, unlockVaultWithRecovery, changePassword,
  getSharingPublicKey, unwrapSharingPrivateKey,
  encryptFileWithPassword,
} from "./assets/js/crypto-utils.js";

let pass = 0, fail = 0;
const ok  = (n) => { pass++; console.log(`  PASS  ${n}`); };
const bad = (n, e) => { fail++; console.log(`  FAIL  ${n}${e ? "  → " + e : ""}`); };

async function expectThrow(name, fn) {
  try { await fn(); bad(name, "expected an error, none thrown"); }
  catch { ok(name); }
}
function eq(name, a, b) { a === b ? ok(name) : bad(name, `${a} !== ${b}`); }

// Minimal File stand-in: seal* only needs name, type, arrayBuffer().
function makeFile(bytes, name, type) {
  const u8 = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
  return { name, type, size: u8.byteLength, arrayBuffer: async () => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength) };
}
const sameBytes = (a, b) => {
  const x = new Uint8Array(a), y = new Uint8Array(b);
  if (x.length !== y.length) return false;
  for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return false;
  return true;
};

const PW   = "correct horse battery staple";
const BODY = crypto.getRandomValues(new Uint8Array(4096));

async function run() {
  console.log("\n── password-mode (local export) ──");
  {
    const file = makeFile(BODY, "secret report.pdf", "application/pdf");
    const { ciphertext, metadata } = await sealFileWithPassword(file, PW);

    eq("metadata is versioned v2", metadata.v, 2);
    eq("mode is password", metadata.mode, "password");
    eq("filename NOT in plaintext metadata", metadata.originalName, undefined);
    eq("kdf recorded as argon2id", metadata.kdf.algo, "argon2id");

    const out = await openFileWithPassword(ciphertext, metadata, PW);
    eq("round-trip filename", out.name, "secret report.pdf");
    eq("round-trip mimetype", out.mimeType, "application/pdf");
    sameBytes(out.plaintext, BODY) ? ok("round-trip body matches") : bad("round-trip body matches");

    await expectThrow("wrong password rejected", () =>
      openFileWithPassword(ciphertext, metadata, "wrong password"));

    // tamper: flip one ciphertext byte → GCM tag must fail
    const t = new Uint8Array(ciphertext.slice(0)); t[0] ^= 0x01;
    await expectThrow("ciphertext bit-flip rejected", () =>
      openFileWithPassword(t.buffer, metadata, PW));

    // tamper: change fileId → AAD changes → metadata auth must fail
    await expectThrow("AAD/fileId tamper rejected", () =>
      openFileWithPassword(ciphertext, { ...metadata, fileId: "ZZZZ" }, PW));
  }

  console.log("\n── key-mode (cloud / master key) ──");
  {
    const masterKey = (await createVault(PW)).masterKey;
    const file = makeFile(BODY, "photo.png", "image/png");
    const storageKey = "1717_abc123";
    const { ciphertext, metadata } = await sealFileWithKey(file, masterKey, storageKey);

    eq("filename NOT in plaintext metadata", metadata.originalName, undefined);

    const out = await openFileWithKey(ciphertext, metadata, masterKey, storageKey);
    eq("round-trip filename", out.name, "photo.png");
    sameBytes(out.plaintext, BODY) ? ok("round-trip body matches") : bad("round-trip body matches");

    const meta = await openMetadataWithKey(metadata, masterKey, storageKey);
    eq("metadata-only decrypt (for listing)", meta.originalName, "photo.png");

    // relocation attack: same blob opened under a different storageKey → AAD mismatch
    await expectThrow("wrong storageKey (relocation) rejected", () =>
      openFileWithKey(ciphertext, metadata, masterKey, "9999_other"));

    // different vault's master key cannot open it
    const otherMK = (await createVault("another password")).masterKey;
    await expectThrow("foreign master key rejected", () =>
      openFileWithKey(ciphertext, metadata, otherMK, storageKey));
  }

  console.log("\n── vault lifecycle ──");
  {
    const { keyvault, recoveryKey, masterKey } = await createVault(PW);
    console.log(`     (recovery key sample: ${recoveryKey})`);

    // file sealed under the original master key
    const file = makeFile(BODY, "vault.bin", "application/octet-stream");
    const sk = "key1";
    const { ciphertext, metadata } = await sealFileWithKey(file, masterKey, sk);

    // unlock with password → must open the same file
    const mk2 = (await unlockVault(keyvault, PW)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mk2, sk)).plaintext, BODY)
      ? ok("unlock(password) yields working master key") : bad("unlock(password) yields working master key");

    await expectThrow("unlock with wrong password rejected", () =>
      unlockVault(keyvault, "nope"));

    // unlock with recovery key → must also open the same file
    const mk3 = (await unlockVaultWithRecovery(keyvault, recoveryKey)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mk3, sk)).plaintext, BODY)
      ? ok("unlock(recovery) yields working master key") : bad("unlock(recovery) yields working master key");

    await expectThrow("bogus recovery key rejected", () =>
      unlockVaultWithRecovery(keyvault, "AAAA-BBBB-CCCC-DDDD"));

    // change password: old files still open under the NEW password, no re-encryption
    const NEWPW = "a brand new passphrase!";
    const rotated = await changePassword(keyvault, PW, NEWPW);
    const mk4 = (await unlockVault(rotated, NEWPW)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mk4, sk)).plaintext, BODY)
      ? ok("changePassword: file opens under new password (no re-encrypt)") : bad("changePassword: file opens under new password");
    await expectThrow("old password rejected after rotation", () =>
      unlockVault(rotated, PW));

    // recovery survives password rotation (same master key underneath)
    const mk5 = (await unlockVaultWithRecovery(rotated, recoveryKey)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mk5, sk)).plaintext, BODY)
      ? ok("recovery key still valid after password change") : bad("recovery key still valid after password change");

    // sharing keypair (X25519) — environment-dependent
    const pub = getSharingPublicKey(keyvault);
    if (pub) {
      ok("X25519 sharing public key present");
      try { await unwrapSharingPrivateKey(keyvault, mk2); ok("sharing private key unwraps with master key"); }
      catch (e) { bad("sharing private key unwraps with master key", e.message); }
    } else {
      console.log("  SKIP  X25519 not available in this runtime (browser will provide it)");
    }
  }

  console.log("\n── master-key hardening & recovery toggle ──");
  {
    const { keyvault, recoveryKey, masterKey } = await createVault(PW);
    await expectThrow("session master key is non-extractable", () =>
      crypto.subtle.exportKey("raw", masterKey));
    recoveryKey ? ok("recovery key issued when enabled") : bad("recovery key issued when enabled");

    const noRec = await createVault(PW, { withRecovery: false });
    eq("no recovery key returned when opted out", noRec.recoveryKey, null);
    eq("no recovery block in keyvault when opted out", noRec.keyvault.recovery, null);
    await unlockVault(noRec.keyvault, PW);                 // must not throw
    ok("opt-out vault still unlocks with password");
    await expectThrow("recovery unlock refused on opt-out vault", () =>
      unlockVaultWithRecovery(noRec.keyvault, "AAAA-BBBB-CCCC-DDDD"));

    // a non-extractable session key can still seal/open files
    const file = makeFile(BODY, "x.bin", "application/octet-stream");
    const { ciphertext, metadata } = await sealFileWithKey(file, masterKey, "k");
    sameBytes((await openFileWithKey(ciphertext, metadata, masterKey, "k")).plaintext, BODY)
      ? ok("non-extractable session key seals & opens files") : bad("non-extractable session key seals & opens files");
  }

  console.log("\n── legacy v1 back-compat (cloud interim) ──");
  {
    const file = makeFile(BODY, "old-file.txt", "text/plain");
    const { ciphertext, metadata } = await encryptFileWithPassword(file, PW);
    eq("v1 writes plaintext metadata (originalName present)", metadata.originalName, "old-file.txt");
    const out = await openFileWithPassword(ciphertext, metadata, PW);
    eq("v2 reader opens v1 file (filename)", out.name, "old-file.txt");
    sameBytes(out.plaintext, BODY) ? ok("v2 reader opens v1 file (body)") : bad("v2 reader opens v1 file (body)");
    await expectThrow("v1 wrong password rejected", () =>
      openFileWithPassword(ciphertext, metadata, "wrong"));
  }

  console.log(`\n──────── ${pass} passed, ${fail} failed ────────\n`);
  process.exit(fail ? 1 : 0);
}

run().catch((e) => { console.error("HARNESS ERROR:", e); process.exit(2); });
