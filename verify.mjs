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
  recoverWithKeyAndReset,
  getSharingPublicKey, unwrapSharingPrivateKey,
  unwrapFileDEK, wrapDEKForRecipient, unwrapSharedDEK, openFileWithSharedDEK, publicKeyFingerprint,
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

  console.log("\n── X25519 sharing ──");
  {
    let x25519Ok = true;
    try {
      const k = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
      await crypto.subtle.deriveBits({ name: "X25519", public: k.publicKey }, k.privateKey, 256);
    } catch { x25519Ok = false; }

    if (!x25519Ok) {
      console.log("  SKIP  X25519 ECDH not available in this runtime (works in browsers)");
    } else {
      const owner     = await createVault(PW);
      const recipient = await createVault("recipient password");
      const third     = await createVault("third party password");

      const sk = "shared_file_1";
      const file = makeFile(BODY, "shared report.pdf", "application/pdf");
      const { ciphertext, metadata } = await sealFileWithKey(file, owner.masterKey, sk);

      // owner wraps the file's DEK to the recipient's public key
      const dek   = await unwrapFileDEK(metadata, owner.masterKey);
      const share = await wrapDEKForRecipient(dek, getSharingPublicKey(recipient.keyvault));
      eq("share names the X25519 KEM suite", share.alg, "X25519-HKDF-SHA256-A256GCM");

      // recipient unwraps with their private key and decrypts
      const rPriv = await unwrapSharingPrivateKey(recipient.keyvault, recipient.masterKey);
      const rDEK  = await unwrapSharedDEK(share, rPriv);
      const out   = await openFileWithSharedDEK(ciphertext, metadata, rDEK, sk);
      eq("recipient gets the filename", out.name, "shared report.pdf");
      sameBytes(out.plaintext, BODY) ? ok("recipient decrypts the shared file") : bad("recipient decrypts the shared file");

      // a third party cannot unwrap the share
      const tPriv = await unwrapSharingPrivateKey(third.keyvault, third.masterKey);
      await expectThrow("third party can't unwrap the share", () => unwrapSharedDEK(share, tPriv));

      // tampered wrapped DEK is rejected
      const bad = { ...share, wrappedDEK: share.wrappedDEK.slice(0, -4) + "AAAA" };
      await expectThrow("tampered share rejected", () => unwrapSharedDEK(bad, rPriv));

      // fingerprints: stable + format
      const fp1 = await publicKeyFingerprint(getSharingPublicKey(recipient.keyvault));
      const fp2 = await publicKeyFingerprint(getSharingPublicKey(recipient.keyvault));
      eq("fingerprint is stable", fp1, fp2);
      (/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/.test(fp1))
        ? ok("fingerprint format AAAA-BBBB-CCCC-DDDD") : bad("fingerprint format", fp1);
    }
  }

  console.log("\n── recovery + password reset ──");
  {
    const { keyvault, recoveryKey } = await createVault(PW);
    const file = makeFile(BODY, "r.bin", "application/octet-stream");
    const sk = "rk";
    const { ciphertext, metadata } = await sealFileWithKey(file, (await unlockVault(keyvault, PW)).masterKey, sk);

    const NEWPW = "post-reset password #9";
    const { keyvault: updated, masterKey: sessionMK } =
      await recoverWithKeyAndReset(keyvault, recoveryKey, NEWPW);

    await expectThrow("recovered session key is non-extractable", () =>
      crypto.subtle.exportKey("raw", sessionMK));
    sameBytes((await openFileWithKey(ciphertext, metadata, sessionMK, sk)).plaintext, BODY)
      ? ok("recovered session key opens existing file") : bad("recovered session key opens existing file");

    const mkNew = (await unlockVault(updated, NEWPW)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mkNew, sk)).plaintext, BODY)
      ? ok("vault unlocks with the NEW password after recovery") : bad("vault unlocks with the NEW password after recovery");
    await expectThrow("old password no longer unlocks", () => unlockVault(updated, PW));

    // recovery key remains valid after the reset (recovery block unchanged)
    const mkRec = (await unlockVaultWithRecovery(updated, recoveryKey)).masterKey;
    sameBytes((await openFileWithKey(ciphertext, metadata, mkRec, sk)).plaintext, BODY)
      ? ok("same recovery key still works after reset") : bad("same recovery key still works after reset");

    await expectThrow("bad recovery key rejected on reset", () =>
      recoverWithKeyAndReset(keyvault, "AAAA-BBBB-CCCC-DDDD", NEWPW));

    const noRec = await createVault(PW, { withRecovery: false });
    await expectThrow("recovery-reset refused when no recovery configured", () =>
      recoverWithKeyAndReset(noRec.keyvault, recoveryKey, NEWPW));
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
