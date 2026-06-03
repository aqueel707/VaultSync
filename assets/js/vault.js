/**
 * vault.js
 * ────────
 * The session vault. Two jobs:
 *
 *   1. Persist the unlocked MASTER KEY across MPA page loads by storing it as a
 *      NON-EXTRACTABLE CryptoKey in IndexedDB. It survives navigation without
 *      re-running Argon2id, and its raw bytes can never be exported (even by
 *      injected script) — only used for wrap/unwrap/encrypt/decrypt.
 *
 *   2. Read/write the KEYVAULT (wrapped keys + public values only — never any
 *      plaintext secret) to the managed app bucket at users/<uid>/keyvault.json,
 *      so a user can unlock from any device. The keyvault lives in the app
 *      bucket regardless of the user's file-storage choice, because the master
 *      key must decrypt files in either bucket.
 *
 * Public API:
 *   provisionVault(uid, password, opts) → { recoveryKey }   (register / migrate)
 *   openVault(uid, password)            → unlocks + persists  (login)
 *   openVaultWithRecovery(uid, key)     → unlocks + persists  (recovery — Step 5)
 *   getMasterKey()                      → CryptoKey | null
 *   isUnlocked()                        → boolean
 *   hasVault(uid)                       → boolean
 *   lock()                              → clears the session key
 *   fetchKeyvault(uid)                  → keyvault | null
 */

import { supabase, BUCKET } from "./supabase-client.js";
import { createVault, unlockVault, unlockVaultWithRecovery, recoverWithKeyAndReset } from "./crypto-utils.js";
import { publishPublicKey } from "./directory.js";

// ─── IndexedDB: store one non-extractable CryptoKey across pages ────────────

const DB_NAME = "vaultsync";
const STORE   = "session";
const MK_ID   = "masterKey";

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

async function idbPut(key, value) {
  const db = await openDB();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).put(value, key);
      tx.oncomplete = resolve;
      tx.onerror    = () => reject(tx.error);
    });
  } finally { db.close(); }
}

async function idbGet(key) {
  const db = await openDB();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const r  = tx.objectStore(STORE).get(key);
      r.onsuccess = () => resolve(r.result ?? null);
      r.onerror   = () => reject(r.error);
    });
  } finally { db.close(); }
}

async function idbDel(key) {
  const db = await openDB();
  try {
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      tx.objectStore(STORE).delete(key);
      tx.oncomplete = resolve;
      tx.onerror    = () => reject(tx.error);
    });
  } finally { db.close(); }
}

// ─── Keyvault storage (managed app bucket — only wrapped keys live here) ────

const vaultPath = (uid) => `users/${uid}/keyvault.json`;

export async function fetchKeyvault(uid) {
  const { data, error } = await supabase.storage.from(BUCKET).download(vaultPath(uid));
  if (error || !data) return null;            // not provisioned yet
  try { return JSON.parse(await data.text()); } catch { return null; }
}

async function storeKeyvault(uid, keyvault) {
  const { error } = await supabase.storage.from(BUCKET).upload(
    vaultPath(uid),
    new Blob([JSON.stringify(keyvault)], { type: "application/json" }),
    { upsert: true },
  );
  if (error) throw new Error(`Failed to save keyvault: ${error.message}`);
}

export async function hasVault(uid) {
  return (await fetchKeyvault(uid)) !== null;
}

// Publish this user's public key to the directory. Non-fatal — sharing is
// optional and must never block sign-in.
async function publishDir(uid, email, keyvault) {
  try {
    const pk = keyvault?.sharing?.publicKey;
    if (pk && email) await publishPublicKey(uid, email, pk);
  } catch (e) {
    console.warn("Public-key directory publish failed:", e?.message);
  }
}

// ─── Session API ────────────────────────────────────────────────────────────

export async function getMasterKey() {
  return idbGet(MK_ID);
}

export async function isUnlocked() {
  return (await idbGet(MK_ID)) !== null;
}

export async function lock() {
  await idbDel(MK_ID);
}

/**
 * Create a fresh vault, store it, and persist the master key for this session.
 * Used at registration, and to migrate pre-vault accounts on first login.
 * @returns {{ recoveryKey: string | null }}
 */
export async function provisionVault(uid, email, password, { withRecovery = true } = {}) {
  const { keyvault, recoveryKey, masterKey } = await createVault(password, { withRecovery });
  await storeKeyvault(uid, keyvault);
  await idbPut(MK_ID, masterKey);
  await publishDir(uid, email, keyvault);
  return { recoveryKey };
}

/** Fetch + unlock the vault with the password, then persist the master key. */
export async function openVault(uid, email, password) {
  const keyvault = await fetchKeyvault(uid);
  if (!keyvault) throw new Error("NO_VAULT");
  const { masterKey } = await unlockVault(keyvault, password);  // throws "Incorrect password." on mismatch
  await idbPut(MK_ID, masterKey);
  await publishDir(uid, email, keyvault);
}

/** Fetch + unlock the vault with the recovery key, then persist the master key. */
export async function openVaultWithRecovery(uid, email, recoveryKey) {
  const keyvault = await fetchKeyvault(uid);
  if (!keyvault) throw new Error("NO_VAULT");
  const { masterKey } = await unlockVaultWithRecovery(keyvault, recoveryKey);
  await idbPut(MK_ID, masterKey);
  await publishDir(uid, email, keyvault);
}

/**
 * Recover access after a password reset: unlock with the recovery key, re-wrap
 * the master key under `newPassword`, save the updated keyvault, and persist the
 * session key. After this, normal password login works again.
 */
export async function recoverAccount(uid, email, recoveryKey, newPassword) {
  const keyvault = await fetchKeyvault(uid);
  if (!keyvault) throw new Error("NO_VAULT");
  const { keyvault: updated, masterKey } = await recoverWithKeyAndReset(keyvault, recoveryKey, newPassword);
  await storeKeyvault(uid, updated);
  await idbPut(MK_ID, masterKey);
  await publishDir(uid, email, updated);
}
