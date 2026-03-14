/**
 * crypto-utils.js
 * ───────────────
 * All cryptographic operations for VaultSync.
 * Runs entirely in the browser via the Web Crypto API.
 *
 * THIS FILE IS UNCHANGED from the original implementation.
 * Do not modify the crypto logic here.
 *
 * Security model:
 *   1. A random 256-bit Data Encryption Key (DEK) encrypts each file.
 *   2. A password-derived key (PBKDF2) wraps (encrypts) the DEK.
 *   3. Only the wrapped DEK and ciphertext are stored in the cloud.
 *   4. Plaintext and the raw DEK never leave the browser.
 */

const PBKDF2_ITERATIONS = 150_000;
const PBKDF2_HASH       = "SHA-256";
const SALT_BYTES        = 16;  // 128-bit salt
const IV_BYTES          = 12;  // 96-bit IV recommended for AES-GCM
const DEK_BITS          = 256; // AES-256

// ─────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function bufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary  = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBuffer(b64) {
  const binary = atob(b64);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─────────────────────────────────────────────
//  Key derivation (PBKDF2)
// ─────────────────────────────────────────────

async function importPasswordMaterial(password) {
  const enc = new TextEncoder();
  return crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
}

export async function deriveKeyFromPassword(password, salt) {
  const material = await importPasswordMaterial(password);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    material,
    { name: "AES-GCM", length: DEK_BITS },
    false,
    ["wrapKey", "unwrapKey"],
  );
}

// ─────────────────────────────────────────────
//  DEK generation & wrapping
// ─────────────────────────────────────────────

export async function generateDEK() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: DEK_BITS }, true, ["encrypt", "decrypt"]);
}

export async function wrapDEK(dek, wrappingKey, iv) {
  return crypto.subtle.wrapKey("raw", dek, wrappingKey, { name: "AES-GCM", iv });
}

export async function unwrapDEK(wrappedDEK, wrappingKey, iv) {
  return crypto.subtle.unwrapKey(
    "raw", wrappedDEK, wrappingKey,
    { name: "AES-GCM", iv },
    { name: "AES-GCM", length: DEK_BITS },
    false, ["encrypt", "decrypt"],
  );
}

// ─────────────────────────────────────────────
//  File encryption / decryption (AES-GCM)
// ─────────────────────────────────────────────

export async function encryptFile(plaintext, dek, iv) {
  return crypto.subtle.encrypt({ name: "AES-GCM", iv }, dek, plaintext);
}

export async function decryptFile(ciphertext, dek, iv) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, dek, ciphertext);
}

// ─────────────────────────────────────────────
//  High-level pipeline helpers
// ─────────────────────────────────────────────

/**
 * Full encryption pipeline for a single file.
 * @param {File}   file
 * @param {string} password
 * @returns {Promise<{ciphertext: ArrayBuffer, metadata: object}>}
 */
export async function encryptFileWithPassword(file, password) {
  const plaintext   = await file.arrayBuffer();
  const salt        = randomBytes(SALT_BYTES);
  const fileIV      = randomBytes(IV_BYTES);
  const dekIV       = randomBytes(IV_BYTES);
  const wrappingKey = await deriveKeyFromPassword(password, salt);
  const dek         = await generateDEK();
  const ciphertext  = await encryptFile(plaintext, dek, fileIV);
  const wrappedDEK  = await wrapDEK(dek, wrappingKey, dekIV);

  const metadata = {
    originalName: file.name,
    mimeType:     file.type || "application/octet-stream",
    salt:         bufferToBase64(salt),
    fileIV:       bufferToBase64(fileIV),
    dekIV:        bufferToBase64(dekIV),
    wrappedDEK:   bufferToBase64(wrappedDEK),
    size:         plaintext.byteLength,
    timestamp:    new Date().toISOString(),
  };

  return { ciphertext, metadata };
}

/**
 * Full decryption pipeline for a single file.
 * @param {ArrayBuffer} ciphertext
 * @param {object}      metadata
 * @param {string}      password
 * @returns {Promise<{plaintext: ArrayBuffer, name: string, mimeType: string}>}
 */
export async function decryptFileWithPassword(ciphertext, metadata, password) {
  const salt       = base64ToBuffer(metadata.salt);
  const fileIV     = base64ToBuffer(metadata.fileIV);
  const dekIV      = base64ToBuffer(metadata.dekIV);
  const wrappedDEK = base64ToBuffer(metadata.wrappedDEK);

  const wrappingKey = await deriveKeyFromPassword(password, salt);

  let dek;
  try {
    dek = await unwrapDEK(wrappedDEK, wrappingKey, dekIV);
  } catch {
    throw new Error("Incorrect password — unable to unwrap the encryption key.");
  }

  let plaintext;
  try {
    plaintext = await decryptFile(ciphertext, dek, fileIV);
  } catch {
    throw new Error("Decryption failed — the file may be corrupted or the wrong password was used.");
  }

  return { plaintext, name: metadata.originalName, mimeType: metadata.mimeType };
}
