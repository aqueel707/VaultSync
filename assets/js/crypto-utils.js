/**
 * crypto-utils.js  (v2)
 * ─────────────────────
 * All cryptographic operations for VaultSync.
 * Runs entirely in the browser via the Web Crypto API.
 *
 * What changed from v1:
 *   • KDF upgraded PBKDF2-SHA256(150k) → Argon2id (memory-hard, GPU-resistant).
 *   • Introduced a per-user MASTER KEY hierarchy:
 *         password ─Argon2id→ KEK ─wraps→ Master Key ─wraps→ per-file DEK
 *     so the password can be rotated without re-encrypting any files, and a
 *     recovery key can independently unwrap the Master Key.
 *   • File METADATA (name, type, size, time) is now ENCRYPTED, not plaintext.
 *   • Every envelope is bound with AES-GCM Additional Authenticated Data (AAD)
 *     so ciphertext/metadata cannot be swapped or relocated undetected.
 *   • Forward-compatible X25519 sharing keypair is provisioned in the vault.
 *   • A legacy reader still decrypts v1 (PBKDF2, plaintext-meta) files.
 *
 * hash-wasm is resolved via an import map (browser) / node_modules (tests):
 *     <script type="importmap">
 *       { "imports": { "hash-wasm": "https://cdn.jsdelivr.net/npm/hash-wasm@4.12.0/+esm" } }
 *     </script>
 * The import is lazy (inside deriveKEK) so the WASM only loads on first use.
 *
 * Security model:
 *   The server only ever stores ciphertext + wrapped keys + public values.
 *   Plaintext, the Master Key, and per-file DEKs never leave the browser.
 */

// ─────────────────────────────────────────────
//  Constants (versioned; persisted with data so they can change safely)
// ─────────────────────────────────────────────

export const FORMAT_VERSION = 2;

export const KDF_DEFAULTS = Object.freeze({
  v:           1,
  algo:        "argon2id",
  parallelism: 1,
  iterations:  3,        // time cost
  memorySize:  65536,    // KiB → 64 MiB
  hashLength:  32,       // bytes → 256-bit key
});

const IV_BYTES       = 12;  // 96-bit IV, recommended for AES-GCM
const SALT_BYTES     = 16;  // 128-bit KDF salt
const DEK_BITS       = 256; // AES-256
const RECOVERY_BYTES = 32;  // 256-bit recovery key (full entropy)

// ─────────────────────────────────────────────
//  Encoding helpers
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

const utf8       = (s) => new TextEncoder().encode(s);
const fromUtf8   = (b) => new TextDecoder().decode(b);

// ─────────────────────────────────────────────
//  Crockford base32 (recovery-key presentation)
//  Alphabet excludes I, L, O, U to avoid ambiguity. Dash is a safe separator.
// ─────────────────────────────────────────────

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function base32Encode(bytes) {
  let out = "", buffer = 0, bits = 0;
  for (const b of bytes) {
    buffer = ((buffer << 8) | b) >>> 0;
    bits += 8;
    while (bits >= 5) { bits -= 5; out += B32[(buffer >>> bits) & 31]; }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(buffer << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = str.toUpperCase()
    .replace(/O/g, "0").replace(/[IL]/g, "1").replace(/U/g, "V")
    .replace(/[^0-9A-Z]/g, "");
  let buffer = 0, bits = 0;
  const out = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) continue;
    buffer = ((buffer << 5) | v) >>> 0;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push((buffer >>> bits) & 0xff); buffer &= (1 << bits) - 1; }
  }
  return new Uint8Array(out);
}

function formatRecoveryKey(bytes) {
  return base32Encode(bytes).match(/.{1,4}/g).join("-");
}
function parseRecoveryKey(str) {
  return base32Decode(str);
}

// ─────────────────────────────────────────────
//  Key derivation — Argon2id → AES-GCM wrapping key (KEK)
// ─────────────────────────────────────────────

export async function deriveKEK(password, salt, params = KDF_DEFAULTS) {
  const { argon2id } = await import("hash-wasm");
  const raw = await argon2id({
    password:    typeof password === "string" ? utf8(password) : password,
    salt,
    parallelism: params.parallelism,
    iterations:  params.iterations,
    memorySize:  params.memorySize,
    hashLength:  params.hashLength,
    outputType:  "binary",
  });
  return crypto.subtle.importKey(
    "raw", raw, { name: "AES-GCM" }, false, ["wrapKey", "unwrapKey"],
  );
}

// ─────────────────────────────────────────────
//  Symmetric key helpers
// ─────────────────────────────────────────────

export async function generateMasterKey() {
  // extractable so it can be wrapped; held only in memory after unlock.
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: DEK_BITS }, true,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
  );
}

async function generateDEK() {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: DEK_BITS }, true, ["encrypt", "decrypt"],
  );
}

async function importWrappingKeyFromBytes(bytes) {
  return crypto.subtle.importKey(
    "raw", bytes, { name: "AES-GCM" }, false, ["wrapKey", "unwrapKey"],
  );
}

export async function wrapKeyWithKey(keyToWrap, wrappingKey, iv) {
  const wrapped = await crypto.subtle.wrapKey("raw", keyToWrap, wrappingKey, { name: "AES-GCM", iv });
  return new Uint8Array(wrapped);
}

async function unwrapDEK(wrapped, wrappingKey, iv) {
  return crypto.subtle.unwrapKey(
    "raw", wrapped, wrappingKey,
    { name: "AES-GCM", iv },
    { name: "AES-GCM", length: DEK_BITS },
    true, ["encrypt", "decrypt"],
  );
}

export async function unwrapMasterKey(wrapped, wrappingKey, iv, extractable = false) {
  // Session master keys are non-extractable: usable for wrap/unwrap/encrypt/
  // decrypt, but their raw bytes can't be exported — this shrinks the XSS
  // exfiltration surface. An extractable copy is materialised only transiently
  // during password rotation (changePassword).
  return crypto.subtle.unwrapKey(
    "raw", wrapped, wrappingKey,
    { name: "AES-GCM", iv },
    { name: "AES-GCM", length: DEK_BITS },
    extractable, ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
  );
}

// ─────────────────────────────────────────────
//  Envelope core — encrypt file + metadata under one DEK, bound by AAD
// ─────────────────────────────────────────────

async function sealWithDEK(plaintext, privateMeta, dek, aadString) {
  const aad    = utf8(aadString);
  const fileIV = randomBytes(IV_BYTES);
  const metaIV = randomBytes(IV_BYTES);

  const fileCipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: fileIV, additionalData: aad }, dek, plaintext,
  );
  const metaCipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: metaIV, additionalData: aad }, dek, utf8(JSON.stringify(privateMeta)),
  );

  return {
    ciphertext: fileCipher,                 // ArrayBuffer → the .enc payload
    fileIV:  bufferToBase64(fileIV),
    metaIV:  bufferToBase64(metaIV),
    encMeta: bufferToBase64(metaCipher),
  };
}

async function openWithDEK(ciphertext, meta, dek, aadString) {
  const aad = utf8(aadString);

  let privateMeta;
  try {
    const buf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuffer(meta.metaIV), additionalData: aad },
      dek, base64ToBuffer(meta.encMeta),
    );
    privateMeta = JSON.parse(fromUtf8(buf));
  } catch {
    throw new Error("Metadata authentication failed — the file may have been tampered with or mismatched.");
  }

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuffer(meta.fileIV), additionalData: aad },
      dek, ciphertext,
    );
  } catch {
    throw new Error("Decryption failed — the file may be corrupted or the wrong key was used.");
  }

  return { plaintext, name: privateMeta.originalName, mimeType: privateMeta.mimeType, metadata: privateMeta };
}

function buildPrivateMeta(file, byteLength) {
  return {
    originalName: file.name,
    mimeType:     file.type || "application/octet-stream",
    size:         byteLength,
    timestamp:    new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────
//  KEY-MODE pipeline  (cloud / account — sealed under the Master Key)
// ─────────────────────────────────────────────

/**
 * @param {File}       file
 * @param {CryptoKey}  masterKey   unlocked vault master key
 * @param {string}     storageKey  stable per-file id (also the storage path key)
 */
export async function sealFileWithKey(file, masterKey, storageKey) {
  const plaintext  = await file.arrayBuffer();
  const dek        = await generateDEK();
  const dekWrapIV  = randomBytes(IV_BYTES);
  const wrappedDEK = await wrapKeyWithKey(dek, masterKey, dekWrapIV);
  const aad        = `v${FORMAT_VERSION}|key|${storageKey}`;

  const sealed = await sealWithDEK(plaintext, buildPrivateMeta(file, plaintext.byteLength), dek, aad);

  const metadata = {
    v:          FORMAT_VERSION,
    mode:       "key",
    dekWrapIV:  bufferToBase64(dekWrapIV),
    wrappedDEK: bufferToBase64(wrappedDEK),
    fileIV:     sealed.fileIV,
    metaIV:     sealed.metaIV,
    encMeta:    sealed.encMeta,
  };
  return { ciphertext: sealed.ciphertext, metadata };
}

export async function openFileWithKey(ciphertext, metadata, masterKey, storageKey) {
  if (metadata.mode !== "key") throw new Error("Not a key-mode envelope.");
  const aad = `v${metadata.v}|key|${storageKey}`;

  let dek;
  try {
    dek = await unwrapDEK(base64ToBuffer(metadata.wrappedDEK), masterKey, base64ToBuffer(metadata.dekWrapIV));
  } catch {
    throw new Error("Could not unwrap the file key — vault key mismatch.");
  }
  return openWithDEK(ciphertext, metadata, dek, aad);
}

/**
 * Decrypt only the metadata (for listing) without decrypting the file body.
 * Returns the private metadata object: { originalName, mimeType, size, timestamp }.
 */
export async function openMetadataWithKey(metadata, masterKey, storageKey) {
  if (metadata.mode !== "key") throw new Error("Not a key-mode envelope.");
  const aad = `v${metadata.v}|key|${storageKey}`;
  let dek;
  try {
    dek = await unwrapDEK(base64ToBuffer(metadata.wrappedDEK), masterKey, base64ToBuffer(metadata.dekWrapIV));
  } catch {
    throw new Error("Could not unwrap the file key — vault key mismatch.");
  }
  try {
    const buf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuffer(metadata.metaIV), additionalData: utf8(aad) },
      dek, base64ToBuffer(metadata.encMeta),
    );
    return JSON.parse(fromUtf8(buf));
  } catch {
    throw new Error("Metadata authentication failed.");
  }
}

// ─────────────────────────────────────────────
//  STREAMING envelope (v3) — chunked AES-GCM for large files
//
//  The body is split into fixed-size segments, each encrypted under the same
//  DEK with a STRUCTURED 12-byte nonce:
//
//      nonce = noncePrefix(7) ‖ uint32_be(segmentIndex) ‖ lastFlag(1)
//
//  This is the "STREAM" online-AEAD construction: the per-segment index defeats
//  reordering, the last-segment flag defeats truncation, and a fresh random
//  prefix per file rules out cross-file nonce reuse. File-level binding (the
//  storage key) rides in the AAD, exactly like the v2 envelope. The encrypted
//  file metadata (encMeta) is byte-for-byte the v2 layout, so listing via
//  openMetadataWithKey works on a v3 envelope with no change.
//
//  These helpers take whole buffers today; the on-disk segment format is what a
//  true streaming reader/writer (next slice) will emit and consume verbatim.
// ─────────────────────────────────────────────

const STREAM_VERSION     = 3;
const STREAM_ALG         = "AES-256-GCM-STREAM";
const DEFAULT_SEGMENT    = 256 * 1024;   // 256 KiB plaintext per segment
const NONCE_PREFIX_BYTES = 7;
const GCM_TAG_BYTES      = 16;

function streamNonce(prefix, index, isLast) {
  const nonce = new Uint8Array(IV_BYTES);                                   // 12 bytes
  nonce.set(prefix, 0);                                                     // [0..6]
  new DataView(nonce.buffer).setUint32(NONCE_PREFIX_BYTES, index, false);   // [7..10] big-endian
  nonce[11] = isLast ? 1 : 0;                                               // [11]
  return nonce;
}

function concatChunks(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

async function streamEncryptBytes(bytes, dek, aadString, segmentSize, prefix) {
  const aad   = utf8(aadString);
  const total = Math.max(1, Math.ceil(bytes.length / segmentSize));   // ≥1 (covers empty file)
  const parts = [];
  for (let i = 0; i < total; i++) {
    const start  = i * segmentSize;
    const end    = Math.min(start + segmentSize, bytes.length);
    const isLast = i === total - 1;
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: streamNonce(prefix, i, isLast), additionalData: aad },
      dek, bytes.subarray(start, end),
    );
    parts.push(new Uint8Array(ct));
  }
  return { ciphertext: concatChunks(parts), totalSegments: total };
}

async function streamDecryptBytes(cipherBytes, dek, aadString, segmentSize, totalSegments, prefix) {
  const aad       = utf8(aadString);
  const ctSegment = segmentSize + GCM_TAG_BYTES;
  const out       = [];
  let   offset    = 0;
  for (let i = 0; i < totalSegments; i++) {
    const isLast    = i === totalSegments - 1;
    const remaining = cipherBytes.length - offset;
    const take      = isLast ? remaining : ctSegment;
    if (take <= 0 || take > remaining) throw new Error("Truncated or malformed stream.");
    let pt;
    try {
      pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: streamNonce(prefix, i, isLast), additionalData: aad },
        dek, cipherBytes.subarray(offset, offset + take),
      );
    } catch {
      throw new Error("Stream segment authentication failed (tampered or reordered).");
    }
    out.push(new Uint8Array(pt));
    offset += take;
  }
  if (offset !== cipherBytes.length) throw new Error("Unexpected trailing data after final segment.");
  return concatChunks(out);
}

/**
 * KEY-MODE streaming seal (cloud). Same DEK-wrapping + encMeta as v2; chunked body.
 * @returns {{ ciphertext: ArrayBuffer, metadata: object }}
 */
export async function sealFileStreamWithKey(file, masterKey, storageKey, { segmentSize = DEFAULT_SEGMENT } = {}) {
  const bytes     = new Uint8Array(await file.arrayBuffer());   // whole buffer for now
  const dek       = await generateDEK();
  const aadString = `v${STREAM_VERSION}|key|${storageKey}`;
  const prefix    = randomBytes(NONCE_PREFIX_BYTES);

  const { ciphertext, totalSegments } = await streamEncryptBytes(bytes, dek, aadString, segmentSize, prefix);

  // Encrypted file metadata — identical layout/AAD to v2.
  const metaIV   = randomBytes(IV_BYTES);
  const privMeta = buildPrivateMeta(file, file.size);
  const encMeta  = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: metaIV, additionalData: utf8(aadString) },
    dek, utf8(JSON.stringify(privMeta)),
  );

  const dekWrapIV  = randomBytes(IV_BYTES);
  const wrappedDEK = await wrapKeyWithKey(dek, masterKey, dekWrapIV);

  const metadata = {
    v:          STREAM_VERSION,
    mode:       "key",
    alg:        STREAM_ALG,
    dekWrapIV:  bufferToBase64(dekWrapIV),
    wrappedDEK: bufferToBase64(wrappedDEK),
    stream:     { noncePrefix: bufferToBase64(prefix), segmentSize, totalSegments },
    metaIV:     bufferToBase64(metaIV),
    encMeta:    bufferToBase64(new Uint8Array(encMeta)),
  };
  return { ciphertext: ciphertext.buffer, metadata };
}

/**
 * KEY-MODE streaming open (cloud). Verifies every segment; returns the full plaintext.
 * (A streaming variant that writes to disk incrementally lands in the next slice.)
 */
export async function openFileStreamWithKey(ciphertext, metadata, masterKey, storageKey) {
  if (metadata.mode !== "key" || metadata.alg !== STREAM_ALG) {
    throw new Error("Not a key-mode streaming envelope.");
  }
  const aadString = `v${metadata.v}|key|${storageKey}`;

  let dek;
  try {
    dek = await unwrapDEK(base64ToBuffer(metadata.wrappedDEK), masterKey, base64ToBuffer(metadata.dekWrapIV));
  } catch {
    throw new Error("Could not unwrap the file key — vault key mismatch.");
  }

  const { noncePrefix, segmentSize, totalSegments } = metadata.stream;
  const plaintext = await streamDecryptBytes(
    new Uint8Array(ciphertext), dek, aadString, segmentSize, totalSegments, base64ToBuffer(noncePrefix),
  );

  let meta;
  try {
    const buf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuffer(metadata.metaIV), additionalData: utf8(aadString) },
      dek, base64ToBuffer(metadata.encMeta),
    );
    meta = JSON.parse(fromUtf8(buf));
  } catch {
    throw new Error("Metadata authentication failed.");
  }

  return { plaintext, name: meta.originalName, mimeType: meta.mimeType, size: meta.size };
}

/**
 * Streaming decrypt — pulls ciphertext from a ReadableStream and hands each
 * decrypted segment to `onPlaintext`, so peak memory is ~one segment regardless
 * of file size. Used for large downloads written straight to disk.
 *
 * @param {ReadableStream<Uint8Array>} cipherStream
 * @param {object}    metadata    v3 key-mode envelope
 * @param {CryptoKey} masterKey
 * @param {string}    storageKey
 * @param {(chunk: Uint8Array) => (void | Promise<void>)} onPlaintext
 */
export async function decryptStreamToSink(cipherStream, metadata, masterKey, storageKey, onPlaintext) {
  if (metadata.mode !== "key" || metadata.alg !== STREAM_ALG) {
    throw new Error("Not a key-mode streaming envelope.");
  }
  const aad = utf8(`v${metadata.v}|key|${storageKey}`);

  let dek;
  try {
    dek = await unwrapDEK(base64ToBuffer(metadata.wrappedDEK), masterKey, base64ToBuffer(metadata.dekWrapIV));
  } catch {
    throw new Error("Could not unwrap the file key — vault key mismatch.");
  }

  const prefix    = base64ToBuffer(metadata.stream.noncePrefix);
  const segSize   = metadata.stream.segmentSize;
  const total     = metadata.stream.totalSegments;
  const ctSegment = segSize + GCM_TAG_BYTES;

  const reader = cipherStream.getReader();
  let buf  = new Uint8Array(0);
  let done = false;

  const pull = async () => {
    const { value, done: d } = await reader.read();
    if (d) { done = true; return; }
    const merged = new Uint8Array(buf.length + value.length);
    merged.set(buf, 0);
    merged.set(value, buf.length);
    buf = merged;
  };

  const decryptSeg = async (index, isLast, bytes) => {
    try {
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: streamNonce(prefix, index, isLast), additionalData: aad },
        dek, bytes,
      );
      return new Uint8Array(pt);
    } catch {
      throw new Error("Stream segment authentication failed (tampered, reordered, or truncated).");
    }
  };

  try {
    for (let i = 0; i < total; i++) {
      const isLast = i === total - 1;
      if (!isLast) {
        while (buf.length < ctSegment && !done) await pull();
        if (buf.length < ctSegment) throw new Error("Truncated stream (segment underflow).");
        await onPlaintext(await decryptSeg(i, false, buf.subarray(0, ctSegment)));
        buf = buf.slice(ctSegment);                 // drop consumed bytes
      } else {
        while (!done) await pull();                 // remaining bytes are the final segment
        await onPlaintext(await decryptSeg(i, true, buf));
        buf = new Uint8Array(0);
      }
    }
  } finally {
    try { reader.releaseLock(); } catch { /* ignore */ }
  }
}

// ─────────────────────────────────────────────
//  PASSWORD-MODE pipeline  (local export — self-contained, portable)
// ─────────────────────────────────────────────

export async function sealFileWithPassword(file, password, params = KDF_DEFAULTS) {
  const plaintext  = await file.arrayBuffer();
  const salt       = randomBytes(SALT_BYTES);
  const fileId     = bufferToBase64(randomBytes(12));
  const kek        = await deriveKEK(password, salt, params);
  const dek        = await generateDEK();
  const dekWrapIV  = randomBytes(IV_BYTES);
  const wrappedDEK = await wrapKeyWithKey(dek, kek, dekWrapIV);
  const aad        = `v${FORMAT_VERSION}|password|${fileId}`;

  const sealed = await sealWithDEK(plaintext, buildPrivateMeta(file, plaintext.byteLength), dek, aad);

  const metadata = {
    v:          FORMAT_VERSION,
    mode:       "password",
    kdf:        params,
    salt:       bufferToBase64(salt),
    fileId,
    dekWrapIV:  bufferToBase64(dekWrapIV),
    wrappedDEK: bufferToBase64(wrappedDEK),
    fileIV:     sealed.fileIV,
    metaIV:     sealed.metaIV,
    encMeta:    sealed.encMeta,
  };
  return { ciphertext: sealed.ciphertext, metadata };
}

export async function openFileWithPassword(ciphertext, metadata, password) {
  // Legacy v1 detection: no version field, or plaintext originalName present.
  if (!metadata.v || metadata.v === 1 || metadata.originalName !== undefined) {
    return openLegacyV1(ciphertext, metadata, password);
  }
  if (metadata.mode !== "password") throw new Error("Not a password-mode envelope.");

  const kek = await deriveKEK(password, base64ToBuffer(metadata.salt), metadata.kdf ?? KDF_DEFAULTS);
  const aad = `v${metadata.v}|password|${metadata.fileId}`;

  let dek;
  try {
    dek = await unwrapDEK(base64ToBuffer(metadata.wrappedDEK), kek, base64ToBuffer(metadata.dekWrapIV));
  } catch {
    throw new Error("Incorrect password — unable to unwrap the encryption key.");
  }
  return openWithDEK(ciphertext, metadata, dek, aad);
}

// ─────────────────────────────────────────────
//  Legacy v1 reader  (PBKDF2-SHA256 150k, plaintext metadata, no AAD)
//  Read-only: lets old files still decrypt. We never write this format.
// ─────────────────────────────────────────────

async function openLegacyV1(ciphertext, meta, password) {
  const salt     = base64ToBuffer(meta.salt);
  const material = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveKey"]);
  const kek      = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"],
  );

  let dek;
  try {
    dek = await crypto.subtle.unwrapKey(
      "raw", base64ToBuffer(meta.wrappedDEK), kek,
      { name: "AES-GCM", iv: base64ToBuffer(meta.dekIV) },
      { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"],
    );
  } catch {
    throw new Error("Incorrect password — unable to unwrap the encryption key (legacy file).");
  }

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBuffer(meta.fileIV) }, dek, ciphertext,
    );
  } catch {
    throw new Error("Decryption failed — the legacy file may be corrupted or the wrong password was used.");
  }

  return { plaintext, name: meta.originalName, mimeType: meta.mimeType, metadata: meta };
}

// ─────────────────────────────────────────────
//  Account vault — Master Key wrapped by password-KEK and recovery key
// ─────────────────────────────────────────────

/**
 * Create a fresh vault for a new account.
 * @returns {{ keyvault: object, recoveryKey: string, masterKey: CryptoKey }}
 *   keyvault    → safe to persist server-side (only wrapped keys + public values)
 *   recoveryKey → show ONCE to the user; never stored in plaintext anywhere
 *   masterKey   → hold in memory for this session
 */
export async function createVault(password, { params = KDF_DEFAULTS, withRecovery = true } = {}) {
  const salt      = randomBytes(SALT_BYTES);
  const kek       = await deriveKEK(password, salt, params);
  const masterKey = await generateMasterKey();   // extractable: needed to wrap below

  const mkWrapIV          = randomBytes(IV_BYTES);
  const wrappedMKPassword = await wrapKeyWithKey(masterKey, kek, mkWrapIV);

  // OPTIONAL recovery escrow. If the user opts out, the password becomes the
  // SOLE secret: no second wrapped copy of the master key exists anywhere, and
  // losing the password means the data is permanently unrecoverable (by design).
  let recovery = null, recoveryKey = null;
  if (withRecovery) {
    const recoveryBytes     = randomBytes(RECOVERY_BYTES);   // full entropy → direct wrapping key
    const recWrapKey        = await importWrappingKeyFromBytes(recoveryBytes);
    const recIV             = randomBytes(IV_BYTES);
    const wrappedMKRecovery = await wrapKeyWithKey(masterKey, recWrapKey, recIV);
    recovery    = { wrapIV: bufferToBase64(recIV), wrappedMK: bufferToBase64(wrappedMKRecovery) };
    recoveryKey = formatRecoveryKey(recoveryBytes);
  }

  // Forward-compatible X25519 sharing keypair. Degrades gracefully if the
  // browser lacks X25519 in Web Crypto (provisioned later on unlock instead).
  let sharing = null;
  try {
    const kp     = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const pubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    const privIV = randomBytes(IV_BYTES);
    const wrapped = new Uint8Array(
      await crypto.subtle.wrapKey("pkcs8", kp.privateKey, masterKey, { name: "AES-GCM", iv: privIV }),
    );
    sharing = {
      alg:        "X25519",
      publicKey:  bufferToBase64(pubRaw),
      privWrapIV: bufferToBase64(privIV),
      wrappedPriv: bufferToBase64(wrapped),
    };
  } catch (e) {
    console.warn("Sharing keypair not provisioned (X25519 unsupported here):", e?.message);
  }

  const keyvault = {
    v:         1,
    kdf:       params,
    salt:      bufferToBase64(salt),
    mkWrapIV:  bufferToBase64(mkWrapIV),
    wrappedMK: bufferToBase64(wrappedMKPassword),
    recovery,
    sharing,
    createdAt: new Date().toISOString(),
  };

  // Return a NON-extractable session master key; the extractable one used for
  // wrapping above goes out of scope and is collected.
  const sessionMK = await unwrapMasterKey(wrappedMKPassword, kek, mkWrapIV, false);
  return { keyvault, recoveryKey, masterKey: sessionMK };
}

export async function unlockVault(keyvault, password) {
  const kek = await deriveKEK(password, base64ToBuffer(keyvault.salt), keyvault.kdf ?? KDF_DEFAULTS);
  try {
    const masterKey = await unwrapMasterKey(base64ToBuffer(keyvault.wrappedMK), kek, base64ToBuffer(keyvault.mkWrapIV));
    return { masterKey };
  } catch {
    throw new Error("Incorrect password.");
  }
}

export async function unlockVaultWithRecovery(keyvault, recoveryKeyString) {
  if (!keyvault.recovery) throw new Error("No recovery key was configured for this vault.");
  const bytes      = parseRecoveryKey(recoveryKeyString);
  const recWrapKey = await importWrappingKeyFromBytes(bytes);
  try {
    const masterKey = await unwrapMasterKey(
      base64ToBuffer(keyvault.recovery.wrappedMK), recWrapKey, base64ToBuffer(keyvault.recovery.wrapIV), false,
    );
    return { masterKey };
  } catch {
    throw new Error("Invalid recovery key.");
  }
}

/**
 * Rotate the password. Unwraps the Master Key with the old password and
 * re-wraps it under a key derived from the new password. No files are touched;
 * the recovery and sharing blocks remain valid (they wrap the same Master Key).
 */
// Re-wrap a master key under a password-derived KEK. Returns the keyvault
// fields that encode it, plus a non-extractable session copy of the key.
async function rewrapMasterKeyForPassword(masterKey, newPassword, params) {
  const salt      = randomBytes(SALT_BYTES);
  const kek       = await deriveKEK(newPassword, salt, params);
  const mkWrapIV  = randomBytes(IV_BYTES);
  const wrappedMK = await wrapKeyWithKey(masterKey, kek, mkWrapIV);
  const sessionMK = await unwrapMasterKey(wrappedMK, kek, mkWrapIV, false);  // non-extractable
  return {
    fields: {
      kdf:       params,
      salt:      bufferToBase64(salt),
      mkWrapIV:  bufferToBase64(mkWrapIV),
      wrappedMK: bufferToBase64(wrappedMK),
    },
    sessionMK,
  };
}

export async function changePassword(keyvault, oldPassword, newPassword, params) {
  // Transiently materialise an EXTRACTABLE master key so it can be re-wrapped.
  // (unlockVault returns a non-extractable session key, which can't be wrapped.)
  const oldKek = await deriveKEK(oldPassword, base64ToBuffer(keyvault.salt), keyvault.kdf ?? KDF_DEFAULTS);
  let masterKey;
  try {
    masterKey = await unwrapMasterKey(base64ToBuffer(keyvault.wrappedMK), oldKek, base64ToBuffer(keyvault.mkWrapIV), true);
  } catch {
    throw new Error("Incorrect password.");
  }

  const newParams   = params ?? keyvault.kdf ?? KDF_DEFAULTS;
  const { fields }  = await rewrapMasterKeyForPassword(masterKey, newPassword, newParams);
  return { ...keyvault, ...fields };
}

/**
 * Recovery flow: unlock the master key with the recovery key, then re-wrap it
 * under a NEW password. Used after a Firebase password reset, where the vault is
 * still wrapped under the old password. The recovery block is left untouched, so
 * the same recovery key keeps working afterwards.
 * @returns {{ keyvault: object, masterKey: CryptoKey }}  updated vault + session key
 */
export async function recoverWithKeyAndReset(keyvault, recoveryKeyString, newPassword, params) {
  if (!keyvault.recovery) throw new Error("No recovery key was configured for this vault.");

  const recWrapKey = await importWrappingKeyFromBytes(parseRecoveryKey(recoveryKeyString));
  let masterKey;
  try {
    // EXTRACTABLE so it can be re-wrapped under the new password.
    masterKey = await unwrapMasterKey(
      base64ToBuffer(keyvault.recovery.wrappedMK), recWrapKey, base64ToBuffer(keyvault.recovery.wrapIV), true,
    );
  } catch {
    throw new Error("Invalid recovery key.");
  }

  const newParams              = params ?? keyvault.kdf ?? KDF_DEFAULTS;
  const { fields, sessionMK }  = await rewrapMasterKeyForPassword(masterKey, newPassword, newParams);
  return { keyvault: { ...keyvault, ...fields }, masterKey: sessionMK };
}

// ─────────────────────────────────────────────
//  Passkey escrow — Master Key wrapped under a WebAuthn PRF-derived secret
//
//  The authenticator's PRF (a.k.a. hmac-secret) extension yields a stable,
//  high-entropy 32-byte output for a given (credential, salt). We use it exactly
//  like the recovery key: imported directly as an AES-GCM wrapping key around a
//  copy of the Master Key. A passkey block therefore lets the user unlock the
//  vault with biometrics / a security key, with no server and no standing secret.
// ─────────────────────────────────────────────

/**
 * @param {CryptoKey}  masterKey  extractable Master Key
 * @param {Uint8Array} prfOutput  32 bytes from the authenticator PRF extension
 * @returns {{ wrapIV: string, wrappedMK: string }}
 */
export async function wrapMasterKeyWithPRF(masterKey, prfOutput) {
  if (!(prfOutput instanceof Uint8Array) || prfOutput.length !== RECOVERY_BYTES) {
    throw new Error("Passkey PRF output must be 32 bytes.");
  }
  const wrapKey = await importWrappingKeyFromBytes(prfOutput);
  const wrapIV  = randomBytes(IV_BYTES);
  const wrapped = await wrapKeyWithKey(masterKey, wrapKey, wrapIV);
  return { wrapIV: bufferToBase64(wrapIV), wrappedMK: bufferToBase64(wrapped) };
}

/**
 * @param {{wrapIV:string, wrappedMK:string}} block
 * @param {Uint8Array} prfOutput  32 bytes from the authenticator PRF extension
 * @param {boolean}    extractable
 * @returns {Promise<CryptoKey>} the Master Key
 */
export async function unwrapMasterKeyWithPRF(block, prfOutput, extractable = false) {
  if (!block?.wrappedMK) throw new Error("No passkey record on this vault.");
  const wrapKey = await importWrappingKeyFromBytes(prfOutput);
  try {
    return await unwrapMasterKey(
      base64ToBuffer(block.wrappedMK), wrapKey, base64ToBuffer(block.wrapIV), extractable,
    );
  } catch {
    throw new Error("This passkey could not unlock the vault (wrong passkey or corrupted record).");
  }
}

export function getSharingPublicKey(keyvault) {
  return keyvault?.sharing?.publicKey ?? null;
}

export async function unwrapSharingPrivateKey(keyvault, masterKey) {
  if (!keyvault?.sharing) throw new Error("No sharing key in this vault.");
  return crypto.subtle.unwrapKey(
    "pkcs8", base64ToBuffer(keyvault.sharing.wrappedPriv), masterKey,
    { name: "AES-GCM", iv: base64ToBuffer(keyvault.sharing.privWrapIV) },
    { name: "X25519" }, true, ["deriveBits"],
  );
}

// ─────────────────────────────────────────────
//  Sharing — X25519 ECDH + HKDF sealed-box around a file's DEK
//
//  To share file F with recipient R:
//    owner   : DEK   = unwrapFileDEK(F.metadata, ownerMasterKey)
//              share = wrapDEKForRecipient(DEK, R.publicKey)
//    recipient: DEK  = unwrapSharedDEK(share, R.privateKey)
//               file = openFileWithSharedDEK(ciphertext, F.metadata, DEK, ownerStorageKey)
//
//  The file body/metadata stay encrypted under the original DEK (AAD-bound to
//  the owner's storageKey), so only the DEK is re-wrapped per recipient.
// ─────────────────────────────────────────────

const SHARE_INFO = "vaultsync-share-v1";

async function deriveShareWrappingKey(sharedBits, salt, usages) {
  const hkdf = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: utf8(SHARE_INFO) },
    hkdf, { name: "AES-GCM", length: DEK_BITS }, false, usages,
  );
}

/** Owner side: recover a key-mode file's DEK (extractable) so it can be shared. */
export async function unwrapFileDEK(metadata, masterKey) {
  if (metadata.mode !== "key") throw new Error("Only key-mode files can be shared.");
  return unwrapDEK(base64ToBuffer(metadata.wrappedDEK), masterKey, base64ToBuffer(metadata.dekWrapIV));
}

/** Owner side: wrap a DEK to a recipient's raw X25519 public key. */
export async function wrapDEKForRecipient(dek, recipientPublicKeyB64) {
  const recipientPub = await crypto.subtle.importKey(
    "raw", base64ToBuffer(recipientPublicKeyB64), { name: "X25519" }, false, [],
  );
  const eph        = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const sharedBits = await crypto.subtle.deriveBits({ name: "X25519", public: recipientPub }, eph.privateKey, 256);

  const hkdfSalt = randomBytes(SALT_BYTES);
  const wrapKey  = await deriveShareWrappingKey(sharedBits, hkdfSalt, ["wrapKey"]);
  const wrapIV   = randomBytes(IV_BYTES);
  const wrapped  = await crypto.subtle.wrapKey("raw", dek, wrapKey, { name: "AES-GCM", iv: wrapIV });
  const ephPub   = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));

  return {
    alg:                "X25519-HKDF-SHA256-A256GCM",
    ephemeralPublicKey: bufferToBase64(ephPub),
    hkdfSalt:           bufferToBase64(hkdfSalt),
    wrapIV:             bufferToBase64(wrapIV),
    wrappedDEK:         bufferToBase64(new Uint8Array(wrapped)),
  };
}

/** Recipient side: unwrap the shared DEK using their X25519 private key. */
export async function unwrapSharedDEK(share, recipientPrivateKey) {
  const ephPub = await crypto.subtle.importKey(
    "raw", base64ToBuffer(share.ephemeralPublicKey), { name: "X25519" }, false, [],
  );
  const sharedBits = await crypto.subtle.deriveBits({ name: "X25519", public: ephPub }, recipientPrivateKey, 256);
  const unwrapKey  = await deriveShareWrappingKey(sharedBits, base64ToBuffer(share.hkdfSalt), ["unwrapKey"]);
  try {
    return await crypto.subtle.unwrapKey(
      "raw", base64ToBuffer(share.wrappedDEK), unwrapKey,
      { name: "AES-GCM", iv: base64ToBuffer(share.wrapIV) },
      { name: "AES-GCM", length: DEK_BITS }, false, ["encrypt", "decrypt"],
    );
  } catch {
    throw new Error("Could not unwrap the shared file key — wrong recipient or tampered share.");
  }
}

/** Recipient side: decrypt a shared file's body + metadata with the shared DEK. */
export async function openFileWithSharedDEK(ciphertext, metadata, dek, ownerStorageKey) {
  if (metadata.mode !== "key") throw new Error("Not a key-mode file.");
  const aad = `v${metadata.v}|key|${ownerStorageKey}`;
  return openWithDEK(ciphertext, metadata, dek, aad);
}

/**
 * Short, human-comparable fingerprint of a public key (first 8 bytes of its
 * SHA-256, as 4 hex groups). Used for out-of-band verification in the share UI
 * to defend against directory key-substitution.
 */
export async function publicKeyFingerprint(publicKeyB64) {
  const hash = await crypto.subtle.digest("SHA-256", base64ToBuffer(publicKeyB64));
  const hex  = [...new Uint8Array(hash).slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{1,4}/g).join("-").toUpperCase();
}

// ─────────────────────────────────────────────
//  DEPRECATED — v1 password writer (PBKDF2, PLAINTEXT metadata).
//  Kept ONLY so the existing cloud flow (upload.js / download.js) keeps
//  working until it is migrated to key-mode in Step 3. Do not use in new code.
//  `decryptFileWithPassword` routes through openFileWithPassword, so it reads
//  both this v1 format and the new v2 password envelope.
// ─────────────────────────────────────────────

export async function encryptFileWithPassword(file, password) {
  const plaintext = await file.arrayBuffer();
  const salt      = randomBytes(SALT_BYTES);
  const fileIV    = randomBytes(IV_BYTES);
  const dekIV     = randomBytes(IV_BYTES);

  const material    = await crypto.subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveKey"]);
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 150000, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"],
  );
  const dek        = await generateDEK();
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: fileIV }, dek, plaintext);
  const wrappedDEK = await crypto.subtle.wrapKey("raw", dek, wrappingKey, { name: "AES-GCM", iv: dekIV });

  const metadata = {
    originalName: file.name,
    mimeType:     file.type || "application/octet-stream",
    salt:         bufferToBase64(salt),
    fileIV:       bufferToBase64(fileIV),
    dekIV:        bufferToBase64(dekIV),
    wrappedDEK:   bufferToBase64(new Uint8Array(wrappedDEK)),
    size:         plaintext.byteLength,
    timestamp:    new Date().toISOString(),
  };
  return { ciphertext, metadata };
}

export async function decryptFileWithPassword(ciphertext, metadata, password) {
  return openFileWithPassword(ciphertext, metadata, password);
}
