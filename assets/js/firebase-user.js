/**
 * firebase-user.js
 * ─────────────────
 * Storage provider for USER-OWNED mode.
 *
 * CHANGED: Firebase Storage replaced with Supabase Storage.
 * The user supplies their own Supabase project URL + anon key at runtime.
 *
 * User config schema:
 * {
 *   supabaseUrl:     string   e.g. "https://xxxx.supabase.co"
 *   supabaseAnonKey: string   e.g. "eyJhbGci..."
 *   bucket:          string   e.g. "vaultsync"  (defaults to "vaultsync")
 * }
 */

import { createUserSupabaseClient } from "./supabase-client.js";

// ─── In-memory client for this page load ─────────────────────────────────

let _client = null;
let _bucket = "vaultsync";

// ─── Initialisation ───────────────────────────────────────────────────────

export async function initUserApp(userConfig) {
  _client = createUserSupabaseClient(userConfig);
  _bucket = userConfig.bucket ?? "vaultsync";
}

function getUserClient() {
  if (!_client) {
    throw new Error(
      "User Supabase client is not initialised. " +
      "Please enter and save your Supabase configuration in Settings first.",
    );
  }
  return _client;
}

// ─── Path helpers ─────────────────────────────────────────────────────────

function encPath(uid, storageKey)  { return `users/${uid}/files/${storageKey}.enc`; }
function metaPath(uid, storageKey) { return `users/${uid}/files/${storageKey}.meta.json`; }

// ─── Upload ───────────────────────────────────────────────────────────────

export async function uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress) {
  const client = getUserClient();

  onProgress?.(10, "Uploading encrypted file to your bucket…");
  const { error: encErr } = await client.storage
    .from(_bucket)
    .upload(
      encPath(uid, storageKey),
      new Blob([ciphertext], { type: "application/octet-stream" }),
      { upsert: true },
    );
  if (encErr) throw new Error(`User bucket upload failed: ${encErr.message}`);

  onProgress?.(70, "Uploading metadata to your bucket…");
  const { error: metaErr } = await client.storage
    .from(_bucket)
    .upload(
      metaPath(uid, storageKey),
      new Blob([JSON.stringify(metadata, null, 2)], { type: "application/json" }),
      { upsert: true },
    );
  if (metaErr) throw new Error(`User bucket metadata upload failed: ${metaErr.message}`);

  onProgress?.(100, "Upload complete.");
}

// ─── List ─────────────────────────────────────────────────────────────────

export async function listUserFiles(uid) {
  const client = getUserClient();
  const folder = `users/${uid}/files`;

  const { data, error } = await client.storage
    .from(_bucket)
    .list(folder, { limit: 1000, offset: 0 });

  if (error) throw new Error(`User bucket list failed: ${error.message}`);
  if (!data?.length) return [];

  const metaItems = data.filter((item) => item.name.endsWith(".meta.json"));

  const files = await Promise.all(
    metaItems.map(async (item) => {
      try {
        const filePath = `${folder}/${item.name}`;
        const { data: urlData, error: urlErr } = await client.storage
          .from(_bucket)
          .createSignedUrl(filePath, 60);

        if (urlErr) throw urlErr;

        const resp = await fetch(urlData.signedUrl);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const metadata = await resp.json();

        const storageKey = item.name.replace(".meta.json", "");
        return { storageKey, metadata };
      } catch (err) {
        console.warn("UserApp: could not load metadata for", item.name, err);
        return null;
      }
    }),
  );

  return files
    .filter(Boolean)
    .sort((a, b) => new Date(b.metadata.timestamp) - new Date(a.metadata.timestamp));
}

// ─── Download ─────────────────────────────────────────────────────────────

export async function downloadEncryptedFile(uid, storageKey) {
  const client = getUserClient();

  const { data: encData, error: encErr } = await client.storage
    .from(_bucket)
    .download(encPath(uid, storageKey));
  if (encErr) throw new Error(`Failed to download encrypted file from your bucket: ${encErr.message}`);
  const ciphertext = await encData.arrayBuffer();

  const { data: metaData, error: metaErr } = await client.storage
    .from(_bucket)
    .download(metaPath(uid, storageKey));
  if (metaErr) throw new Error(`Failed to download metadata from your bucket: ${metaErr.message}`);
  const metadata = JSON.parse(await metaData.text());

  return { ciphertext, metadata };
}

// ─── Delete ───────────────────────────────────────────────────────────────

export async function deleteFile(uid, storageKey) {
  const client = getUserClient();
  const { error } = await client.storage
    .from(_bucket)
    .remove([encPath(uid, storageKey), metaPath(uid, storageKey)]);
  if (error) throw new Error(`User bucket delete failed: ${error.message}`);
}