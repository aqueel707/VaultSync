/**
 * firebase-managed.js
 * ────────────────────
 * Storage provider for MANAGED mode.
 *
 * CHANGED: Firebase Storage replaced with Supabase Storage.
 * Firebase Authentication is NOT touched — auth.js still owns that.
 *
 * Uses the app-level Supabase client from supabase-client.js.
 * Exposes the SAME 4-function interface as before so storage-manager.js
 * requires zero changes to its provider-selection logic:
 *
 *   uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress?)
 *   listUserFiles(uid)
 *   downloadEncryptedFile(uid, storageKey)
 *   deleteFile(uid, storageKey)
 *
 * Storage paths (unchanged):
 *   users/<uid>/files/<storageKey>.enc
 *   users/<uid>/files/<storageKey>.meta.json
 */

import { supabase, BUCKET } from "./supabase-client.js";

// ─── Path helpers ─────────────────────────────────────────────────────────

function encPath(uid, storageKey) {
  return `users/${uid}/files/${storageKey}.enc`;
}
function metaPath(uid, storageKey) {
  return `users/${uid}/files/${storageKey}.meta.json`;
}

// ─── Upload ───────────────────────────────────────────────────────────────

export async function uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress) {
  onProgress?.(10, "Uploading encrypted file…");
  const { error: encErr } = await supabase.storage
    .from(BUCKET)
    .upload(
      encPath(uid, storageKey),
      new Blob([ciphertext], { type: "application/octet-stream" }),
      { upsert: true },
    );
  if (encErr) throw new Error(`Supabase upload failed: ${encErr.message}`);

  onProgress?.(70, "Uploading metadata…");
  const { error: metaErr } = await supabase.storage
    .from(BUCKET)
    .upload(
      metaPath(uid, storageKey),
      new Blob([JSON.stringify(metadata, null, 2)], { type: "application/json" }),
      { upsert: true },
    );
  if (metaErr) throw new Error(`Supabase metadata upload failed: ${metaErr.message}`);

  onProgress?.(100, "Upload complete.");
}

// ─── List ─────────────────────────────────────────────────────────────────

export async function listUserFiles(uid) {
  const folder = `users/${uid}/files`;

  const { data, error } = await supabase.storage
    .from(BUCKET)
    .list(folder, { limit: 1000, offset: 0 });

  if (error) throw new Error(`Supabase list failed: ${error.message}`);
  if (!data?.length) return [];

  const metaItems = data.filter((item) => item.name.endsWith(".meta.json"));

  const files = await Promise.all(
    metaItems.map(async (item) => {
      try {
        const filePath = `${folder}/${item.name}`;
        const { data: urlData, error: urlErr } = await supabase.storage
          .from(BUCKET)
          .createSignedUrl(filePath, 60);

        if (urlErr) throw urlErr;

        const resp = await fetch(urlData.signedUrl);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const metadata = await resp.json();

        const storageKey = item.name.replace(".meta.json", "");
        return { storageKey, metadata };
      } catch (err) {
        console.warn("Managed: could not load metadata for", item.name, err);
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
  const { data: encData, error: encErr } = await supabase.storage
    .from(BUCKET)
    .download(encPath(uid, storageKey));
  if (encErr) throw new Error(`Failed to download encrypted file: ${encErr.message}`);
  const ciphertext = await encData.arrayBuffer();

  const { data: metaData, error: metaErr } = await supabase.storage
    .from(BUCKET)
    .download(metaPath(uid, storageKey));
  if (metaErr) throw new Error(`Failed to download file metadata: ${metaErr.message}`);
  const metadata = JSON.parse(await metaData.text());

  return { ciphertext, metadata };
}

// ─── Delete ───────────────────────────────────────────────────────────────

export async function deleteFile(uid, storageKey) {
  const { error } = await supabase.storage
    .from(BUCKET)
    .remove([encPath(uid, storageKey), metaPath(uid, storageKey)]);
  if (error) throw new Error(`Supabase delete failed: ${error.message}`);
}