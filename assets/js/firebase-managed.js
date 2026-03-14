/**
 * firebase-managed.js
 * ────────────────────
 * Storage provider for MANAGED mode.
 * Uses the application's own Firebase project (firebase-config.js).
 *
 * Exposes the same interface as firebase-user.js so storage-manager.js
 * can swap providers transparently.
 *
 * UNCHANGED from original — only the import path for firebase-config was
 * updated to reflect the new directory structure.
 */

import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getStorage,
  ref,
  uploadBytes,
  getDownloadURL,
  listAll,
  deleteObject,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

import { firebaseConfig } from "./firebase-config.js";

function getManagedStorage() {
  const existing = getApps().find((a) => a.name === "[DEFAULT]");
  const app = existing ?? initializeApp(firebaseConfig);
  return getStorage(app);
}

function encPath(uid, storageKey)  { return `users/${uid}/files/${storageKey}.enc`; }
function metaPath(uid, storageKey) { return `users/${uid}/files/${storageKey}.meta.json`; }

export async function uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress) {
  const storage = getManagedStorage();
  onProgress?.(10, "Uploading encrypted file…");
  await uploadBytes(ref(storage, encPath(uid, storageKey)),
    new Blob([ciphertext], { type: "application/octet-stream" }));
  onProgress?.(70, "Uploading metadata…");
  await uploadBytes(ref(storage, metaPath(uid, storageKey)),
    new Blob([JSON.stringify(metadata, null, 2)], { type: "application/json" }));
  onProgress?.(100, "Upload complete.");
}

export async function listUserFiles(uid) {
  const storage   = getManagedStorage();
  const folderRef = ref(storage, `users/${uid}/files/`);
  const result    = await listAll(folderRef);
  const metaItems = result.items.filter((i) => i.name.endsWith(".meta.json"));

  const files = await Promise.all(metaItems.map(async (item) => {
    try {
      const url      = await getDownloadURL(item);
      const metadata = await (await fetch(url)).json();
      return { storageKey: item.name.replace(".meta.json", ""), metadata };
    } catch (err) {
      console.warn("Managed: could not load metadata for", item.name, err);
      return null;
    }
  }));

  return files.filter(Boolean)
    .sort((a, b) => new Date(b.metadata.timestamp) - new Date(a.metadata.timestamp));
}

export async function downloadEncryptedFile(uid, storageKey) {
  const storage = getManagedStorage();

  const encUrl  = await getDownloadURL(ref(storage, encPath(uid, storageKey)));
  const encResp = await fetch(encUrl);
  if (!encResp.ok) throw new Error("Failed to download encrypted file.");
  const ciphertext = await encResp.arrayBuffer();

  const metaUrl  = await getDownloadURL(ref(storage, metaPath(uid, storageKey)));
  const metaResp = await fetch(metaUrl);
  if (!metaResp.ok) throw new Error("Failed to download file metadata.");
  const metadata = await metaResp.json();

  return { ciphertext, metadata };
}

export async function deleteFile(uid, storageKey) {
  const storage = getManagedStorage();
  await Promise.all([
    deleteObject(ref(storage, encPath(uid, storageKey))),
    deleteObject(ref(storage, metaPath(uid, storageKey))),
  ]);
}
