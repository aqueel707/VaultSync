/**
 * firebase-user.js
 * ─────────────────
 * Storage provider for USER-OWNED mode.
 *
 * Initialises a SECONDARY Firebase app instance (named "userApp") using
 * config supplied by the user at runtime. Never collides with the app's
 * own DEFAULT Firebase instance.
 *
 * Exposes the same interface as firebase-managed.js.
 *
 * UNCHANGED from original.
 */

import {
  initializeApp,
  getApps,
  deleteApp,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getStorage,
  ref,
  uploadBytes,
  getDownloadURL,
  listAll,
  deleteObject,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-storage.js";

const USER_APP_NAME = "userApp";

export async function initUserApp(userConfig) {
  const existing = getApps().find((a) => a.name === USER_APP_NAME);
  if (existing) await deleteApp(existing);
  initializeApp(userConfig, USER_APP_NAME);
}

function getUserStorage() {
  const existing = getApps().find((a) => a.name === USER_APP_NAME);
  if (!existing) {
    throw new Error(
      "User Firebase app is not initialised. " +
      "Please enter and save your Firebase configuration in Settings first.",
    );
  }
  return getStorage(existing);
}

function encPath(uid, storageKey)  { return `vaultsync/${uid}/files/${storageKey}.enc`; }
function metaPath(uid, storageKey) { return `vaultsync/${uid}/files/${storageKey}.meta.json`; }

export async function uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress) {
  const storage = getUserStorage();
  onProgress?.(10, "Uploading encrypted file to your bucket…");
  await uploadBytes(ref(storage, encPath(uid, storageKey)),
    new Blob([ciphertext], { type: "application/octet-stream" }));
  onProgress?.(70, "Uploading metadata to your bucket…");
  await uploadBytes(ref(storage, metaPath(uid, storageKey)),
    new Blob([JSON.stringify(metadata, null, 2)], { type: "application/json" }));
  onProgress?.(100, "Upload complete.");
}

export async function listUserFiles(uid) {
  const storage   = getUserStorage();
  const folderRef = ref(storage, `vaultsync/${uid}/files/`);
  const result    = await listAll(folderRef);
  const metaItems = result.items.filter((i) => i.name.endsWith(".meta.json"));

  const files = await Promise.all(metaItems.map(async (item) => {
    try {
      const url      = await getDownloadURL(item);
      const metadata = await (await fetch(url)).json();
      return { storageKey: item.name.replace(".meta.json", ""), metadata };
    } catch (err) {
      console.warn("UserApp: could not load metadata for", item.name, err);
      return null;
    }
  }));

  return files.filter(Boolean)
    .sort((a, b) => new Date(b.metadata.timestamp) - new Date(a.metadata.timestamp));
}

export async function downloadEncryptedFile(uid, storageKey) {
  const storage = getUserStorage();

  const encUrl  = await getDownloadURL(ref(storage, encPath(uid, storageKey)));
  const encResp = await fetch(encUrl);
  if (!encResp.ok) throw new Error("Failed to download encrypted file from your bucket.");
  const ciphertext = await encResp.arrayBuffer();

  const metaUrl  = await getDownloadURL(ref(storage, metaPath(uid, storageKey)));
  const metaResp = await fetch(metaUrl);
  if (!metaResp.ok) throw new Error("Failed to download file metadata from your bucket.");
  const metadata = await metaResp.json();

  return { ciphertext, metadata };
}

export async function deleteFile(uid, storageKey) {
  const storage = getUserStorage();
  await Promise.all([
    deleteObject(ref(storage, encPath(uid, storageKey))),
    deleteObject(ref(storage, metaPath(uid, storageKey))),
  ]);
}
