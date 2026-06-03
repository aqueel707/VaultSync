/**
 * sharing.js
 * ──────────
 * Share-record storage for X25519 file sharing.
 *
 * A share wraps a file's DEK to the recipient's public key (crypto in
 * crypto-utils.js) and stores a small record the recipient can read:
 *
 *   users/<recipientUid>/shares/<shareId>.json
 *
 * (kept under users/ so the existing storage RLS applies). The file body and
 * metadata stay in the OWNER's app-bucket path; the recipient fetches them
 * directly and decrypts with the unwrapped DEK.
 *
 * Sharing targets the managed app bucket. Files stored in a user-owned bucket
 * (user storage mode) can't be shared — the recipient has no access to that
 * private project.
 */

import { supabase, BUCKET } from "./supabase-client.js";
import { unwrapFileDEK, wrapDEKForRecipient } from "./crypto-utils.js";

const sharesFolder = (uid)          => `users/${uid}/shares`;
const sharePath    = (uid, shareId) => `${sharesFolder(uid)}/${shareId}.json`;

function newShareId() {
  return `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Owner: wrap the file's DEK to the recipient and store the share record.
 * @returns {Promise<string>} shareId
 */
export async function createShare({
  ownerUid, ownerEmail, storageKey, fileMetadata, masterKey,
  recipientUid, recipientPublicKey,
}) {
  const dek   = await unwrapFileDEK(fileMetadata, masterKey);
  const share = await wrapDEKForRecipient(dek, recipientPublicKey);

  const record = {
    v:          1,
    ownerUid,
    ownerEmail,
    storageKey,
    share,
    sharedAt:   new Date().toISOString(),
  };

  const shareId = newShareId();
  const { error } = await supabase.storage.from(BUCKET).upload(
    sharePath(recipientUid, shareId),
    new Blob([JSON.stringify(record)], { type: "application/json" }),
    { upsert: true },
  );
  if (error) throw new Error(`Failed to create share: ${error.message}`);
  return shareId;
}

/** Recipient: list shares addressed to me, newest first. */
export async function listIncomingShares(myUid) {
  const folder = sharesFolder(myUid);
  const { data, error } = await supabase.storage.from(BUCKET).list(folder, { limit: 1000, offset: 0 });
  if (error) throw new Error(`Failed to list shares: ${error.message}`);
  if (!data?.length) return [];

  const records = await Promise.all(
    data.filter((i) => i.name.endsWith(".json")).map(async (item) => {
      try {
        const { data: blob, error: dlErr } = await supabase.storage.from(BUCKET).download(`${folder}/${item.name}`);
        if (dlErr) throw dlErr;
        const rec = JSON.parse(await blob.text());
        return { shareId: item.name.replace(".json", ""), ...rec };
      } catch (e) {
        console.warn("Share record load failed:", item.name, e);
        return null;
      }
    }),
  );

  return records.filter(Boolean).sort((a, b) => new Date(b.sharedAt) - new Date(a.sharedAt));
}

/** Recipient: fetch the shared file's ciphertext + metadata from the owner's app-bucket path. */
export async function downloadSharedBlob(ownerUid, storageKey) {
  const encPath  = `users/${ownerUid}/files/${storageKey}.enc`;
  const metaPath = `users/${ownerUid}/files/${storageKey}.meta.json`;

  const { data: encData, error: encErr } = await supabase.storage.from(BUCKET).download(encPath);
  if (encErr) throw new Error(`Couldn't fetch the shared file: ${encErr.message}`);
  const ciphertext = await encData.arrayBuffer();

  const { data: metaData, error: metaErr } = await supabase.storage.from(BUCKET).download(metaPath);
  if (metaErr) throw new Error(`Couldn't fetch the shared file's metadata: ${metaErr.message}`);
  const metadata = JSON.parse(await metaData.text());

  return { ciphertext, metadata };
}

/** Recipient: remove a share from my inbox. */
export async function deleteIncomingShare(myUid, shareId) {
  const { error } = await supabase.storage.from(BUCKET).remove([sharePath(myUid, shareId)]);
  if (error) throw new Error(`Failed to remove the share: ${error.message}`);
}
