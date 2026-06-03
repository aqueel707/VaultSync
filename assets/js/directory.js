/**
 * directory.js
 * ────────────
 * Public-key directory for sharing. Maps email → X25519 public key so a sender
 * can find a recipient. Backed by the `public_keys` table in the app's Supabase
 * project.
 *
 * Lookups go through the `get_public_key` SECURITY DEFINER function, so the
 * directory can't be enumerated — you can only resolve an email you already
 * know, not list every registered user.
 *
 * Only PUBLIC keys live here (safe to expose). Writes are permissive at the DB
 * layer (no Supabase Auth identity to bind against); the resulting key-
 * substitution risk is mitigated by fingerprint verification in the share UI.
 */

import { supabase } from "./supabase-client.js";

/** Publish (or update) this user's public key. Idempotent. */
export async function publishPublicKey(uid, email, publicKey) {
  const { error } = await supabase
    .from("public_keys")
    .upsert(
      { uid, email, public_key: publicKey, updated_at: new Date().toISOString() },
      { onConflict: "uid" },
    );
  if (error) throw new Error(`Failed to publish public key: ${error.message}`);
}

/**
 * Resolve a recipient by exact email.
 * @returns {Promise<{uid: string, publicKey: string}|null>} or null if unknown
 */
export async function lookupRecipient(email) {
  const { data, error } = await supabase.rpc("get_public_key", { p_email: email });
  if (error) throw new Error(`Directory lookup failed: ${error.message}`);
  if (!data) return null;
  return { uid: data.uid, publicKey: data.public_key };
}
