/**
 * supabase-client.js
 * ──────────────────
 * Creates and exports the APPLICATION-LEVEL Supabase client.
 * Used by firebase-managed.js for the app's own storage bucket.
 *
 * Firebase Authentication is kept unchanged — this file ONLY handles
 * the Supabase Storage connection.
 *
 * The anon key is public by design (same as Firebase web config).
 * Access is enforced by Supabase Storage RLS policies, not by key secrecy.
 */

import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";

const SUPABASE_URL  = "https://isvaqkhbdzlgjylkvvvl.supabase.co";
const SUPABASE_ANON = "sb_publishable_Yf_XWf1MpYYDcyqI9fBzSg_X-RgMCll";

export const BUCKET = "vaultsync";

/**
 * The shared app-level Supabase client.
 * Imported by firebase-managed.js only.
 */
export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON);

/**
 * Create a fresh Supabase client using a user-supplied project config.
 * Used by firebase-user.js for user-owned storage buckets.
 *
 * @param {{ supabaseUrl: string, supabaseAnonKey: string }} config
 * @returns {import("@supabase/supabase-js").SupabaseClient}
 */
export function createUserSupabaseClient({ supabaseUrl, supabaseAnonKey }) {
  if (!supabaseUrl || !supabaseAnonKey) {
    throw new Error(
      "User Supabase config is missing supabaseUrl or supabaseAnonKey.",
    );
  }
  return createClient(supabaseUrl, supabaseAnonKey);
}