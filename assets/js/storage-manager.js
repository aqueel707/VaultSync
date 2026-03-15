/**
 * storage-manager.js
 * ───────────────────
 * Abstraction layer — selects managed or user-owned Supabase provider.
 * Public API is identical to the Firebase version.
 *
 * localStorage keys:
 *   vaultsync_storage_mode  → "managed" | "user"
 *   vaultsync_user_cfg      → JSON { supabaseUrl, supabaseAnonKey, bucket? }
 */

import * as managed  from "./firebase-managed.js";
import * as userProv from "./firebase-user.js";

const LS_MODE   = "vaultsync_storage_mode";
const LS_CONFIG = "vaultsync_user_cfg";

let activeMode = "managed";

// ─── Persistence helpers ──────────────────────────────────────────────────

export function saveUserConfig(config) {
  localStorage.setItem(LS_CONFIG, JSON.stringify(config));
}

export function loadUserConfig() {
  try {
    return JSON.parse(localStorage.getItem(LS_CONFIG) ?? "null");
  } catch {
    return null;
  }
}

// ─── Mode control ─────────────────────────────────────────────────────────

export function setMode(mode) {
  if (mode !== "managed" && mode !== "user") {
    throw new Error(`Unknown storage mode: "${mode}".`);
  }
  activeMode = mode;
  localStorage.setItem(LS_MODE, mode);
  console.info(`[StorageManager] Active provider → ${mode}`);
}

export function getMode() {
  return activeMode;
}

// ─── User provider initialisation ─────────────────────────────────────────

export async function initUserProvider(userConfig) {
  await userProv.initUserApp(userConfig);
}

// ─── Page boot ────────────────────────────────────────────────────────────

export async function initFromStorage() {
  const savedMode = localStorage.getItem(LS_MODE);
  if (savedMode === "user") {
    const cfg = loadUserConfig();
    if (cfg) {
      try {
        await userProv.initUserApp(cfg);
        activeMode = "user";
        console.info("[StorageManager] Restored user Supabase provider from localStorage.");
      } catch (err) {
        console.warn("[StorageManager] Could not restore user provider:", err.message);
        activeMode = "managed";
        localStorage.setItem(LS_MODE, "managed");
        localStorage.removeItem(LS_CONFIG);
      }
    } else {
      activeMode = "managed";
      localStorage.setItem(LS_MODE, "managed");
    }
  } else {
    activeMode = "managed";
  }
}

// ─── Provider selector ────────────────────────────────────────────────────

function provider() {
  return activeMode === "user" ? userProv : managed;
}

// ─── Unified storage API ──────────────────────────────────────────────────

export async function uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress) {
  return provider().uploadEncryptedFile(uid, storageKey, ciphertext, metadata, onProgress);
}

export async function listUserFiles(uid) {
  return provider().listUserFiles(uid);
}

export async function downloadEncryptedFile(uid, storageKey) {
  return provider().downloadEncryptedFile(uid, storageKey);
}

export async function deleteFile(uid, storageKey) {
  return provider().deleteFile(uid, storageKey);
}

export function generateStorageKey() {
  return `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}