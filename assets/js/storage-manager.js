/**
 * storage-manager.js
 * ───────────────────
 * Abstraction layer that selects the active storage provider.
 *
 * KEY CHANGE vs the SPA version:
 *   Mode and user config are persisted to localStorage so they survive
 *   page navigations. On each page load, call initFromStorage() once
 *   to restore state before making any storage calls.
 *
 * Supported modes:
 *   "managed"  → firebase-managed.js  (app's own Firebase project)
 *   "user"     → firebase-user.js     (user-supplied Firebase project)
 *
 * localStorage keys:
 *   vaultsync_storage_mode   → "managed" | "user"
 *   vaultsync_user_cfg       → JSON string of user Firebase config
 *
 * Public API (same as SPA version):
 *   initFromStorage()                  → Promise<void>   call on every page
 *   setMode(mode)                      → void
 *   getMode()                          → "managed" | "user"
 *   initUserProvider(config)           → Promise<void>
 *   uploadEncryptedFile(...)           → Promise<void>
 *   listUserFiles(uid)                 → Promise<array>
 *   downloadEncryptedFile(uid, key)    → Promise<object>
 *   deleteFile(uid, key)               → Promise<void>
 *   generateStorageKey()               → string
 *   saveUserConfig(config)             → void
 *   loadUserConfig()                   → object | null
 */

import * as managed         from "./firebase-managed.js";
import * as user            from "./firebase-user.js";
import { initUserApp }      from "./firebase-user.js";

const LS_MODE   = "vaultsync_storage_mode";
const LS_CONFIG = "vaultsync_user_cfg";

let activeMode = "managed";   // in-memory state for this page load

// ─── Persistence helpers ──────────────────────────────────────────────────

/**
 * Save user Firebase config to localStorage.
 * @param {object} config
 */
export function saveUserConfig(config) {
  localStorage.setItem(LS_CONFIG, JSON.stringify(config));
}

/**
 * Load user Firebase config from localStorage.
 * @returns {object|null}
 */
export function loadUserConfig() {
  try {
    return JSON.parse(localStorage.getItem(LS_CONFIG) ?? "null");
  } catch {
    return null;
  }
}

// ─── Mode control ─────────────────────────────────────────────────────────

/**
 * Set the active storage mode and persist it.
 * @param {"managed"|"user"} mode
 */
export function setMode(mode) {
  if (mode !== "managed" && mode !== "user") {
    throw new Error(`Unknown storage mode: "${mode}".`);
  }
  activeMode = mode;
  localStorage.setItem(LS_MODE, mode);
  console.info(`[StorageManager] Active provider → ${mode}`);
}

/**
 * @returns {"managed"|"user"}
 */
export function getMode() {
  return activeMode;
}

// ─── User provider initialisation ─────────────────────────────────────────

/**
 * Initialise the user-owned Firebase app.
 * @param {object} userConfig
 */
export async function initUserProvider(userConfig) {
  await initUserApp(userConfig);
}

// ─── Page boot: restore persisted state ──────────────────────────────────

/**
 * Call ONCE at the top of every page that uses storage, before any
 * storage calls. Reads localStorage and re-initialises the user Firebase
 * app if user mode was previously selected.
 *
 * @returns {Promise<void>}
 */
export async function initFromStorage() {
  const savedMode = localStorage.getItem(LS_MODE);
  if (savedMode === "user") {
    const cfg = loadUserConfig();
    if (cfg) {
      try {
        await initUserApp(cfg);
        activeMode = "user";
        console.info("[StorageManager] Restored user provider from localStorage.");
      } catch (err) {
        console.warn("[StorageManager] Could not restore user provider:", err.message);
        // Fall back gracefully to managed mode and clear bad config
        activeMode = "managed";
        localStorage.setItem(LS_MODE, "managed");
        localStorage.removeItem(LS_CONFIG);
      }
    } else {
      // Mode was "user" but config is missing — fall back
      activeMode = "managed";
      localStorage.setItem(LS_MODE, "managed");
    }
  } else {
    activeMode = "managed";
  }
}

// ─── Provider selector ────────────────────────────────────────────────────

function provider() {
  return activeMode === "user" ? user : managed;
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
