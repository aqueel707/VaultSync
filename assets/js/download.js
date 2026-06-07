/**
 * download.js  (key-mode / v2, with v1 fallback)
 * ──────────────────────────────────────────────
 * Page controller for files.html.
 *   • Lists files and decrypts each metadata client-side to show name/size/date.
 *   • v2 (key-mode) files decrypt under the vault master key — no password.
 *   • Legacy v1 files still require their per-file password (field shown only then).
 * Crypto → crypto-utils.js, storage → storage-manager.js, master key → vault.js.
 */

import { requireAuth, navigateTo, markLoggedOut } from "./router.js";
import { logoutUser }       from "./auth.js";
import { openFileWithKey, openFileWithPassword, openMetadataWithKey, publicKeyFingerprint,
         openFileStreamWithKey, decryptStreamToSink } from "./crypto-utils.js";
import * as storageManager  from "./storage-manager.js";
import * as vault           from "./vault.js";
import * as sharing         from "./sharing.js";
import { lookupRecipient }  from "./directory.js";
import { supabase, BUCKET } from "./supabase-client.js";
import * as manifest        from "./manifest.js";

// Above this size, key-mode v3 files stream straight to disk (when the browser
// supports the File System Access API and storage is the managed app bucket).
const STREAM_DL_THRESHOLD = 8 * 1024 * 1024;   // 8 MiB

// ─── Boot ─────────────────────────────────────────────────────────────────

const user = await requireAuth("login.html");
await storageManager.initFromStorage();

// ─── DOM refs ─────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const fileListEl     = $("file-list");
const btnRefresh     = $("btn-refresh");
const downloadPanel  = $("download-panel");
const dlFilename     = $("dl-filename");
const btnClosePanel  = $("btn-close-panel");
const decPassword    = $("dec-password");
const togglePassBtn  = $("toggle-dec-pass");
const btnDownload    = $("btn-download");
const btnDelete      = $("btn-delete");
const dlError        = $("dl-error");
const storageBadgeEl = $("storage-badge");
const btnLogout      = $("btn-logout");

const decPasswordField = decPassword.closest(".field");  // toggled per file type

// Share UI
const btnShare         = $("btn-share");
const shareBox         = $("share-box");
const shareEmail       = $("share-email");
const btnShareLookup   = $("btn-share-lookup");
const shareVerify      = $("share-verify");
const shareFingerprint = $("share-fingerprint");
const btnShareConfirm  = $("btn-share-confirm");
const shareStatus      = $("share-status");

// ─── State ────────────────────────────────────────────────────────────────

let entries          = [];     // [{ storageKey, metadata, displayMeta, locked }]
let selected         = null;
let pendingRecipient = null;   // { uid, publicKey, email } after a directory lookup

// ─── Init ─────────────────────────────────────────────────────────────────

renderStorageBadge();
$("user-email").textContent = user.email;
loadFileList();

// ─── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)      return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(2)} MB`;
}

function fileEmoji(mimeType = "") {
  if (mimeType.startsWith("image/")) return "🖼";
  if (mimeType.startsWith("video/")) return "🎬";
  if (mimeType.startsWith("audio/")) return "🎵";
  if (mimeType.includes("pdf"))      return "📄";
  if (mimeType.includes("zip") || mimeType.includes("tar")) return "🗜";
  if (mimeType.includes("text/"))    return "📝";
  return "📦";
}

function setLoading(btn, loading) {
  btn.querySelector(".btn-label").hidden   = loading;
  btn.querySelector(".btn-spinner").hidden = !loading;
  btn.disabled = loading;
}

function showError(el, message) {
  el.textContent = message;
  el.hidden      = !message;
}

function renderStorageBadge() {
  if (!storageBadgeEl) return;
  const mode = storageManager.getMode();
  storageBadgeEl.textContent = mode === "user" ? "Your Storage" : "App Storage";
  storageBadgeEl.className   = `storage-badge ${mode}`;
}

function lockedMeta() {
  return { originalName: "🔒 Locked — sign in again", mimeType: "", size: 0, timestamp: 0 };
}

// ─── File list ────────────────────────────────────────────────────────────

btnRefresh?.addEventListener("click", loadFileList);

async function loadFileList() {
  fileListEl.innerHTML = `<p class="loading-msg">Loading…</p>`;
  downloadPanel.hidden = true;
  selected             = null;

  let raw;
  try {
    raw = await storageManager.listUserFiles(user.uid);
  } catch (err) {
    const p = document.createElement("p");
    p.className   = "error-msg";
    p.textContent = err.message;          // textContent — never innerHTML with external data
    fileListEl.innerHTML = "";
    fileListEl.appendChild(p);
    console.error("List error:", err);
    return;
  }

  const masterKey = await vault.getMasterKey();

  entries = await Promise.all(raw.map(async ({ storageKey, metadata }) => {
    if (metadata && metadata.mode === "key") {
      // v2: metadata is encrypted — decrypt it with the master key.
      if (!masterKey) return { storageKey, metadata, displayMeta: lockedMeta(), locked: true };
      try {
        const dm = await openMetadataWithKey(metadata, masterKey, storageKey);
        return { storageKey, metadata, displayMeta: dm, locked: false };
      } catch (e) {
        console.warn("Metadata decrypt failed for", storageKey, e);
        return { storageKey, metadata, displayMeta: lockedMeta(), locked: true };
      }
    }
    // legacy v1: metadata is plaintext (originalName/size/timestamp present).
    return { storageKey, metadata, displayMeta: metadata, locked: false };
  }));

  entries.sort((a, b) =>
    new Date(b.displayMeta?.timestamp || 0) - new Date(a.displayMeta?.timestamp || 0));

  const anyLocked = entries.some((e) => e.locked);
  renderFileList(anyLocked);

  // Integrity manifest check — app storage only, non-blocking, best-effort.
  if (masterKey && storageManager.getMode() !== "user") {
    runIntegrityCheck(masterKey).catch((e) => console.warn("Integrity check failed:", e));
  } else {
    clearIntegrityBanner();
  }
}

async function runIntegrityCheck(masterKey) {
  const result = await manifest.checkIntegrity(
    user.uid, masterKey,
    entries.map((e) => ({ storageKey: e.storageKey, size: e.displayMeta?.size })),
  );
  renderIntegrityBanner(result);
}

// ─── Integrity banner ───────────────────────────────────────────────────────

let integrityBannerEl = null;

function integrityBanner() {
  if (!integrityBannerEl) {
    integrityBannerEl = document.createElement("div");
    integrityBannerEl.id = "integrity-banner";
    integrityBannerEl.style.cssText =
      "margin:0 0 1rem;padding:.7rem .9rem;border-radius:8px;font-size:.9rem;border:1px solid;display:none;";
    fileListEl.parentNode.insertBefore(integrityBannerEl, fileListEl);
  }
  return integrityBannerEl;
}

function clearIntegrityBanner() {
  if (integrityBannerEl) integrityBannerEl.style.display = "none";
}

function renderIntegrityBanner(result) {
  const el = integrityBanner();
  if (!result || result.status === "ok" || result.status === "skip") { el.style.display = "none"; return; }

  let msg;
  if (result.status === "tampered") {
    msg = "⚠ Your file manifest failed authentication — it may have been tampered with. Review your files carefully.";
  } else {
    const parts = [];
    if (result.missing?.length) parts.push(`${result.missing.length} file(s) recorded in your vault are missing from storage`);
    if (result.rolledBack)      parts.push("your file index may have been rolled back to an older version");
    msg = `⚠ Integrity check — ${parts.join("; ")}.`;
  }

  const danger = result.status === "tampered";
  el.textContent       = msg;
  el.style.background   = danger ? "rgba(255,80,80,.12)" : "rgba(255,200,60,.12)";
  el.style.borderColor  = danger ? "rgba(255,80,80,.5)"  : "rgba(255,200,60,.5)";
  el.style.color        = danger ? "#ff8a8a"             : "#ffd166";
  el.style.display      = "block";
}

function renderFileList(showLockBanner) {
  fileListEl.innerHTML = "";

  if (showLockBanner) {
    const banner = document.createElement("p");
    banner.className   = "error-msg";
    banner.textContent = "Your vault is locked, so some files can't be shown. Sign out and sign in again.";
    fileListEl.appendChild(banner);
  }

  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const icon = document.createElement("span");
    icon.className   = "empty-icon";
    icon.textContent = "☁";
    const msg = document.createElement("p");
    msg.textContent  = "No files uploaded yet.";
    empty.appendChild(icon);
    empty.appendChild(msg);
    fileListEl.appendChild(empty);
    return;
  }

  entries.forEach((entry) => {
    const { storageKey, displayMeta, locked, metadata } = entry;

    const card = document.createElement("div");
    card.className   = "file-card";
    card.dataset.key = storageKey;
    if (locked) card.style.opacity = "0.5";

    const date = displayMeta?.timestamp
      ? new Date(displayMeta.timestamp).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
      : "";

    const thumb = document.createElement("span");
    thumb.className   = "file-thumb";
    thumb.textContent = fileEmoji(displayMeta?.mimeType);

    const info = document.createElement("div");
    info.className = "file-info";

    const nameEl = document.createElement("div");
    nameEl.className   = "file-card-name";
    nameEl.textContent = displayMeta?.originalName ?? "(unknown)";

    const metaEl = document.createElement("div");
    metaEl.className   = "file-card-meta";
    metaEl.textContent = locked
      ? "encrypted"
      : `${formatBytes(displayMeta.size || 0)}${date ? " · " + date : ""}`;

    info.appendChild(nameEl);
    info.appendChild(metaEl);

    const badge = document.createElement("span");
    badge.className   = "file-badge";
    badge.textContent = metadata?.mode === "key" ? "ENC" : "ENC·V1";

    card.appendChild(thumb);
    card.appendChild(info);
    card.appendChild(badge);

    if (!locked) card.addEventListener("click", () => selectFile(entry));
    fileListEl.appendChild(card);
  });
}

function selectFile(entry) {
  selected = entry;
  document.querySelectorAll(".file-card").forEach((c) => {
    c.classList.toggle("selected", c.dataset.key === entry.storageKey);
  });
  dlFilename.textContent = entry.displayMeta?.originalName ?? "";
  showError(dlError, "");
  decPassword.value = "";

  // Only legacy v1 files need a per-file password; v2 use the vault key.
  const isV1 = entry.metadata?.mode !== "key";
  if (decPasswordField) decPasswordField.hidden = !isV1;

  // Sharing is only available for key-mode (v2) files.
  if (btnShare) btnShare.hidden = isV1;
  resetShareBox();

  downloadPanel.hidden = false;
}

// ─── Toggle password visibility ───────────────────────────────────────────

togglePassBtn?.addEventListener("click", () => {
  decPassword.type = decPassword.type === "password" ? "text" : "password";
});

// ─── Close panel ──────────────────────────────────────────────────────────

btnClosePanel?.addEventListener("click", () => {
  downloadPanel.hidden = true;
  document.querySelectorAll(".file-card").forEach((c) => c.classList.remove("selected"));
  selected = null;
  resetShareBox();
});

// ─── Download / decrypt ───────────────────────────────────────────────────

btnDownload.addEventListener("click", handleDownload);

async function handleDownload() {
  if (!selected) return;

  const meta = selected.metadata;
  const isV1 = meta?.mode !== "key";
  if (isV1 && !decPassword.value) return showError(dlError, "Please enter the decryption password.");

  showError(dlError, "");
  setLoading(btnDownload, true);

  try {
    const isV3   = meta?.mode === "key" && meta?.alg === "AES-256-GCM-STREAM";
    const size   = selected.displayMeta?.size ?? 0;
    const canStream = isV3
      && ("showSaveFilePicker" in window)
      && storageManager.getMode() !== "user"   // signed URL targets the app bucket
      && size >= STREAM_DL_THRESHOLD;

    if (canStream) {
      const masterKey = await vault.getMasterKey();
      if (!masterKey) throw new Error("Your vault is locked. Sign out and sign in again.");
      await streamingDownload(selected, masterKey);
      return;
    }

    // Buffered path — handles v1, v2, v3-small, Firefox/no-FSA, and user buckets.
    const { ciphertext, metadata } = await storageManager.downloadEncryptedFile(
      user.uid, selected.storageKey,
    );

    let result;
    if (metadata.mode === "key") {
      const masterKey = await vault.getMasterKey();
      if (!masterKey) throw new Error("Your vault is locked. Sign out and sign in again.");
      result = metadata.alg === "AES-256-GCM-STREAM"
        ? await openFileStreamWithKey(ciphertext, metadata, masterKey, selected.storageKey)
        : await openFileWithKey(ciphertext, metadata, masterKey, selected.storageKey);
    } else {
      result = await openFileWithPassword(ciphertext, metadata, decPassword.value);
    }

    const blob = new Blob([result.plaintext], { type: result.mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = result.name;
    a.click();
    URL.revokeObjectURL(url);

    decPassword.value = "";
  } catch (err) {
    console.error("Decrypt error:", err);
    showError(dlError, err.message || "Decryption failed. Please check your password.");
  } finally {
    setLoading(btnDownload, false);
  }
}

// Stream a large v3 file from the app bucket straight to a user-chosen file on
// disk: signed URL → fetch().body → decrypt segment-by-segment → WritableStream.
async function streamingDownload(entry, masterKey) {
  const name = entry.displayMeta?.originalName || "download";

  let handle;
  try {
    handle = await window.showSaveFilePicker({ suggestedName: name });
  } catch (e) {
    if (e?.name === "AbortError") return;   // user dismissed the save dialog
    throw e;
  }

  const writable = await handle.createWritable();
  try {
    const path = `users/${user.uid}/files/${entry.storageKey}.enc`;
    const { data, error } = await supabase.storage.from(BUCKET).createSignedUrl(path, 180);
    if (error || !data?.signedUrl) throw new Error(`Couldn't get a download URL: ${error?.message || "unknown error"}`);

    const resp = await fetch(data.signedUrl);
    if (!resp.ok || !resp.body) throw new Error(`Download failed (HTTP ${resp.status}).`);

    await decryptStreamToSink(resp.body, entry.metadata, masterKey, entry.storageKey, async (chunk) => {
      await writable.write(chunk);
    });
    await writable.close();
  } catch (e) {
    try { await writable.abort(); } catch { /* ignore */ }
    throw e;
  }
}

// ─── Delete ───────────────────────────────────────────────────────────────

btnDelete?.addEventListener("click", async () => {
  if (!selected) return;
  if (!confirm("Permanently delete this file? This cannot be undone.")) return;

  try {
    await storageManager.deleteFile(user.uid, selected.storageKey);

    if (storageManager.getMode() !== "user") {
      const mk = await vault.getMasterKey();
      if (mk) {
        try { await manifest.removeFileFromManifest(user.uid, mk, selected.storageKey); }
        catch (e) { console.warn("Manifest update (remove) failed:", e); }
      }
    }

    downloadPanel.hidden = true;
    selected             = null;
    await loadFileList();
  } catch (err) {
    console.error("Delete error:", err);
    showError(dlError, "Failed to delete file.");
  }
});

// ─── Share ────────────────────────────────────────────────────────────────

function resetShareBox() {
  if (!shareBox) return;
  shareBox.hidden    = true;
  shareVerify.hidden = true;
  shareStatus.hidden = true;
  shareEmail.value   = "";
  pendingRecipient   = null;
}

function showShareStatus(msg, type) {
  shareStatus.textContent = msg;
  shareStatus.className    = `config-status ${type}`;
  shareStatus.hidden       = !msg;
}

btnShare?.addEventListener("click", () => {
  if (shareBox.hidden) shareBox.hidden = false;
  else resetShareBox();
});

btnShareLookup?.addEventListener("click", async () => {
  const email = shareEmail.value.trim().toLowerCase();
  shareVerify.hidden = true;
  pendingRecipient   = null;
  if (!email) return showShareStatus("Enter a recipient email.", "error");
  if (email === (user.email || "").toLowerCase()) {
    return showShareStatus("You can't share a file with yourself.", "error");
  }

  showShareStatus("Looking up recipient…", "info");
  try {
    const rec = await lookupRecipient(email);
    if (!rec || !rec.publicKey) {
      return showShareStatus("No VaultSync user with that email (they need an account with sharing enabled).", "error");
    }
    pendingRecipient = { ...rec, email };
    shareFingerprint.textContent = await publicKeyFingerprint(rec.publicKey);
    shareVerify.hidden = false;
    showShareStatus("", "");
  } catch (err) {
    showShareStatus(err.message || "Lookup failed.", "error");
  }
});

btnShareConfirm?.addEventListener("click", async () => {
  if (!selected || !pendingRecipient) return;
  const masterKey = await vault.getMasterKey();
  if (!masterKey) return showShareStatus("Your vault is locked. Sign out and sign in again.", "error");

  btnShareConfirm.disabled = true;
  showShareStatus("Sharing…", "info");
  try {
    await sharing.createShare({
      ownerUid:           user.uid,
      ownerEmail:         user.email,
      storageKey:         selected.storageKey,
      fileMetadata:       selected.metadata,
      masterKey,
      recipientUid:       pendingRecipient.uid,
      recipientPublicKey: pendingRecipient.publicKey,
    });
    showShareStatus(`Shared with ${pendingRecipient.email}. ⇄`, "success");
    shareVerify.hidden = true;
  } catch (err) {
    showShareStatus(err.message || "Sharing failed.", "error");
  } finally {
    btnShareConfirm.disabled = false;
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  markLoggedOut();
  navigateTo("login.html");
});
