/**
 * download.js
 * ───────────
 * Page controller for files.html.
 * Lists encrypted files, handles file selection, decryption, and download.
 * Delegates all crypto to crypto-utils.js and all storage to storage-manager.js.
 */

import { requireAuth, navigateTo, markLoggedOut } from "./router.js";
import { logoutUser }               from "./auth.js";
import { decryptFileWithPassword }  from "./crypto-utils.js";
import * as storageManager          from "./storage-manager.js";

// ─── Boot ─────────────────────────────────────────────────────────────────

const user = await requireAuth("login.html");
await storageManager.initFromStorage();

// ─── DOM refs ─────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const fileListEl    = $("file-list");
const btnRefresh    = $("btn-refresh");
const downloadPanel = $("download-panel");
const dlFilename    = $("dl-filename");
const btnClosePanel = $("btn-close-panel");
const decPassword   = $("dec-password");
const togglePassBtn = $("toggle-dec-pass");
const btnDownload   = $("btn-download");
const btnDelete     = $("btn-delete");
const dlError       = $("dl-error");
const storageBadgeEl = $("storage-badge");
const btnLogout     = $("btn-logout");

// ─── State ────────────────────────────────────────────────────────────────

let fileList        = [];
let selectedFileKey = null;

// ─── Init ─────────────────────────────────────────────────────────────────

renderStorageBadge();
document.getElementById("user-email").textContent = user.email;
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

// ─── File list ────────────────────────────────────────────────────────────

btnRefresh?.addEventListener("click", loadFileList);

async function loadFileList() {
  fileListEl.innerHTML = `<p class="loading-msg">Loading…</p>`;
  downloadPanel.hidden = true;
  selectedFileKey      = null;

  try {
    fileList = await storageManager.listUserFiles(user.uid);
  } catch (err) {
    fileListEl.innerHTML = `<p class="error-msg">${err.message}</p>`;
    console.error("List error:", err);
    return;
  }

  renderFileList();
}

function renderFileList() {
  fileListEl.innerHTML = "";

  if (!fileList.length) {
    fileListEl.innerHTML = `
      <div class="empty-state">
        <span class="empty-icon">☁</span>
        <p>No files uploaded yet.</p>
      </div>`;
    return;
  }

  fileList.forEach(({ storageKey, metadata }) => {
    const card = document.createElement("div");
    card.className   = "file-card";
    card.dataset.key = storageKey;

    const date = new Date(metadata.timestamp).toLocaleDateString(undefined, {
      year: "numeric", month: "short", day: "numeric",
    });

    card.innerHTML = `
      <span class="file-thumb">${fileEmoji(metadata.mimeType)}</span>
      <div class="file-info">
        <div class="file-card-name">${metadata.originalName}</div>
        <div class="file-card-meta">${formatBytes(metadata.size)} · ${date}</div>
      </div>
      <span class="file-badge">ENC</span>
    `;

    card.addEventListener("click", () => selectFile(storageKey, metadata));
    fileListEl.appendChild(card);
  });
}

function selectFile(storageKey, metadata) {
  document.querySelectorAll(".file-card").forEach((c) => {
    c.classList.toggle("selected", c.dataset.key === storageKey);
  });
  selectedFileKey        = storageKey;
  dlFilename.textContent = metadata.originalName;
  showError(dlError, "");
  decPassword.value    = "";
  downloadPanel.hidden = false;
}

// ─── Toggle password visibility ───────────────────────────────────────────

togglePassBtn?.addEventListener("click", () => {
  decPassword.type = decPassword.type === "password" ? "text" : "password";
});

// ─── Close panel ─────────────────────────────────────────────────────────

btnClosePanel?.addEventListener("click", () => {
  downloadPanel.hidden = true;
  document.querySelectorAll(".file-card").forEach((c) => c.classList.remove("selected"));
  selectedFileKey = null;
});

// ─── Download / decrypt ───────────────────────────────────────────────────

btnDownload.addEventListener("click", handleDownload);

async function handleDownload() {
  if (!selectedFileKey) return;
  const password = decPassword.value;
  if (!password) return showError(dlError, "Please enter the decryption password.");

  showError(dlError, "");
  setLoading(btnDownload, true);

  try {
    const { ciphertext, metadata } = await storageManager.downloadEncryptedFile(
      user.uid, selectedFileKey,
    );

    const { plaintext, name, mimeType } = await decryptFileWithPassword(
      ciphertext, metadata, password,
    );

    const blob = new Blob([plaintext], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);

    showError(dlError, "");
    decPassword.value = "";
  } catch (err) {
    console.error("Decrypt error:", err);
    showError(dlError, err.message || "Decryption failed. Please check your password.");
  } finally {
    setLoading(btnDownload, false);
  }
}

// ─── Delete ───────────────────────────────────────────────────────────────

btnDelete?.addEventListener("click", async () => {
  if (!selectedFileKey) return;
  if (!confirm("Permanently delete this file? This cannot be undone.")) return;

  try {
    await storageManager.deleteFile(user.uid, selectedFileKey);
    downloadPanel.hidden = true;
    selectedFileKey      = null;
    await loadFileList();
  } catch (err) {
    console.error("Delete error:", err);
    showError(dlError, "Failed to delete file.");
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  markLoggedOut();
  navigateTo("login.html");
});
