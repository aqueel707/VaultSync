/**
 * upload.js  (key-mode / v3 streaming)
 * ──────────────────────────
 * Page controller for upload.html.
 * Encrypts each file under the account's VAULT MASTER KEY (no per-file password)
 * and uploads ciphertext + encrypted metadata.
 * Crypto → crypto-utils.js, storage → storage-manager.js, master key → vault.js.
 */

import { requireAuth, navigateTo, markLoggedOut } from "./router.js";
import { logoutUser }      from "./auth.js";
import { sealFileStreamWithKey } from "./crypto-utils.js";
import * as storageManager from "./storage-manager.js";
import * as vault          from "./vault.js";

// ─── Boot ─────────────────────────────────────────────────────────────────

const user = await requireAuth("login.html");
await storageManager.initFromStorage();

// ─── DOM refs ─────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const dropZone        = $("drop-zone");
const fileInput       = $("file-input");
const selectedFilesEl = $("selected-files");
const btnUpload       = $("btn-upload");
const progressSection = $("upload-progress");
const progressFill    = $("progress-fill");
const progressLabel   = $("progress-label");
const statusToast     = $("status-toast");
const storageBadgeEl  = $("storage-badge");
const btnLogout       = $("btn-logout");

// ─── State ────────────────────────────────────────────────────────────────

let selectedFiles = [];

// ─── Init ─────────────────────────────────────────────────────────────────

renderStorageBadge();
$("user-email").textContent = user.email;

// Warn early if the vault isn't unlocked (e.g. after a Firebase password reset).
vault.getMasterKey().then((mk) => {
  if (!mk) showToast("Your vault is locked. Please sign out and sign in again.", "error");
});

// ─── Helpers ──────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)      return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1_048_576).toFixed(2)} MB`;
}

function setLoading(btn, loading) {
  btn.querySelector(".btn-label").hidden   = loading;
  btn.querySelector(".btn-spinner").hidden = !loading;
  btn.disabled = loading;
}

function showToast(message, type = "success") {
  statusToast.textContent = message;
  statusToast.className   = `toast ${type}`;
  statusToast.hidden      = false;
  clearTimeout(statusToast._t);
  statusToast._t = setTimeout(() => { statusToast.hidden = true; }, 4500);
}

function updateProgress(pct, label) {
  progressSection.hidden    = false;
  progressFill.style.width  = `${pct}%`;
  progressLabel.textContent = label;
}

function renderStorageBadge() {
  if (!storageBadgeEl) return;
  const mode = storageManager.getMode();
  storageBadgeEl.textContent = mode === "user" ? "Your Storage" : "App Storage";
  storageBadgeEl.className   = `storage-badge ${mode}`;
}

function updateUploadBtn() {
  btnUpload.disabled = selectedFiles.length === 0;
}

// ─── File selection ───────────────────────────────────────────────────────

fileInput.addEventListener("change", () => {
  selectedFiles = Array.from(fileInput.files);
  renderSelectedFiles();
  updateUploadBtn();
});

dropZone.addEventListener("click", (e) => {
  if (e.target.tagName !== "LABEL") fileInput.click();
});
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  selectedFiles = Array.from(e.dataTransfer.files);
  renderSelectedFiles();
  updateUploadBtn();
});

function renderSelectedFiles() {
  selectedFilesEl.innerHTML = "";
  selectedFiles.forEach((f) => {
    const item = document.createElement("div");
    item.className = "selected-file-item";

    // Safe DOM — textContent only, never innerHTML with a filename.
    const nameSpan = document.createElement("span");
    nameSpan.className   = "file-name";
    nameSpan.textContent = f.name;

    const sizeSpan = document.createElement("span");
    sizeSpan.textContent = formatBytes(f.size);

    item.appendChild(nameSpan);
    item.appendChild(sizeSpan);
    selectedFilesEl.appendChild(item);
  });
}

// ─── Upload pipeline ──────────────────────────────────────────────────────

btnUpload.addEventListener("click", handleUpload);

async function handleUpload() {
  if (!selectedFiles.length) return showToast("Please select at least one file.", "error");

  const masterKey = await vault.getMasterKey();
  if (!masterKey) return showToast("Your vault is locked. Please sign out and sign in again.", "error");

  setLoading(btnUpload, true);

  let ok = 0, fail = 0;

  for (let i = 0; i < selectedFiles.length; i++) {
    const file   = selectedFiles[i];
    const prefix = `[${i + 1}/${selectedFiles.length}] ${file.name}`;

    try {
      updateProgress(5, `${prefix} — Encrypting…`);
      const storageKey = storageManager.generateStorageKey();   // also the AAD binding
      const { ciphertext, metadata } = await sealFileStreamWithKey(file, masterKey, storageKey);

      updateProgress(30, `${prefix} — Uploading…`);
      await storageManager.uploadEncryptedFile(
        user.uid, storageKey, ciphertext, metadata,
        (pct, step) => updateProgress(30 + Math.round(pct * 0.65), `${prefix} — ${step}`),
      );

      ok++;
    } catch (err) {
      console.error("Upload error:", err);
      fail++;
    }
  }

  setLoading(btnUpload, false);

  if (ok > 0) {
    const dest = storageManager.getMode() === "user" ? "your bucket" : "app storage";
    updateProgress(100, "All uploads complete.");
    showToast(`${ok} file(s) encrypted & uploaded to ${dest}. 🔒`);
    selectedFiles             = [];
    selectedFilesEl.innerHTML = "";
    fileInput.value           = "";
    updateUploadBtn();
  }
  if (fail > 0) showToast(`${fail} file(s) failed to upload.`, "error");

  setTimeout(() => { progressSection.hidden = true; }, 3500);
}

// ─── Logout ───────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  markLoggedOut();
  navigateTo("login.html");
});
