/**
 * decrypt-local.js
 * ─────────────────
 * Page controller for decrypt.html.
 * User uploads their local .enc and .meta.json files, enters their password,
 * and the browser decrypts and downloads the original file.
 *
 * No cloud storage used. No network requests made.
 * Uses the exact same crypto-utils.js pipeline as the cloud download flow.
 */

import { requireAuth }              from "./router.js";
import { logoutUser }               from "./auth.js";
import { decryptFileWithPassword }  from "./crypto-utils.js";
import * as storageManager          from "./storage-manager.js";

// ─── Boot ─────────────────────────────────────────────────────────────────────
const user = await requireAuth("login.html");
await storageManager.initFromStorage();

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const encFileInput   = $("enc-file-input");
const metaFileInput  = $("meta-file-input");
const encFileName    = $("enc-file-name");
const metaFileName   = $("meta-file-name");
const decPassword    = $("dec-password");
const togglePassBtn  = $("toggle-dec-pass");
const btnDecrypt     = $("btn-decrypt");
const decryptError   = $("decrypt-error");
const statusToast    = $("status-toast");
const storageBadgeEl = $("storage-badge");
const userEmailEl    = $("user-email");
const btnLogout      = $("btn-logout");

// ─── State ────────────────────────────────────────────────────────────────────
let encFile  = null;
let metaFile = null;

// ─── Init ─────────────────────────────────────────────────────────────────────
userEmailEl.textContent = user.email;
renderStorageBadge();

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setLoading(btn, loading) {
  btn.querySelector(".btn-label").hidden   = loading;
  btn.querySelector(".btn-spinner").hidden = !loading;
  btn.disabled = loading;
}

function showError(message) {
  decryptError.textContent = message;
  decryptError.hidden      = !message;
}

function showToast(message, type = "success") {
  statusToast.textContent = message;
  statusToast.className   = `toast ${type}`;
  statusToast.hidden      = false;
  clearTimeout(statusToast._t);
  statusToast._t = setTimeout(() => { statusToast.hidden = true; }, 5000);
}

function updateBtn() {
  btnDecrypt.disabled = !(encFile && metaFile && decPassword.value.length > 0);
}

function renderStorageBadge() {
  if (!storageBadgeEl) return;
  const mode = storageManager.getMode();
  storageBadgeEl.textContent = mode === "user" ? "Your Storage" : "App Storage";
  storageBadgeEl.className   = `storage-badge ${mode}`;
}

// ─── Toggle password visibility ───────────────────────────────────────────────

togglePassBtn?.addEventListener("click", () => {
  decPassword.type = decPassword.type === "password" ? "text" : "password";
});

// ─── File inputs ──────────────────────────────────────────────────────────────

encFileInput.addEventListener("change", () => {
  encFile = encFileInput.files[0] ?? null;
  encFileName.textContent = encFile ? encFile.name : "Click to select your .enc file";
  encFileName.style.color = encFile ? "var(--accent)" : "";
  showError("");
  updateBtn();
});

metaFileInput.addEventListener("change", () => {
  metaFile = metaFileInput.files[0] ?? null;
  metaFileName.textContent = metaFile ? metaFile.name : "Click to select your .meta.json file";
  metaFileName.style.color = metaFile ? "var(--accent)" : "";
  showError("");
  updateBtn();
});

decPassword.addEventListener("input", () => {
  showError("");
  updateBtn();
});

// ─── Decrypt & download pipeline ──────────────────────────────────────────────

btnDecrypt.addEventListener("click", handleDecrypt);

async function handleDecrypt() {
  const password = decPassword.value;
  if (!password)  return showError("Please enter the decryption password.");
  if (!encFile)   return showError("Please select the .enc file.");
  if (!metaFile)  return showError("Please select the .meta.json file.");

  showError("");
  setLoading(btnDecrypt, true);

  try {
    // Read both files
    const ciphertext  = await encFile.arrayBuffer();
    const metaText    = await metaFile.text();
    const metadata    = JSON.parse(metaText);

    // Decrypt using the exact same pipeline as the cloud download flow
    const { plaintext, name, mimeType } = await decryptFileWithPassword(
      ciphertext, metadata, password,
    );

    // Trigger browser download of the original file
    const blob = new Blob([plaintext], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);

    showToast(`${name} decrypted and downloaded successfully. 🔓`);

    // Reset
    decPassword.value        = "";
    encFile                  = null;
    metaFile                 = null;
    encFileInput.value       = "";
    metaFileInput.value      = "";
    encFileName.textContent  = "Click to select your .enc file";
    metaFileName.textContent = "Click to select your .meta.json file";
    encFileName.style.color  = "";
    metaFileName.style.color = "";
    updateBtn();

  } catch (err) {
    console.error("Decrypt error:", err);
    showError(err.message || "Decryption failed. Check your password and files.");
  } finally {
    setLoading(btnDecrypt, false);
  }
}

// ─── Logout ───────────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  window.location.href = "login.html";
});