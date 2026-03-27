/**
 * encrypt-local.js
 * ─────────────────
 * Page controller for encrypt.html.
 * Encrypts a file entirely in the browser and triggers two downloads:
 *   filename.enc       — the AES-256-GCM encrypted blob
 *   filename.meta.json — salt, IVs, wrappedDEK, originalName, mimeType, etc.
 *
 * No cloud storage used. No network requests made.
 * Uses the exact same crypto-utils.js pipeline as the upload flow.
 */

import { requireAuth }             from "./router.js";
import { logoutUser }              from "./auth.js";
import { encryptFileWithPassword } from "./crypto-utils.js";
import * as storageManager         from "./storage-manager.js";

// ─── Boot ─────────────────────────────────────────────────────────────────────
const user = await requireAuth("login.html");
await storageManager.initFromStorage();

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

const dropZone        = $("drop-zone");
const fileInput       = $("file-input");
const selectedFilesEl = $("selected-files");
const encPassword     = $("enc-password");
const togglePassBtn   = $("toggle-enc-pass");
const strengthWrap    = $("strength-wrap");
const strengthFill    = $("strength-fill");
const strengthLabel   = $("strength-label");
const btnEncrypt      = $("btn-encrypt");
const statusToast     = $("status-toast");
const outputPanel     = $("output-panel");
const outEncName      = $("out-enc-name");
const outMetaName     = $("out-meta-name");
const storageBadgeEl  = $("storage-badge");
const userEmailEl     = $("user-email");
const btnLogout       = $("btn-logout");

// ─── State ────────────────────────────────────────────────────────────────────
let selectedFile = null;

// ─── Init ─────────────────────────────────────────────────────────────────────
userEmailEl.textContent = user.email;
renderStorageBadge();

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
  statusToast._t = setTimeout(() => { statusToast.hidden = true; }, 5000);
}

function updateBtn() {
  btnEncrypt.disabled = !(selectedFile && encPassword.value.length > 0);
}

function renderStorageBadge() {
  if (!storageBadgeEl) return;
  const mode = storageManager.getMode();
  storageBadgeEl.textContent = mode === "user" ? "Your Storage" : "App Storage";
  storageBadgeEl.className   = `storage-badge ${mode}`;
}

/**
 * Trigger a browser file download from an ArrayBuffer or string.
 * @param {ArrayBuffer|string} content
 * @param {string}             filename
 * @param {string}             mimeType
 */
function triggerDownload(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Password strength ────────────────────────────────────────────────────────

function getStrength(pw) {
  let score = 0;
  if (pw.length >= 8)          score++;
  if (pw.length >= 14)         score++;
  if (/[A-Z]/.test(pw))        score++;
  if (/[0-9]/.test(pw))        score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["Weak","Weak","Fair","Good","Strong","Strong"];
  const colors = ["#ff4d6d","#ff4d6d","#f7c948","#f7c948","#00e5a0","#00e5a0"];
  return { label: labels[score], color: colors[score], pct: (score / 5) * 100 };
}

encPassword.addEventListener("input", () => {
  const pw = encPassword.value;
  strengthWrap.hidden = !pw;
  if (!pw) { updateBtn(); return; }
  const { label, color, pct } = getStrength(pw);
  strengthFill.style.width      = `${pct}%`;
  strengthFill.style.background = color;
  strengthLabel.textContent     = label;
  updateBtn();
});

// ─── Toggle password visibility ───────────────────────────────────────────────

togglePassBtn?.addEventListener("click", () => {
  encPassword.type = encPassword.type === "password" ? "text" : "password";
});

// ─── File selection ───────────────────────────────────────────────────────────

fileInput.addEventListener("change", () => {
  selectedFile = fileInput.files[0] ?? null;
  renderSelected();
  updateBtn();
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
  selectedFile = e.dataTransfer.files[0] ?? null;
  renderSelected();
  updateBtn();
});

function renderSelected() {
  selectedFilesEl.innerHTML = "";
  if (!selectedFile) return;
  const item = document.createElement("div");
  item.className = "selected-file-item";
  item.innerHTML = `
    <span class="file-name">${selectedFile.name}</span>
    <span>${formatBytes(selectedFile.size)}</span>
  `;
  selectedFilesEl.appendChild(item);
}

// ─── Encrypt & download pipeline ──────────────────────────────────────────────

btnEncrypt.addEventListener("click", handleEncrypt);

async function handleEncrypt() {
  const password = encPassword.value;
  if (!password)    return showToast("Please enter an encryption password.", "error");
  if (!selectedFile) return showToast("Please select a file.", "error");

  setLoading(btnEncrypt, true);
  outputPanel.hidden = true;

  try {
    // Encrypt using the exact same pipeline as the cloud upload flow
    const { ciphertext, metadata } = await encryptFileWithPassword(selectedFile, password);

    // Build filenames
    const baseName   = selectedFile.name;
    const encName    = `${baseName}.enc`;
    const metaName   = `${baseName}.meta.json`;

    // Download encrypted blob
    triggerDownload(ciphertext, encName, "application/octet-stream");

    // Small delay so browser doesn't block the second download
    await new Promise((r) => setTimeout(r, 300));

    // Download metadata JSON
    triggerDownload(
      JSON.stringify(metadata, null, 2),
      metaName,
      "application/json",
    );

    // Show output panel
    outEncName.textContent  = encName;
    outMetaName.textContent = metaName;
    outputPanel.hidden      = false;

    showToast(`${baseName} encrypted successfully. Check your Downloads folder. 🔒`);

    // Reset form
    encPassword.value         = "";
    strengthWrap.hidden       = true;
    selectedFile              = null;
    selectedFilesEl.innerHTML = "";
    fileInput.value           = "";
    updateBtn();

  } catch (err) {
    console.error("Encryption error:", err);
    showToast(`Encryption failed: ${err.message}`, "error");
  } finally {
    setLoading(btnEncrypt, false);
  }
}

// ─── Logout ───────────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  window.location.href = "login.html";
});