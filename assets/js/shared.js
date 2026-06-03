/**
 * shared.js
 * ─────────
 * Page controller for shared.html ("Shared with me").
 *   • Shows your own key fingerprint (so senders can verify).
 *   • Lists incoming shares and, on download, unwraps the shared DEK with your
 *     X25519 private key and decrypts the file — all in the browser.
 */

import { requireAuth, navigateTo, markLoggedOut } from "./router.js";
import { logoutUser } from "./auth.js";
import {
  unwrapSharingPrivateKey, unwrapSharedDEK, openFileWithSharedDEK, publicKeyFingerprint,
} from "./crypto-utils.js";
import * as vault   from "./vault.js";
import * as sharing from "./sharing.js";

// ─── Boot ─────────────────────────────────────────────────────────────────

const user = await requireAuth("login.html");

// ─── DOM refs ─────────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const shareListEl    = $("share-list");
const btnRefresh     = $("btn-refresh");
const recvPanel      = $("recv-panel");
const recvFrom       = $("recv-from");
const btnRecvClose   = $("btn-recv-close");
const btnRecvDownload = $("btn-recv-download");
const btnRecvRemove  = $("btn-recv-remove");
const recvError      = $("recv-error");
const myFingerprint  = $("my-fingerprint");
const btnLogout      = $("btn-logout");

// ─── State ────────────────────────────────────────────────────────────────

let shares   = [];
let selected = null;

// ─── Init ─────────────────────────────────────────────────────────────────

$("user-email").textContent = user.email;
showMyFingerprint();
loadShares();

// ─── Helpers ──────────────────────────────────────────────────────────────

function setLoading(btn, loading) {
  btn.querySelector(".btn-label").hidden   = loading;
  btn.querySelector(".btn-spinner").hidden = !loading;
  btn.disabled = loading;
}

function showError(el, message) {
  el.textContent = message;
  el.hidden      = !message;
}

async function showMyFingerprint() {
  try {
    const pub = await vault.getPublicKey(user.uid);
    myFingerprint.textContent = pub ? await publicKeyFingerprint(pub) : "(sharing unavailable)";
  } catch {
    myFingerprint.textContent = "(unavailable)";
  }
}

// ─── Share list ───────────────────────────────────────────────────────────

btnRefresh?.addEventListener("click", loadShares);

async function loadShares() {
  shareListEl.innerHTML = `<p class="loading-msg">Loading…</p>`;
  recvPanel.hidden = true;
  selected = null;

  try {
    shares = await sharing.listIncomingShares(user.uid);
  } catch (err) {
    const p = document.createElement("p");
    p.className   = "error-msg";
    p.textContent = err.message;
    shareListEl.innerHTML = "";
    shareListEl.appendChild(p);
    console.error("List shares error:", err);
    return;
  }

  renderShares();
}

function renderShares() {
  shareListEl.innerHTML = "";

  if (!shares.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    const icon = document.createElement("span");
    icon.className   = "empty-icon";
    icon.textContent = "⇄";
    const msg = document.createElement("p");
    msg.textContent  = "Nothing shared with you yet.";
    empty.appendChild(icon);
    empty.appendChild(msg);
    shareListEl.appendChild(empty);
    return;
  }

  shares.forEach((s) => {
    const card = document.createElement("div");
    card.className   = "file-card";
    card.dataset.key = s.shareId;

    const date = s.sharedAt
      ? new Date(s.sharedAt).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
      : "";

    const thumb = document.createElement("span");
    thumb.className   = "file-thumb";
    thumb.textContent = "⇄";

    const info = document.createElement("div");
    info.className = "file-info";

    const nameEl = document.createElement("div");
    nameEl.className   = "file-card-name";
    nameEl.textContent = `From ${s.ownerEmail || "someone"}`;   // textContent — safe

    const metaEl = document.createElement("div");
    metaEl.className   = "file-card-meta";
    metaEl.textContent = date ? `shared ${date}` : "shared file";

    info.appendChild(nameEl);
    info.appendChild(metaEl);

    const badge = document.createElement("span");
    badge.className   = "file-badge";
    badge.textContent = "SHARED";

    card.appendChild(thumb);
    card.appendChild(info);
    card.appendChild(badge);

    card.addEventListener("click", () => selectShare(s));
    shareListEl.appendChild(card);
  });
}

function selectShare(s) {
  selected = s;
  document.querySelectorAll(".file-card").forEach((c) => {
    c.classList.toggle("selected", c.dataset.key === s.shareId);
  });
  recvFrom.textContent = `Shared by ${s.ownerEmail || "someone"}`;
  showError(recvError, "");
  recvPanel.hidden = false;
}

// ─── Close panel ──────────────────────────────────────────────────────────

btnRecvClose?.addEventListener("click", () => {
  recvPanel.hidden = true;
  document.querySelectorAll(".file-card").forEach((c) => c.classList.remove("selected"));
  selected = null;
});

// ─── Download / decrypt ─────────────────────────────────────────────────────

btnRecvDownload.addEventListener("click", handleDownload);

async function handleDownload() {
  if (!selected) return;

  const masterKey = await vault.getMasterKey();
  if (!masterKey) return showError(recvError, "Your vault is locked. Sign out and sign in again.");

  showError(recvError, "");
  setLoading(btnRecvDownload, true);

  try {
    // Unwrap our X25519 private key, then the shared DEK.
    const keyvault = await vault.fetchKeyvault(user.uid);
    const privKey  = await unwrapSharingPrivateKey(keyvault, masterKey);
    const dek      = await unwrapSharedDEK(selected.share, privKey);

    // Fetch the owner's ciphertext + metadata and decrypt.
    const { ciphertext, metadata } = await sharing.downloadSharedBlob(selected.ownerUid, selected.storageKey);
    const out = await openFileWithSharedDEK(ciphertext, metadata, dek, selected.storageKey);

    const blob = new Blob([out.plaintext], { type: out.mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = out.name;
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error("Shared decrypt error:", err);
    showError(recvError, err.message || "Couldn't decrypt this shared file.");
  } finally {
    setLoading(btnRecvDownload, false);
  }
}

// ─── Remove share ───────────────────────────────────────────────────────────

btnRecvRemove?.addEventListener("click", async () => {
  if (!selected) return;
  if (!confirm("Remove this shared item from your list? (The owner's file is not affected.)")) return;
  try {
    await sharing.deleteIncomingShare(user.uid, selected.shareId);
    recvPanel.hidden = true;
    selected = null;
    await loadShares();
  } catch (err) {
    console.error("Remove share error:", err);
    showError(recvError, "Failed to remove the share.");
  }
});

// ─── Logout ───────────────────────────────────────────────────────────────

btnLogout?.addEventListener("click", async () => {
  await logoutUser();
  markLoggedOut();
  navigateTo("login.html");
});
