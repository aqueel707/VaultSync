/**
 * manifest.js
 * ───────────
 * Maintains the integrity manifest — a signed index of the user's files stored
 * at users/<uid>/manifest.json in the app bucket. The crypto (seal/open/
 * reconcile) lives in crypto-utils; this module is the storage + orchestration.
 *
 * Primary signal: DELETION / suppression — a file recorded in the manifest but
 * absent from the live listing. Extras (present but unrecorded) are self-healed
 * in, since a file that an attacker injected without the vault key fails to
 * decrypt and already shows as a locked entry. A device-local seq pin gives a
 * best-effort rollback tripwire.
 *
 * Managed (app bucket) only — mirrors sharing/streaming. User-bucket mode skips.
 */

import { supabase, BUCKET } from "./supabase-client.js";
import { sealManifest, openManifest, reconcileManifest } from "./crypto-utils.js";

const manifestPath = (uid) => `users/${uid}/manifest.json`;

// ─── Storage I/O ────────────────────────────────────────────────────────────

async function fetchManifestDoc(uid) {
  const { data, error } = await supabase.storage.from(BUCKET).download(manifestPath(uid));
  if (error) {
    const m = (error.message || "").toLowerCase();
    if (m.includes("not found") || m.includes("no such") ||
        error.status === 404 || error.statusCode === 404 || error.statusCode === "404") {
      return null;                       // genuinely absent
    }
    throw new Error(`Manifest fetch failed: ${error.message}`);
  }
  let text;
  try { text = await data.text(); } catch { throw new Error("Manifest read failed."); }
  try { return JSON.parse(text); } catch { return { __corrupt: true }; }
}

async function putManifestDoc(uid, doc) {
  const { error } = await supabase.storage.from(BUCKET).upload(
    manifestPath(uid),
    new Blob([JSON.stringify(doc)], { type: "application/json" }),
    { upsert: true },
  );
  if (error) throw new Error(`Failed to save manifest: ${error.message}`);
}

/** @returns {{status:"ok",body}|{status:"absent"}|{status:"tampered"}|{status:"error",error}} */
async function loadManifest(uid, masterKey) {
  let doc;
  try { doc = await fetchManifestDoc(uid); }
  catch (e) { return { status: "error", error: e }; }
  if (!doc) return { status: "absent" };
  if (doc.__corrupt) return { status: "tampered" };
  try { return { status: "ok", body: await openManifest(doc, masterKey, uid) }; }
  catch { return { status: "tampered" }; }
}

async function saveManifest(uid, masterKey, body) {
  await putManifestDoc(uid, await sealManifest(body, masterKey, uid));
}

function bumpBody(prev, files) {
  return { seq: (prev?.seq ?? 0) + 1, updatedAt: new Date().toISOString(), files };
}

// ─── Incremental maintenance (no-op unless a good manifest already exists) ───

export async function addFileToManifest(uid, masterKey, entry) {
  const res = await loadManifest(uid, masterKey);
  if (res.status !== "ok") return null;          // load-time check will bootstrap/heal
  const files = (res.body.files || []).filter((f) => f.storageKey !== entry.storageKey);
  files.push({ storageKey: entry.storageKey, size: entry.size ?? null, addedAt: entry.addedAt ?? new Date().toISOString() });
  const next = bumpBody(res.body, files);
  await saveManifest(uid, masterKey, next);
  await setPinnedSeq(uid, next.seq);
  return next;
}

export async function removeFileFromManifest(uid, masterKey, storageKey) {
  const res = await loadManifest(uid, masterKey);
  if (res.status !== "ok") return null;
  const files = (res.body.files || []).filter((f) => f.storageKey !== storageKey);
  const next = bumpBody(res.body, files);
  await saveManifest(uid, masterKey, next);
  await setPinnedSeq(uid, next.seq);
  return next;
}

async function bootstrapManifest(uid, masterKey, entries) {
  const files = entries.map((e) => ({ storageKey: e.storageKey, size: e.size ?? null, addedAt: e.addedAt ?? null }));
  const body  = { seq: 1, updatedAt: new Date().toISOString(), files };
  await saveManifest(uid, masterKey, body);
  return body;
}

// ─── Load-time integrity check (bootstrap + self-heal + report) ──────────────

/**
 * @param {string} uid
 * @param {CryptoKey} masterKey
 * @param {Array<{storageKey:string, size?:number}>} entries  the live listing
 * @returns {{ status:"ok"|"warn"|"tampered"|"skip", missing:string[], rolledBack:boolean }}
 */
export async function checkIntegrity(uid, masterKey, entries) {
  const pinnedSeq   = await getPinnedSeq(uid);
  const res         = await loadManifest(uid, masterKey);
  const storageKeys = entries.map((e) => e.storageKey);

  if (res.status === "error")   return { status: "skip",     missing: [], rolledBack: false };
  if (res.status === "tampered") return { status: "tampered", missing: [], rolledBack: false };
  if (res.status === "absent") {
    const body = await bootstrapManifest(uid, masterKey, entries);
    await setPinnedSeq(uid, body.seq);
    return { status: "ok", missing: [], rolledBack: false };
  }

  const body = res.body;
  const { missing, extra } = reconcileManifest(body, storageKeys);
  const rolledBack = pinnedSeq >= 0 && (body.seq ?? 0) < pinnedSeq;

  let seq = body.seq ?? 0;
  if (extra.length) {
    const byKey     = Object.fromEntries(entries.map((e) => [e.storageKey, e]));
    const additions = extra.map((k) => ({ storageKey: k, size: byKey[k]?.size ?? null, addedAt: null }));
    try {
      const next = bumpBody(body, [...(body.files || []), ...additions]);
      await saveManifest(uid, masterKey, next);
      seq = next.seq;
    } catch (e) { console.warn("Manifest self-heal save failed:", e); }
  }

  await setPinnedSeq(uid, Math.max(seq, pinnedSeq));
  return { status: (missing.length || rolledBack) ? "warn" : "ok", missing, rolledBack };
}

// ─── Device-local seq pin (rollback tripwire) ────────────────────────────────

const PIN_DB = "vaultsync-integrity";

function pinDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(PIN_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore("pins");
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

export async function getPinnedSeq(uid) {
  try {
    const db = await pinDB();
    return await new Promise((resolve) => {
      const r = db.transaction("pins", "readonly").objectStore("pins").get(uid);
      r.onsuccess = () => resolve(Number.isFinite(r.result) ? r.result : -1);
      r.onerror   = () => resolve(-1);
    });
  } catch { return -1; }
}

export async function setPinnedSeq(uid, seq) {
  try {
    const db = await pinDB();
    await new Promise((resolve) => {
      const r = db.transaction("pins", "readwrite").objectStore("pins").put(seq, uid);
      r.onsuccess = () => resolve();
      r.onerror   = () => resolve();
    });
  } catch { /* non-fatal */ }
}
