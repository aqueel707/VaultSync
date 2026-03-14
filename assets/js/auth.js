/**
 * auth.js
 * ───────
 * Firebase Authentication for VaultSync.
 * Owns the DEFAULT Firebase app instance and all auth operations.
 *
 * Exported API:
 *   registerUser(email, password)  → Promise<UserCredential>
 *   loginUser(email, password)     → Promise<UserCredential>
 *   logoutUser()                   → Promise<void>
 *   onAuthChange(callback)         → Unsubscribe
 *   getCurrentUser()               → User | null  (synchronous snapshot)
 */

import { initializeApp, getApps } from "https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js";
import {
  getAuth,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js";

import { firebaseConfig } from "./firebase-config.js";

// Initialise once — guard against module being imported by multiple pages
const app  = getApps().find((a) => a.name === "[DEFAULT]") ?? initializeApp(firebaseConfig);
const auth = getAuth(app);

export { auth };

export async function registerUser(email, password) {
  return createUserWithEmailAndPassword(auth, email, password);
}

export async function loginUser(email, password) {
  return signInWithEmailAndPassword(auth, email, password);
}

export async function logoutUser() {
  return signOut(auth);
}

export function onAuthChange(callback) {
  return onAuthStateChanged(auth, callback);
}

/**
 * Synchronous snapshot of the current user.
 * Returns null if called before the auth state has resolved.
 * Prefer onAuthChange() for reactive code.
 */
export function getCurrentUser() {
  return auth.currentUser;
}
