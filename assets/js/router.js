/**
 * router.js
 * ─────────
 * Client-side routing guards for the MPA.
 *
 * Guards:
 *   requireAuth(redirectTo?)     — protected pages; redirects to login if signed out
 *   redirectIfAuthed(redirectTo?) — login/index pages; redirects to dashboard if signed in
 *
 * Navigation:
 *   navigateTo(filename)  — centralised redirect that handles /pages/ prefix automatically
 *
 * Logout race-condition fix:
 *   After logoutUser() the browser navigates to login.html. Firebase's
 *   onAuthStateChanged fires one last time on the NEW page with the old
 *   (still-resolving) session before confirming sign-out, which can cause
 *   redirectIfAuthed to incorrectly bounce the user back to dashboard.
 *   We prevent this by writing a short-lived sessionStorage flag right
 *   before navigating away, and honouring it in redirectIfAuthed.
 */

import { onAuthChange } from "./auth.js";

const LOGOUT_FLAG = "vaultsync_just_logged_out";

// ─── Navigation ───────────────────────────────────────────────────────────

/**
 * Navigate to another page inside /pages/.
 * Works for both local dev (localhost) and GitHub Pages
 * where the repo name (e.g. /VaultSync/) is part of the URL.
 *
 * Examples:
 *   localhost:3000/pages/upload.html      → just "filename"
 *   aqueel707.github.io/VaultSync/pages/  → just "filename" (same dir)
 *   aqueel707.github.io/VaultSync/        → "pages/filename"
 */
export function navigateTo(filename) {
  const pathParts = window.location.pathname.split("/");
  // When we're inside /pages/, the second-to-last segment is "pages"
  const parentDir = pathParts[pathParts.length - 2] ?? "";
  window.location.href = parentDir === "pages" ? filename : `pages/${filename}`;
}

/**
 * Call this before navigating away on logout so login.html won't
 * immediately bounce back to dashboard due to a stale auth event.
 */
export function markLoggedOut() {
  sessionStorage.setItem(LOGOUT_FLAG, "1");
}

// ─── Core guard helper ────────────────────────────────────────────────────

function resolveAuth() {
  return new Promise((resolve) => {
    const unsub = onAuthChange((user) => {
      unsub();
      resolve(user);
    });
  });
}

// ─── Guard: protected pages ───────────────────────────────────────────────

/**
 * Redirects to login if not signed in.
 * @param {string} [loginPage="login.html"]
 * @returns {Promise<import("firebase/auth").User>}
 */
export async function requireAuth(loginPage = "login.html") {
  const user = await resolveAuth();
  if (!user) {
    navigateTo(loginPage);
    return new Promise(() => {});
  }
  return user;
}

// ─── Guard: login / index pages ───────────────────────────────────────────

/**
 * Redirects to dashboard if already signed in.
 * Skips the redirect if we just logged out (prevents race condition).
 * @param {string} [dashboardPage="dashboard.html"]
 * @returns {Promise<null>}
 */
export async function redirectIfAuthed(dashboardPage = "dashboard.html") {
  // If we just logged out, clear the flag and stay on login.html
  if (sessionStorage.getItem(LOGOUT_FLAG)) {
    sessionStorage.removeItem(LOGOUT_FLAG);
    return null;
  }

  const user = await resolveAuth();
  if (user) {
    navigateTo(dashboardPage);
    return new Promise(() => {});
  }
  return null;
}
