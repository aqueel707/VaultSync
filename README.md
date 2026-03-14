# ⬡ VaultSync — Multi-Page Application

> Zero-knowledge client-side encrypted cloud storage.
> Files are encrypted in your browser using AES-256-GCM — the server never sees plaintext.

🔗 **Live:** https://aqueel707.github.io/VaultSync/pages/

---

## Project Structure

```
VaultSync/
├── pages/
│   ├── index.html        ← Entry point — auth check & redirect
│   ├── login.html        ← Register / Sign in
│   ├── dashboard.html    ← Navigation hub
│   ├── upload.html       ← Encrypt & upload files
│   ├── files.html        ← List, decrypt & download files
│   └── settings.html     ← Storage mode configuration
│
├── assets/
│   ├── css/
│   │   └── style.css     ← Shared stylesheet (all pages)
│   └── js/
│       ├── firebase-config.js   ← Firebase credentials
│       ├── auth.js              ← Firebase Auth (login/register/logout)
│       ├── router.js            ← Page guards + navigateTo
│       ├── crypto-utils.js      ← PBKDF2 + AES-256-GCM encryption
│       ├── firebase-managed.js  ← App-owned storage provider
│       ├── firebase-user.js     ← User-owned storage provider
│       ├── storage-manager.js   ← Provider abstraction + localStorage state
│       ├── upload.js            ← Upload page controller
│       └── download.js          ← Files page controller
│
├── firebase/
│   └── storage.rules     ← Firebase Storage security rules
│
├── .gitignore
└── README.md
```

---

## Security Model

- Encryption happens entirely in the browser (Web Crypto API).
- Each file is encrypted with a random AES-256-GCM Data Encryption Key (DEK).
- The DEK is wrapped using a PBKDF2-derived key from your password (150,000 iterations).
- Only AES-256-GCM ciphertext + wrapped key metadata is stored in Firebase.
- Your password and raw encryption keys **never leave your device**.
- Firebase API keys are public by design — access is controlled by Storage Rules.

---

## Firebase Setup

### 1. Enable Authentication
Firebase Console → **Authentication → Sign-in method → Email/Password → Enable**

### 2. Enable Storage
Firebase Console → **Storage → Get started → Production mode**

### 3. Deploy Storage Rules
Paste the contents of `firebase/storage.rules` into:
Firebase Console → **Storage → Rules → Publish**

### 4. Authorise GitHub Pages domain
Firebase Console → **Authentication → Settings → Authorised domains → Add domain**
Add: `aqueel707.github.io`

---

## Running Locally

ES modules require an HTTP server — you cannot open files directly as `file://` URLs.

```bash
# Option A — npx serve (recommended)
cd VaultSync
npx serve .
# Open http://localhost:3000/pages/

# Option B — Python
python3 -m http.server 8080
# Open http://localhost:8080/pages/
```

---

## Deploying to GitHub Pages

The project is already deployed at:
**https://aqueel707.github.io/VaultSync/pages/**

To push updates:
```bash
git add .
git commit -m "Your update message"
git push origin main
```

GitHub Pages auto-deploys from the main branch root (/).

---

## Storage Modes

| Mode | Description |
|------|-------------|
| **App Storage** (default) | Files stored in the VaultSync Firebase bucket |
| **My Firebase Storage** | Files stored in your own Firebase project — app owner has zero access |

Mode is saved in `localStorage` and persists across sessions.
