# ⬡ VaultSync — Client-Side Encrypted Cloud Storage

> **Zero-knowledge file storage.** Files are encrypted entirely in your browser
> before they ever reach the cloud. The server never sees your plaintext data or
> encryption keys — ever.

🔗 **Live Demo:** https://aqueel707.github.io/VaultSync/

---

## What is VaultSync?

VaultSync is a secure cloud file storage web application where **all encryption
happens in the browser** before upload. Even the storage provider (Supabase) only
ever holds encrypted ciphertext — it has no ability to read your files.

Built as a fully static multi-page application (MPA), VaultSync requires **no
backend server** and runs entirely on free-tier infrastructure.

---

## Security Model

| Property | Detail |
|---|---|
| Encryption algorithm | AES-256-GCM |
| Key derivation | PBKDF2-SHA-256, 150,000 iterations |
| Key isolation | Raw DEK never stored or transmitted |
| Server knowledge | Zero — only ciphertext is uploaded |
| Authentication | Firebase Auth (email/password) |
| Storage | Supabase Storage (private bucket + RLS) |
| Hosting | GitHub Pages (no backend) |

### Encryption Architecture
```
USER PASSWORD
      │
      ▼
PBKDF2-SHA-256 (150,000 iterations + random 16-byte salt)
      │
      ▼
WRAPPING KEY (AES-256, never stored)
      │
      ├─── wraps ──────────────────────────────┐
      │                                         │
      │    DEK (random 256-bit, never stored)  │
      │     │                                   │
      │     └── AES-256-GCM encrypt ───────┐   │
      │              (random 12-byte IV)    │   │
      │                                     ▼   ▼
      │                              ┌─────────────────┐
      │                              │  metadata.json  │
      │                              │  salt (b64)     │
      │                              │  fileIV (b64)   │
      │                              │  dekIV (b64)    │
      │                              │  wrappedDEK(b64)│
      │                              │  originalName   │
      │                              │  timestamp      │
      │                              └─────────────────┘
      ▼
PLAINTEXT FILE
      │
      ▼
AES-256-GCM encrypt (DEK + fileIV)
      │
      ▼
CIPHERTEXT BLOB ──► Supabase Storage
METADATA JSON   ──► Supabase Storage
```

---

## Features

- 🔒 **Client-side AES-256-GCM encryption** — files encrypted before upload
- 🔑 **PBKDF2 key derivation** — password never stored, never transmitted
- 🗂 **Multi-page application** — dedicated pages for login, dashboard, upload, files, settings
- ☁ **Hybrid storage** — use the app's Supabase bucket or connect your own
- 🔐 **Firebase Authentication** — email/password login and registration
- 📁 **File management** — list, decrypt, download, and delete encrypted files
- 📱 **Responsive UI** — works on desktop and mobile
- 🚀 **Zero backend** — fully static, deployed on GitHub Pages
- 💾 **Persistent settings** — storage mode saved in `localStorage`

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
│   │   └── style.css     ← Shared stylesheet
│   └── js/
│       ├── firebase-config.js   ← ⚠ Firebase credentials
│       ├── auth.js              ← Firebase Authentication
│       ├── router.js            ← Page guards
│       ├── crypto-utils.js      ← PBKDF2 + AES-256-GCM (unchanged)
│       ├── supabase-client.js   ← Supabase client setup
│       ├── firebase-managed.js  ← App-owned storage provider
│       ├── firebase-user.js     ← User-owned storage provider
│       ├── storage-manager.js   ← Provider abstraction + localStorage
│       ├── upload.js            ← Upload page controller
│       └── download.js          ← Files page controller
│
├── firebase/
│   └── storage.rules
├── .gitignore
└── README.md
```

---

## How Routing Works

Every protected page calls `requireAuth()` from `router.js`. This waits for
Firebase to resolve the auth state, then either returns the user or redirects to
`login.html`. Pages `await` this before rendering, preventing any flash of
wrong UI.
```
Open app
    │
    ▼
pages/index.html
    ├── authed? ──YES──► dashboard.html
    └── no ────────────► login.html
                              │
                      login or register
                              │
                              ▼
                        dashboard.html
                        ┌────┬───────┬──────────┐
                        ↓    ↓       ↓          ↓
                     upload files  settings  logout
```

---

## Setup Instructions

### 1. Clone the repository
```bash
git clone https://github.com/aqueel707/VaultSync.git
cd VaultSync
```

### 2. Insert your Firebase config

Edit `assets/js/firebase-config.js`:
```js
export const firebaseConfig = {
  apiKey:            "YOUR_API_KEY",
  authDomain:        "YOUR_PROJECT_ID.firebaseapp.com",
  projectId:         "YOUR_PROJECT_ID",
  storageBucket:     "YOUR_PROJECT_ID.appspot.com",
  messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
  appId:             "YOUR_APP_ID",
};
```

### 3. Firebase setup

- **Authentication** → Sign-in method → Enable **Email/Password**

### 4. Supabase setup

- Create a **private** bucket named `vaultsync`
- Run these RLS policies in the **SQL Editor**:
```sql
CREATE POLICY "Anon can upload to vaultsync"
ON storage.objects FOR INSERT TO anon, authenticated
WITH CHECK (bucket_id = 'vaultsync');

CREATE POLICY "Anon can read from vaultsync"
ON storage.objects FOR SELECT TO anon, authenticated
USING (bucket_id = 'vaultsync');

CREATE POLICY "Anon can delete from vaultsync"
ON storage.objects FOR DELETE TO anon, authenticated
USING (bucket_id = 'vaultsync');

CREATE POLICY "Anon can update vaultsync"
ON storage.objects FOR UPDATE TO anon, authenticated
USING (bucket_id = 'vaultsync');
```

---

## Running Locally

ES modules require HTTP — you cannot open files directly as `file://` URLs.
```bash
# Option A — npx serve (recommended)
npx serve .
# Open http://localhost:3000/pages/

# Option B — Python
python3 -m http.server 8080
# Open http://localhost:8080/pages/
```

---

## Deploying to GitHub Pages

1. Push to GitHub
2. Go to **Settings → Pages** → Source: branch `main`, folder `/`
3. Site goes live at `https://<username>.github.io/<repo-name>/pages/`
4. Add that URL to Firebase Auth → **Authorised domains**

---

## Tech Stack

| Layer | Technology |
|---|---|
| Encryption | Web Crypto API (AES-256-GCM, PBKDF2) |
| Authentication | Firebase Authentication |
| Storage | Supabase Storage |
| Frontend | HTML5, CSS3, Vanilla JS (ES Modules) |
| Hosting | GitHub Pages |
| Build tools | None — zero build step |

---

## License

MIT
