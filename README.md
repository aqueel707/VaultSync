# VaultSync — Encrypted Cloud Storage

A web app where your files are encrypted in the browser before they go anywhere.
The server never sees your actual data — only the encrypted version of it.

Live: https://aqueel707.github.io/VaultSync/pages/login.html

---

## What does it actually do?

When you upload a file, VaultSync encrypts it on your device first using AES-256-GCM
before anything is sent to the cloud. The encryption key is derived from your password
using PBKDF2 (150,000 iterations) and never leaves your browser. Even if someone broke
into the storage bucket, all they'd find is unreadable ciphertext.

There's no backend server. No database of passwords. Nothing to breach on the server side
that would compromise your files.

---

## Features

**Cloud storage (with account)**
- Upload encrypted files to the app's Supabase bucket
- Or connect your own Supabase bucket in Settings — your data, your infrastructure
- Browse, decrypt, and download your files from any device
- Delete files from the bucket

**Local encryption (no cloud needed)**
- Encrypt any file and download it directly to your device as a `.enc` + `.meta.json` pair
- Save those files anywhere — Google Drive, Dropbox, OneDrive, a USB drive, email to yourself
- Come back later and decrypt any locally saved file right in the browser
- Nothing is uploaded anywhere during this process

**Authentication**
- Email/password login via Firebase Auth
- Protected pages redirect to login if you're not signed in

---

## Security model

Everything cryptographic happens in the browser using the native Web Crypto API —
no third-party crypto libraries involved.
```
Your password
    |
    v
PBKDF2-SHA-256 (150,000 iterations + random 16-byte salt)
    |
    v
Wrapping Key  ──── wraps ────>  Random 256-bit DEK
                                      |
                                      v
                              AES-256-GCM encrypt
                                      |
                                      v
                               Encrypted file blob  ──> stored/downloaded
                               + metadata JSON      ──> stored/downloaded
                                 (salt, IVs, wrapped DEK, filename)
```

The raw DEK is never stored. Your password is never stored or transmitted.
The metadata JSON on its own is useless without the password.

---

## Pages

| Page | What it does |
|---|---|
| `login.html` | Sign in or create an account |
| `dashboard.html` | Home screen with navigation |
| `upload.html` | Encrypt and upload to cloud storage |
| `files.html` | List your cloud files, decrypt and download |
| `encrypt.html` | Encrypt a file and download it locally — no cloud |
| `decrypt.html` | Upload a local .enc file and decrypt it |
| `settings.html` | Switch between app storage and your own Supabase bucket |

---

## Project structure
```
VaultSync/
├── pages/
│   ├── index.html
│   ├── login.html
│   ├── dashboard.html
│   ├── upload.html
│   ├── files.html
│   ├── encrypt.html
│   ├── decrypt.html
│   └── settings.html
│
├── assets/
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── firebase-config.js    <- put your Firebase credentials here
│       ├── supabase-client.js    <- Supabase client setup
│       ├── auth.js               <- login / register / logout
│       ├── router.js             <- page guards
│       ├── crypto-utils.js       <- all the crypto logic (don't touch this)
│       ├── firebase-managed.js   <- app Supabase storage provider
│       ├── firebase-user.js      <- user-owned Supabase storage provider
│       ├── storage-manager.js    <- picks which provider to use
│       ├── upload.js             <- upload page logic
│       ├── download.js           <- files page logic
│       ├── encrypt-local.js      <- local encrypt page logic
│       └── decrypt-local.js      <- local decrypt page logic
│
├── firebase/
│   └── storage.rules
└── README.md
```

---

## Setup

### 1. Clone it
```bash
git clone https://github.com/aqueel707/VaultSync.git
cd VaultSync
```

### 2. Add your Firebase config

Edit `assets/js/firebase-config.js` and paste in your Firebase project credentials.
You get these from Firebase Console > Project Settings > Your apps > SDK setup.
```js
export const firebaseConfig = {
  apiKey:            "...",
  authDomain:        "...",
  projectId:         "...",
  storageBucket:     "...",
  messagingSenderId: "...",
  appId:             "...",
};
```

These keys are public by design — Firebase security comes from Auth rules,
not from keeping the config secret.

### 3. Firebase setup

- Authentication > Sign-in method > enable Email/Password

### 4. Supabase setup

Create a private bucket called `vaultsync`, then run these in the SQL editor:
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

## Running locally

You need an HTTP server — ES modules don't work over `file://`.
```bash
# easiest option
npx serve .

# then open
http://localhost:3000/pages/
```

---

## Deploying

Push to GitHub, then go to Settings > Pages > Source: branch `main`, folder `/`.

Add your GitHub Pages URL to Firebase Auth > Authorised domains so login works.

---

## File size limits

**Cloud upload** — capped at 50MB in the UI (Supabase free tier friendly).

**Local encrypt/export** — no hard limit. The file is loaded into browser memory,
so practically speaking anything under ~500MB works fine on a normal laptop.
Very large files (1GB+) depend on how much RAM the device has.

---

## Tech stack

- Encryption: Web Crypto API (AES-256-GCM, PBKDF2-SHA-256)
- Auth: Firebase Authentication
- Cloud storage: Supabase Storage
- Frontend: Vanilla JS with ES modules, HTML, CSS
- Hosting: GitHub Pages
- Build tools: none

---

## License

MIT