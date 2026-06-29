# SecureScope Accounts — Firebase & Google Cloud Setup

This guide enables user accounts, per-user report history, sharing, and the admin
dashboard. Auth + storage are **client-side** (Firebase Auth + Firestore), so no
secret ever touches the Render backend and passwords are handled entirely by
Firebase. You complete the console steps below once and paste the web config; I
wire everything else.

---

## 1. Create the Firebase project
1. Go to <https://console.firebase.google.com> → **Add project** (e.g. `securescope`).
2. Google Analytics: optional (you can reuse it for the existing telemetry).

## 2. Enable Authentication
1. **Build → Authentication → Get started**.
2. **Sign-in method** tab → enable:
   - **Google** (set support email).
   - **Email/Password**.
3. **Settings → Authorized domains** → add:
   - `omarrao.github.io`  (GitHub Pages landing page)
   - `secure-scope.onrender.com`  (dashboard)
   - `localhost`  (local testing)

## 3. Create Firestore
1. **Build → Firestore Database → Create database** → **Production mode** → pick a region.
2. **Rules** tab → paste exactly (note the two admin emails):

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    function isSignedIn() { return request.auth != null; }
    function isAdmin() {
      return isSignedIn() && request.auth.token.email in [
        'omarsrao@gmail.com'
      ];
    }
    function isOwner(uid) { return isSignedIn() && request.auth.uid == uid; }

    // Per-user scan reports. Owner has full access; admins can read all.
    match /users/{uid}/reports/{reportId} {
      allow read:  if isOwner(uid) || isAdmin();
      allow create, update, delete: if isOwner(uid);
    }

    // Lightweight per-user profile (created at signup). Admin can read all.
    match /users/{uid} {
      allow read:  if isOwner(uid) || isAdmin();
      allow write: if isOwner(uid);
    }

    // Publicly shared reports → readable by anyone with the link (view-only),
    // writable only by the owner who created the share.
    match /shared/{shareId} {
      allow read:  if true;
      allow create: if isSignedIn() && request.resource.data.ownerUid == request.auth.uid;
      allow update, delete: if isSignedIn() && resource.data.ownerUid == request.auth.uid;
    }

    // Admin-only activity log (sign-ins, scans) — clients append, admins read.
    match /activity/{eventId} {
      allow create: if isSignedIn();
      allow read:   if isAdmin();
      allow update, delete: if false;
    }
  }
}
```

3. **Publish**.

## 4. Enable the Gmail API (for "Share via email" sending as the user)
1. Open the linked **Google Cloud project** (same project): <https://console.cloud.google.com>.
2. **APIs & Services → Library** → search **Gmail API** → **Enable**.
3. **APIs & Services → OAuth consent screen**:
   - User type: **External**.
   - Add scope: `https://www.googleapis.com/auth/gmail.send`.
   - Add yourself (both emails) under **Test users** (or **Publish** the app to allow anyone).

> If you skip this step, email sharing falls back to opening the user's mail
> client with the link pre-filled (still "from" their address); link sharing and
> everything else work without it.

## 5. Get the web config
1. Firebase console → **Project settings (gear) → General → Your apps → Web app** (`</>`).
2. Register an app (nickname `securescope-web`). Copy the `firebaseConfig` object:

```js
const firebaseConfig = {
  apiKey: "AIza…",
  authDomain: "securescope.firebaseapp.com",
  projectId: "securescope",
  storageBucket: "securescope.appspot.com",
  messagingSenderId: "…",
  appId: "1:…:web:…",
};
```

These values are **not secrets** — they are meant to live in client code. Paste
them to me (or into `docs/firebase-config.js`) and I'll finish the wiring.

---

## What gets built once config is in
- **Sign-up gate**: after entering the repo URL in the scan modal and clicking
  Run, the user signs in / signs up (Google or email) before the scan starts.
- **History**: every completed scan is saved to `users/{uid}/reports` and shown
  in a "My Reports" view in the dashboard.
- **Sharing**: per report — copy a view-only link (`/view?id=…`) and/or
  "Share via email" (sends through the user's Gmail).
- **View-only dashboard**: shared links open a read-only report, no controls.
- **Admin dashboard**: `/admin` — visible only to the two admin emails — lists
  all users, their scans, and aggregate statistics.
