// SecureScope Firebase web config (project: scope-main).
// These values are NOT secrets — they are meant to live in client code.
export const firebaseConfig = {
  apiKey: "AIzaSyCFDJj5NUG2AwIGJAORi8QrrAukWVwU5gU",
  authDomain: "scope-main.firebaseapp.com",
  projectId: "scope-main",
  storageBucket: "scope-main.firebasestorage.app",
  messagingSenderId: "927085657399",
  appId: "1:927085657399:web:1cab44c7bdde4f58176eb2",
  measurementId: "G-4HTPW47WVE",
};

// Accounts that may open the admin dashboard (enforced again by Firestore rules).
export const ADMIN_EMAILS = ["omarsrao@gmail.com"];

// Where shared report links resolve (stable GitHub Pages origin).
export const VIEW_BASE = "https://omarrao.github.io/secure-scope/view.html";
