// SecureScope accounts: Firebase Auth + Firestore, self-injecting UI.
// Exposes window.SS for the page scripts. Loaded as <script type="module">.
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.15.0/firebase-app.js";
import {
  getAuth, GoogleAuthProvider, signInWithPopup, signOut,
  createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged,
} from "https://www.gstatic.com/firebasejs/12.15.0/firebase-auth.js";
import {
  getFirestore, collection, addDoc, setDoc, doc, getDoc, getDocs,
  query, orderBy, serverTimestamp,
} from "https://www.gstatic.com/firebasejs/12.15.0/firebase-firestore.js";
import { firebaseConfig, ADMIN_EMAILS, VIEW_BASE } from "./firebase-config.js";

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

let _user = null;
let _gmailToken = null;          // Google OAuth access token w/ gmail.send (if granted)
let _pendingResolve = null;      // resolver for requireSignIn()
const _userCbs = [];

const GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.send";

// ── Styles (reuse the page's theme variables; fall back for view/admin pages) ──
const css = `
.ss-chip{position:fixed;top:9px;right:60px;z-index:10000;display:flex;align-items:center;gap:8px;font-family:'Geist',sans-serif}
.ss-slot{display:flex;align-items:center;gap:10px}
.ss-mini{background:none;border:none;color:var(--sub,#a0aec0);font-size:13px;font-family:'Geist',sans-serif;cursor:pointer;padding:0}
.ss-mini:hover{color:var(--head,#fff)}
.ss-mini.pri{color:var(--accent,#4f8ef7);font-weight:600}
.ss-mini-email{font-size:12px;color:var(--sub,#a0aec0);font-family:'Geist Mono',monospace;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ss-banner{position:fixed;top:52px;left:0;right:0;z-index:9990;display:none;align-items:center;justify-content:center;gap:14px;flex-wrap:wrap;padding:9px 44px 9px 16px;background:linear-gradient(90deg,rgba(79,142,247,.16),rgba(167,139,250,.16));border-bottom:1px solid var(--rule2,#2e3540);font-family:'Geist',sans-serif;font-size:13px;color:var(--body,#e2e8f0)}
.ss-banner.show{display:flex}
.ss-banner b{color:var(--head,#fff)}
.ss-banner .ss-bx{background:none;border:none;color:var(--muted,#6b7785);cursor:pointer;font-size:16px;line-height:1;position:absolute;right:12px}
.ss-btn{background:var(--accent,#4f8ef7);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit}
.ss-btn.ghost{background:transparent;border:1px solid var(--rule2,#2e3540);color:var(--sub,#a0aec0)}
.ss-btn.ghost:hover{color:var(--head,#fff)}
.ss-email{font-size:12px;color:var(--sub,#a0aec0);font-family:'Geist Mono',monospace;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.ss-overlay{position:fixed;inset:0;z-index:10001;background:rgba(0,0,0,.7);backdrop-filter:blur(6px);display:none;align-items:center;justify-content:center}
.ss-overlay.open{display:flex}
.ss-card{background:var(--ink2,#111419);border:1px solid var(--rule2,#2e3540);border-radius:16px;width:100%;max-width:420px;padding:28px;position:relative;font-family:'Geist',sans-serif;color:var(--body,#e2e8f0);margin:16px}
.ss-card h3{font-size:20px;font-weight:800;color:var(--head,#fff);margin:0 0 4px}
.ss-card p{font-size:13px;color:var(--sub,#a0aec0);margin:0 0 18px;line-height:1.5}
.ss-x{position:absolute;top:14px;right:14px;background:none;border:1px solid var(--rule2,#2e3540);color:var(--sub,#a0aec0);border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:15px}
.ss-google{width:100%;display:flex;align-items:center;justify-content:center;gap:10px;background:#fff;color:#1f2937;border:1px solid #dadce0;border-radius:8px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;margin-bottom:14px}
.ss-or{display:flex;align-items:center;gap:10px;color:var(--muted,#6b7785);font-size:11px;margin:6px 0 14px}
.ss-or::before,.ss-or::after{content:'';flex:1;height:1px;background:var(--rule,#252b35)}
.ss-input{width:100%;background:var(--ink,#0a0c0f);border:1px solid var(--rule2,#2e3540);border-radius:8px;padding:11px 13px;color:var(--head,#fff);font-size:13px;font-family:'Geist Mono',monospace;outline:none;margin-bottom:10px}
.ss-input:focus{border-color:var(--accent,#4f8ef7)}
.ss-err{color:#fca5a5;font-size:12px;min-height:16px;margin:2px 0 8px}
.ss-row{display:flex;gap:8px;margin-top:4px}
.ss-row .ss-btn{flex:1}
.ss-drawer{position:fixed;top:0;right:0;bottom:0;width:420px;max-width:92vw;z-index:10001;background:var(--ink2,#111419);border-left:1px solid var(--rule2,#2e3540);transform:translateX(100%);transition:transform .25s;overflow-y:auto;font-family:'Geist',sans-serif;color:var(--body,#e2e8f0)}
.ss-drawer.open{transform:translateX(0)}
.ss-drawer-h{display:flex;align-items:center;justify-content:space-between;padding:18px 20px;border-bottom:1px solid var(--rule,#252b35)}
.ss-drawer-h h3{font-size:16px;font-weight:800;color:var(--head,#fff);margin:0}
.ss-rep{border:1px solid var(--rule,#252b35);border-radius:10px;padding:14px;margin:12px 16px;background:var(--ink,#0a0c0f)}
.ss-rep-repo{font-size:13px;font-weight:700;color:var(--head,#fff);font-family:'Geist Mono',monospace;word-break:break-all}
.ss-rep-meta{font-size:11px;color:var(--dim,#6b7785);margin:4px 0 10px}
.ss-rep-actions{display:flex;gap:6px;flex-wrap:wrap}
.ss-rep-actions a,.ss-rep-actions button{font-size:11px;font-weight:600;border-radius:6px;padding:6px 10px;cursor:pointer;border:1px solid var(--rule2,#2e3540);background:var(--ink3,#181c23);color:var(--body,#e2e8f0);text-decoration:none;font-family:inherit}
.ss-rep-actions .pri{background:var(--accent,#4f8ef7);border-color:var(--accent,#4f8ef7);color:#fff}
`;

function injectStyles() {
  const s = document.createElement("style");
  s.textContent = css;
  document.head.appendChild(s);
}

function el(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstChild;
}

let chip, overlay, drawer, banner, authSlot;

function buildUI() {
  injectStyles();

  // Prefer a topbar slot the page provides (#ssauth) so the auth control sits
  // inside the existing nav instead of floating over it. Fall back to a fixed
  // chip only when no slot exists (e.g. minimal pages).
  authSlot = document.getElementById("ssauth");
  if (authSlot) {
    authSlot.classList.add("ss-slot");
  } else {
    chip = el(`<div class="ss-chip"></div>`);
    document.body.appendChild(chip);
  }

  banner = el(`
    <div class="ss-banner" id="ssBanner">
      <span>🔐 <b>Create a free SecureScope account</b> to run scans and keep your full report history.</span>
      <button class="ss-btn" id="ssBannerIn">Sign up / Sign in</button>
      <button class="ss-bx" id="ssBannerX" title="Dismiss">&times;</button>
    </div>`);
  document.body.appendChild(banner);
  banner.querySelector("#ssBannerIn").onclick = () => openAuth();
  banner.querySelector("#ssBannerX").onclick = () => { banner.classList.remove("show"); try { localStorage.setItem("ss-banner-dismissed", "1"); } catch (e) {} };

  overlay = el(`
    <div class="ss-overlay" id="ssOverlay">
      <div class="ss-card">
        <button class="ss-x" id="ssClose">&times;</button>
        <h3 id="ssTitle">Sign in to start scanning</h3>
        <p>Create a free account to run scans and keep your report history. No credit card.</p>
        <button class="ss-google" id="ssGoogle">
          <svg width="18" height="18" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.8-6.8C35.6 2.4 30.2 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.9 6.1C12.3 13.2 17.7 9.5 24 9.5z"/><path fill="#4285F4" d="M46.1 24.5c0-1.6-.1-3.1-.4-4.5H24v9h12.4c-.5 2.9-2.1 5.3-4.6 7l7.1 5.5c4.1-3.8 6.5-9.4 6.5-16z"/><path fill="#FBBC05" d="M10.5 28.3c-.5-1.4-.8-2.9-.8-4.3s.3-3 .8-4.3l-7.9-6.1C1 16.6 0 20.2 0 24s1 7.4 2.6 10.5l7.9-6.2z"/><path fill="#34A853" d="M24 48c6.2 0 11.4-2 15.2-5.5l-7.1-5.5c-2 1.4-4.6 2.2-8.1 2.2-6.3 0-11.7-3.7-13.5-9.1l-7.9 6.2C6.5 42.6 14.6 48 24 48z"/></svg>
          Continue with Google
        </button>
        <div class="ss-or">or</div>
        <input class="ss-input" id="ssEmail" type="email" placeholder="you@example.com" autocomplete="email">
        <input class="ss-input" id="ssPass" type="password" placeholder="Password (6+ chars)" autocomplete="current-password">
        <div class="ss-err" id="ssErr"></div>
        <div class="ss-row">
          <button class="ss-btn" id="ssLogin">Log in</button>
          <button class="ss-btn ghost" id="ssSignup">Create account</button>
        </div>
      </div>
    </div>`);
  document.body.appendChild(overlay);

  drawer = el(`
    <div class="ss-drawer" id="ssDrawer">
      <div class="ss-drawer-h"><h3>My Reports</h3><button class="ss-btn ghost" id="ssDrawerClose">Close</button></div>
      <div id="ssRepList"><p style="padding:16px;color:var(--dim,#6b7785);font-size:13px">Loading…</p></div>
    </div>`);
  document.body.appendChild(drawer);

  overlay.querySelector("#ssClose").onclick = closeAuth;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeAuth(); });
  overlay.querySelector("#ssGoogle").onclick = doGoogle;
  overlay.querySelector("#ssLogin").onclick = () => doEmail(false);
  overlay.querySelector("#ssSignup").onclick = () => doEmail(true);
  drawer.querySelector("#ssDrawerClose").onclick = () => drawer.classList.remove("open");
}

function renderChip() {
  const host = authSlot || chip;
  if (host) {
    if (_user) {
      const isAdmin = ADMIN_EMAILS.includes((_user.email || "").toLowerCase());
      host.innerHTML = `
        <span class="ss-mini-email" title="${_user.email}">${_user.email}</span>
        ${isAdmin ? `<a class="ss-mini pri" href="https://omarrao.github.io/secure-scope/admin.html">Admin</a>` : ""}
        <button class="ss-mini" id="ssOut">Sign out</button>`;
      host.querySelector("#ssOut").onclick = () => signOut(auth);
    } else {
      host.innerHTML = `<button class="ss-mini pri" id="ssIn">Sign in</button>`;
      host.querySelector("#ssIn").onclick = () => openAuth();
    }
  }
  // First-visit banner: only when signed out and not previously dismissed.
  if (banner) {
    let dismissed = false;
    try { dismissed = localStorage.getItem("ss-banner-dismissed") === "1"; } catch (e) {}
    banner.classList.toggle("show", !_user && !dismissed);
  }
}

function setErr(m) { const e = overlay?.querySelector("#ssErr"); if (e) e.textContent = m || ""; }
function openAuth() { setErr(""); overlay.classList.add("open"); }
function closeAuth() { overlay.classList.remove("open"); }

async function doGoogle() {
  setErr("");
  // Basic profile/email only — no sensitive scopes, so Google shows no
  // "unverified app" warning and the app can be published without review.
  // Email sharing sends from the user's own address via their mail client.
  const provider = new GoogleAuthProvider();
  try {
    await signInWithPopup(auth, provider);
  } catch (e) {
    setErr(e.code === "auth/popup-closed-by-user" ? "Sign-in cancelled." : (e.message || "Google sign-in failed."));
  }
}

async function doEmail(isSignup) {
  setErr("");
  const email = overlay.querySelector("#ssEmail").value.trim();
  const pass = overlay.querySelector("#ssPass").value;
  if (!email || !pass) { setErr("Enter email and password."); return; }
  try {
    if (isSignup) await createUserWithEmailAndPassword(auth, email, pass);
    else await signInWithEmailAndPassword(auth, email, pass);
  } catch (e) {
    const map = {
      "auth/invalid-credential": "Invalid email or password.",
      "auth/email-already-in-use": "That email already has an account — log in instead.",
      "auth/weak-password": "Password must be at least 6 characters.",
      "auth/invalid-email": "Enter a valid email address.",
    };
    setErr(map[e.code] || e.message || "Authentication failed.");
  }
}

async function recordProfile() {
  if (!_user) return;
  try {
    await setDoc(doc(db, "users", _user.uid), {
      uid: _user.uid, email: _user.email || "",
      displayName: _user.displayName || "", lastActive: serverTimestamp(),
    }, { merge: true });
  } catch (e) { /* non-fatal */ }
}

onAuthStateChanged(auth, (u) => {
  _user = u;
  renderChip();
  if (u) {
    recordProfile();
    closeAuth();
    if (_pendingResolve) { const r = _pendingResolve; _pendingResolve = null; r(u); }
  }
  _userCbs.forEach((cb) => { try { cb(u); } catch (e) {} });
});

// ── Public API ───────────────────────────────────────────────────────────────
window.SS = {
  get user() { return _user; },
  isAdmin() { return _user && ADMIN_EMAILS.includes((_user.email || "").toLowerCase()); },
  onUser(cb) { _userCbs.push(cb); if (_user !== undefined) cb(_user); },
  signIn() { openAuth(); },
  signOutUser() { return signOut(auth); },

  // Resolve once the user is signed in; opens the auth modal if needed.
  requireSignIn() {
    return new Promise((resolve) => {
      if (_user) return resolve(_user);
      _pendingResolve = resolve;
      openAuth();
    });
  },

  // Persist a completed scan to the user's history + the admin activity log.
  async saveReport(rec) {
    if (!_user) return null;
    const data = {
      repo: rec.repo || "", report_url: rec.report_url || "", gist_url: rec.gist_url || "",
      summary: rec.summary || {}, scanType: rec.scanType || "full",
      createdAt: serverTimestamp(),
    };
    // Durable copy: gzip the rendered report HTML and store it in Firestore so
    // the report survives Render redeploys (ephemeral disk). Best-effort +
    // size-guarded to stay well under Firestore's 1 MB document limit.
    try {
      if (rec.reportHtml) {
        const z = await ssGzipB64(rec.reportHtml);
        if (z && z.length < 700000) data.htmlz = z;
      }
    } catch (e) { console.warn("report compress failed", e); }
    try {
      const ref = await addDoc(collection(db, "users", _user.uid, "reports"), data);
      await recordProfile();
      try {
        await addDoc(collection(db, "activity"), {
          type: "scan", uid: _user.uid, email: _user.email || "",
          repo: data.repo, scanType: data.scanType,
          findings: (rec.summary && rec.summary.total_findings) || 0,
          createdAt: serverTimestamp(),
        });
      } catch (e) {}
      return ref.id;
    } catch (e) { console.warn("saveReport failed", e); return null; }
  },

  async listReports() {
    if (!_user) return [];
    const q = query(collection(db, "users", _user.uid, "reports"), orderBy("createdAt", "desc"));
    const snap = await getDocs(q);
    return snap.docs.map((d) => ({ id: d.id, ...d.data() }));
  },

  // Create a public view-only share doc; returns the shareable link.
  async createShare(rec) {
    if (!_user) return null;
    const doc0 = {
      ownerUid: _user.uid, ownerEmail: _user.email || "",
      repo: rec.repo || "", report_url: rec.report_url || "", gist_url: rec.gist_url || "",
      summary: rec.summary || {}, createdAt: serverTimestamp(),
    };
    // Carry the durable HTML into the share doc so view-only links keep working
    // regardless of the backend's ephemeral disk.
    try {
      let z = rec.htmlz;
      if (!z && rec.reportHtml) { z = await ssGzipB64(rec.reportHtml); }
      if (z && z.length < 700000) doc0.htmlz = z;
    } catch (e) { console.warn("share compress failed", e); }
    const ref = await addDoc(collection(db, "shared"), doc0);
    return `${VIEW_BASE}?id=${ref.id}`;
  },

  // Send an email FROM the signed-in user's Gmail (if gmail.send was granted),
  // otherwise fall back to opening their local mail client.
  async sendEmail(to, subject, htmlBody, textBody) {
    if (_gmailToken) {
      const mime =
        `To: ${to}\r\nSubject: ${subject}\r\n` +
        `MIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n${htmlBody}`;
      const raw = btoa(unescape(encodeURIComponent(mime)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const r = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
        method: "POST",
        headers: { Authorization: `Bearer ${_gmailToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ raw }),
      });
      if (r.ok) return "sent";
    }
    // Fallback: open the user's own mail client with a caller-supplied plain-text body.
    const text = textBody || subject;
    window.open(`mailto:${encodeURIComponent(to)}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(text)}`);
    return "mailto";
  },
};

// ── Durable report HTML (gzip <-> base64, native CompressionStream) ─────────────
async function ssGzipB64(str) {
  if (!("CompressionStream" in window)) return "";
  const cs = new CompressionStream("gzip");
  const w = cs.writable.getWriter();
  w.write(new TextEncoder().encode(str)); w.close();
  const buf = new Uint8Array(await new Response(cs.readable).arrayBuffer());
  let b = ""; for (let i = 0; i < buf.length; i++) b += String.fromCharCode(buf[i]);
  return btoa(b);
}
async function ssUngzipB64(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  const ds = new DecompressionStream("gzip");
  const w = ds.writable.getWriter(); w.write(u); w.close();
  return new TextDecoder().decode(await new Response(ds.readable).arrayBuffer());
}
// Open a durable report: prefer the stored gzip HTML (survives redeploys),
// fall back to any external URL. Exposed for view.html and the history drawer.
async function ssOpenReport(rec) {
  try {
    if (rec && rec.htmlz) {
      const html = await ssUngzipB64(rec.htmlz);
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      window.open(url, "_blank", "noopener");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
      return true;
    }
  } catch (e) { console.warn("open durable report failed", e); }
  const link = (rec && (rec.gist_url || rec.report_url)) || "";
  if (link) { window.open(link, "_blank", "noopener"); return true; }
  return false;
}
window.SS.ssUngzipB64 = ssUngzipB64;
window.SS.openReport = ssOpenReport;

// ── My Reports drawer ──────────────────────────────────────────────────────────
async function openReports() {
  drawer.classList.add("open");
  const list = drawer.querySelector("#ssRepList");
  list.innerHTML = `<p style="padding:16px;color:var(--dim,#6b7785);font-size:13px">Loading…</p>`;
  let reports = [];
  try { reports = await window.SS.listReports(); }
  catch (e) { list.innerHTML = `<p style="padding:16px;color:#fca5a5;font-size:13px">Could not load reports. Check Firestore rules.</p>`; return; }
  if (!reports.length) { list.innerHTML = `<p style="padding:16px;color:var(--dim,#6b7785);font-size:13px">No scans yet. Run a scan to build your history.</p>`; return; }
  list.innerHTML = reports.map((r) => {
    const s = r.summary || {};
    const sev = s.by_severity || {};
    const when = r.createdAt && r.createdAt.toDate ? r.createdAt.toDate().toLocaleString() : "";
    return `
      <div class="ss-rep">
        <div class="ss-rep-repo">${(r.repo || "").replace(/^https?:\/\//, "")}</div>
        <div class="ss-rep-meta">${when} · ${s.total_findings ?? (sev.ERROR || 0) + (sev.WARNING || 0)} findings · ${sev.ERROR || 0} critical</div>
        <div class="ss-rep-actions">
          <button class="pri ss-open" data-id="${r.id}">Open report</button>
          <button data-id="${r.id}" class="ss-copy">Copy share link</button>
          <button data-id="${r.id}" class="ss-email">Email</button>
        </div>
      </div>`;
  }).join("");
  list.querySelectorAll(".ss-open").forEach((b) => b.onclick = async () => {
    const ok = await ssOpenReport(reports.find(x => x.id === b.dataset.id));
    if (!ok) alert("This report has no stored copy or link available.");
  });
  list.querySelectorAll(".ss-copy").forEach((b) => b.onclick = () => shareReport(reports.find(x => x.id === b.dataset.id), "copy"));
  list.querySelectorAll(".ss-email").forEach((b) => b.onclick = () => shareReport(reports.find(x => x.id === b.dataset.id), "email"));
}

async function shareReport(rec, mode) {
  if (!rec) return;
  let url;
  try { url = await window.SS.createShare(rec); }
  catch (e) { alert("Could not create share link: " + (e.message || e)); return; }
  if (mode === "copy") {
    try { await navigator.clipboard.writeText(url); alert("View-only link copied:\n" + url); }
    catch (e) { prompt("Copy this view-only link:", url); }
  } else {
    const to = prompt("Send the report to which email address?");
    if (!to) return;
    const repo = (rec.repo || "").replace(/^https?:\/\//, "");
    const body = `<p>${_user.email} shared a SecureScope security report with you.</p>
      <p><strong>Repository:</strong> ${repo}</p>
      <p><a href="${url}">Open the view-only report dashboard →</a></p>`;
    const text = `${_user.email} shared a SecureScope security report with you.\n\nRepository: ${repo}\n\nOpen the view-only report dashboard:\n${url}`;
    const res = await window.SS.sendEmail(to, `SecureScope report — ${repo}`, body, text);
    alert(res === "sent" ? "Email sent from your Gmail." : "Opened your mail app to send the report.");
  }
}

// Expose for pages that want to trigger the drawer / share directly.
window.SS.openReports = openReports;
window.SS.shareReport = shareReport;
// Topbar "History": ensure signed in, then open the My Reports drawer.
window.SS.openHistory = () => window.SS.requireSignIn().then(() => openReports());

buildUI();
renderChip();
