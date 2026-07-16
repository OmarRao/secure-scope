/*
 * SecureScope capability constellation — self-contained, dependency-free.
 * Radial mind map (every capability labelled) + detail panel, rendered into
 * #ss-constellation. Adapts to the host page's light/dark theme (html.light).
 * No external fonts, no framework. © 2026 Omar Rao. All rights reserved.
 */
(function () {
  function build() {
    var mount = document.getElementById("ss-constellation");
    if (!mount || mount.dataset.built) return;
    mount.dataset.built = "1";

    var cx = 370, cy = 340, Rh = 130, N;
    var cats = [
      { n: "Static analysis",
        sum: "Reads your source code without running it, pattern-matching for insecure code and mapping every hit to a known weakness and attacker technique.",
        l: [["Semgrep", "Fast open-source SAST engine scanning 30+ languages."],
            ["OWASP/CWE", "Rules aligned to the OWASP Top 10 and CWE/SANS Top 25."],
            ["Rulepacks", "Framework-specific packs (Flask, API, secrets) plus your own rules."],
            ["ATT&CK map", "Each finding mapped to the MITRE ATT&CK technique and tactic."],
            ["AI advisor", "LLM-generated remediation guidance and suggested patches."]] },
      { n: "Dependencies",
        sum: "Inventories your third-party packages and flags the ones with known vulnerabilities — ranked by real-world exploit risk, not just severity.",
        l: [["OSV CVEs", "Cross-ecosystem vulnerability lookup against OSV.dev."],
            ["EPSS + KEV", "Prioritised by exploit probability (EPSS) and CISA known-exploited status."],
            ["Reachable", "Checks whether your code actually uses the vulnerable package.", [10, 24]],
            ["Fix PRs", "One-click pull request bumping each package to its safe version."],
            ["Polyglot", "npm, cargo, go and bundler audits across every ecosystem."]] },
      { n: "Secrets & malware",
        sum: "Hunts for leaked credentials and malicious code across the working tree and the full git history — not just the current commit.",
        l: [["Secret scan", "Detects API keys, tokens, private keys and cloud credentials."],
            ["Entropy", "Flags high-entropy strings that look like secrets without a known pattern."],
            ["Git history", "Scans past commits — secrets removed from HEAD still live in history."],
            ["YARA", "Signature matching for known malware and suspicious artifacts."],
            ["Ransomware", "Correlates findings with ransomware/APT indicators and blast-radius scoring."]] },
      { n: "Infrastructure",
        sum: "Checks how your code is deployed — infrastructure-as-code, containers and runtime behaviour — for misconfigurations and insecure defaults.",
        l: [["IaC checks", "Security checks across Terraform, K8s, CloudFormation, Ansible, Actions."],
            ["TF/K8s", "Cloud-native manifests scanned for insecure defaults and over-permissioning."],
            ["Trivy", "Dockerfile and container image layer CVE scanning."],
            ["Sandbox", "Optionally runs code in an isolated Docker sandbox to observe behaviour."]] },
      { n: "Governance",
        sum: "Turns raw findings into audit-ready evidence and vets the integrity and health of your software supply chain.",
        l: [["PCI/NIST", "Maps findings to PCI DSS v4.0, NIST 800-53, OWASP and SANS Top 25."],
            ["Licenses", "Classifies dependency licenses for copyleft/GPL and commercial risk."],
            ["SBOM", "Generates a downloadable CycloneDX software bill of materials."],
            ["Typosquat", "Detects package name mimicry and dependency-confusion exposure."],
            ["OpenSSF", "Grades project health — maintenance, branch protection, signed releases."]] },
      { n: "Reporting",
        sum: "Delivers results the way each audience needs — from executives reading a PDF to pipelines consuming SARIF.",
        l: [["HTML report", "Rich browser report with charts, threat scoring and attack-surface views."],
            ["PDF/SARIF", "PDF for humans, JSON for tooling, SARIF for GitHub code scanning."],
            ["Trends", "Tracks findings over time to show if your posture is improving."],
            ["PR comments", "Posts a Markdown summary straight onto the pull request."]] },
      { n: "Platform",
        sum: "The product around the scanner — accounts, sharing, live intelligence, and every place it plugs into your workflow.",
        l: [["Dashboard", "Live web dashboard streaming scan progress stage-by-stage."],
            ["Accounts", "Firebase sign-in with per-user report history, saved for free."],
            ["Sharing", "View-only share links, email delivery, and an admin activity panel."],
            ["Threat feed", "Real-time CISA KEV and ransomware.live intelligence in the dashboard."],
            ["GitHub/Jira", "GitHub App auth, auto-created Issues/PRs, and Jira ticketing."],
            ["CLI/CI/K8s", "Full CLI, CI/CD integration, and Kubernetes/Helm deployment."]] }
    ];
    N = cats.length;

    var css = "" +
      "#ss-constellation{padding:1rem 0;font-family:inherit;" +
      "--c0:#38bdf8;--c1:#a3e635;--c2:#fb7185;--c3:#fbbf24;--c4:#2dd4bf;--c5:#c084fc;--c6:#f472b6;" +
      "--ssc-bg:radial-gradient(58% 46% at 50% 40%,#15274a 0%,#0b1324 58%,#070c17 100%);--ssc-border:rgba(120,170,255,.16);" +
      "--ssc-accent:#5eead4;--ssc-h:#f1f5f9;--ssc-sub:#9fb0c9;--ssc-label:#dbe4f0;" +
      "--ssc-panel2:rgba(255,255,255,.03);--ssc-line:rgba(255,255,255,.09);--ssc-legtext:#c4d0e2;" +
      "--ssc-dname:#f1f5f9;--ssc-dsum:#aebccf;--ssc-cd:#c1cdde;--ssc-foot:#7688a3;--ssc-badgetext:#04121a}" +
      "html.light #ss-constellation{" +
      "--c0:#0284c7;--c1:#4d7c0f;--c2:#e11d48;--c3:#b45309;--c4:#0d9488;--c5:#7c3aed;--c6:#db2777;" +
      "--ssc-bg:radial-gradient(70% 60% at 50% 34%,#ffffff 0%,#eef2f8 62%,#e4e9f1 100%);--ssc-border:rgba(20,40,80,.12);" +
      "--ssc-accent:#0d9488;--ssc-h:#0f172a;--ssc-sub:#475569;--ssc-label:#334155;" +
      "--ssc-panel2:rgba(20,40,80,.03);--ssc-line:rgba(20,40,80,.12);--ssc-legtext:#334155;" +
      "--ssc-dname:#0f172a;--ssc-dsum:#475569;--ssc-cd:#475569;--ssc-foot:#64748b;--ssc-badgetext:#ffffff}" +
      ".ssc-panel{position:relative;overflow:hidden;background:var(--ssc-bg);border:1px solid var(--ssc-border);border-radius:18px;padding:26px 16px 22px}" +
      ".ssc-eye{font-size:12px;letter-spacing:.2em;text-transform:uppercase;color:var(--ssc-accent);margin:0;text-align:center}" +
      ".ssc-h{font-size:23px;font-weight:600;color:var(--ssc-h);margin:8px 0 6px;line-height:1.3;text-align:center}" +
      ".ssc-sub{font-size:14px;color:var(--ssc-sub);line-height:1.55;margin:0 auto;text-align:center;max-width:560px}" +
      ".ssc-svg{display:block;width:100%;height:auto;margin:8px auto 0;max-width:820px}" +
      ".ssc-svg text{font-family:inherit}" +
      ".ssc-lt{fill:var(--ssc-label);font-size:11px}" +
      ".ssc-flow{stroke-dasharray:2 6;animation:sscdash 1.3s linear infinite}" +
      ".ssc-flow2{stroke-dasharray:2 6;animation:sscdash 2s linear infinite}" +
      "@keyframes sscdash{to{stroke-dashoffset:-16}}" +
      ".ssc-cat{transition:opacity .25s ease;cursor:pointer}" +
      ".ssc-svg:hover .ssc-cat{opacity:.22}.ssc-svg .ssc-cat:hover{opacity:1}" +
      ".ssc-ring{transform-origin:370px 340px;animation:sscspin 22s linear infinite}" +
      "@keyframes sscspin{to{transform:rotate(360deg)}}" +
      ".ssc-pulse{transform-origin:370px 340px;animation:sscpul 2.8s ease-out infinite}" +
      "@keyframes sscpul{0%{transform:scale(1);opacity:.45}70%{transform:scale(2.5);opacity:0}100%{opacity:0}}" +
      ".ssc-legend{display:flex;flex-wrap:wrap;justify-content:center;gap:8px 12px;margin-top:16px}" +
      ".ssc-li{display:flex;align-items:center;gap:7px;font-size:13px;color:var(--ssc-legtext);cursor:pointer;padding:4px 11px;border-radius:999px;border:1px solid var(--ssc-line);transition:border-color .2s,background .2s}" +
      ".ssc-li:hover{border-color:var(--n)}.ssc-li.on{border-color:var(--n);background:var(--ssc-panel2)}" +
      ".ssc-dot{width:11px;height:11px;border-radius:50%;background:var(--n)}" +
      ".ssc-detail{margin:18px auto 0;max-width:720px;background:var(--ssc-panel2);border:1px solid var(--ssc-line);border-left:3px solid var(--n);border-radius:12px;padding:18px 20px}" +
      ".ssc-dtop{display:flex;align-items:center;gap:11px;flex-wrap:wrap}" +
      ".ssc-dbadge{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:var(--ssc-badgetext);background:var(--n)}" +
      ".ssc-dname{font-size:17px;font-weight:600;color:var(--ssc-dname)}" +
      ".ssc-dtag{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--n);margin-left:auto}" +
      ".ssc-dsum{font-size:14px;color:var(--ssc-dsum);line-height:1.6;margin:11px 0 15px}" +
      ".ssc-cap{display:flex;gap:12px;padding:9px 0;border-top:1px solid var(--ssc-line)}" +
      ".ssc-cn{flex:0 0 130px;font-size:13px;font-weight:600;color:var(--n)}" +
      ".ssc-cd{flex:1;font-size:13px;color:var(--ssc-cd);line-height:1.5}" +
      ".ssc-foot{text-align:center;font-size:12px;color:var(--ssc-foot);margin-top:14px}" +
      ".ssc-mobnote{display:none;text-align:center;font-size:13px;color:var(--ssc-sub);margin:2px 0 4px}" +
      "@media(max-width:640px){.ssc-svg{display:none}.ssc-foot{display:none}.ssc-mobnote{display:block}.ssc-panel{padding:22px 13px 18px}.ssc-h{font-size:20px}}" +
      "@media(max-width:540px){.ssc-cn{flex-basis:104px}}" +
      "@media(prefers-reduced-motion:reduce){.ssc-flow,.ssc-flow2,.ssc-ring,.ssc-pulse{animation:none}}";

    var st = document.createElement("style");
    st.textContent = css;
    document.head.appendChild(st);

    mount.innerHTML =
      '<div class="ssc-panel">' +
      '<p class="ssc-eye">SecureScope · capability constellation</p>' +
      '<h2 class="ssc-h">Your code enters the core. Seven fronts light up.</h2>' +
      '<p class="ssc-sub">Every scan fires signals from the core across seven fronts of security. Click any front for a full briefing on what it does.</p>' +
      '<svg class="ssc-svg" id="sscSvg" viewBox="0 0 740 700" role="img" aria-label="SecureScope capability constellation"></svg>' +
      '<p class="ssc-mobnote">Tap a front to explore its capabilities.</p>' +
      '<div class="ssc-legend" id="sscLegend"></div>' +
      '<div class="ssc-detail" id="sscDetail"></div>' +
      '<p class="ssc-foot">Hover to isolate a front · click a front or legend chip for its full briefing</p>' +
      '</div>';

    var svg = mount.querySelector("#sscSvg"),
        leg = mount.querySelector("#sscLegend"),
        det = mount.querySelector("#sscDetail");

    function esc(t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

    var s = '<defs><radialGradient id="sscCore" cx="36%" cy="30%"><stop offset="0%" stop-color="#5cf3e4"/><stop offset="100%" stop-color="#0a8f9c"/></radialGradient></defs>';
    for (var i = 0; i < N; i++) {
      var v = "var(--c" + i + ")";
      var ang = (-90 + i * (360 / N)) * Math.PI / 180, ca = Math.cos(ang), sa = Math.sin(ang);
      var hx = cx + Rh * ca, hy = cy + Rh * sa;
      var g = '<g class="ssc-cat" data-i="' + i + '">';
      var cpx = cx + Rh * 0.55 * ca - 18 * sa, cpy = cy + Rh * 0.55 * sa + 18 * ca;
      g += '<path class="ssc-flow" d="M' + cx + ',' + cy + ' Q' + cpx.toFixed(1) + ',' + cpy.toFixed(1) + ' ' + hx.toFixed(1) + ',' + hy.toFixed(1) + '" fill="none" style="stroke:' + v + '" stroke-width="2.2" stroke-opacity="0.8"/>';
      var M = cats[i].l.length, spread = 38 * Math.PI / 180;
      for (var j = 0; j < M; j++) {
        var la = ang + (M > 1 ? (j - (M - 1) / 2) * (spread / (M - 1)) : 0);
        var Rl = 204 + (j % 3) * 46, lca = Math.cos(la), lsa = Math.sin(la);
        var lx = cx + Rl * lca, ly = cy + Rl * lsa;
        var off = cats[i].l[j][2]; if (off) { lx += off[0] || 0; ly += off[1] || 0; }
        var mpx = hx + (lx - hx) * 0.5 - 12 * Math.sin(la), mpy = hy + (ly - hy) * 0.5 + 12 * Math.cos(la);
        g += '<path class="ssc-flow2" d="M' + hx.toFixed(1) + ',' + hy.toFixed(1) + ' Q' + mpx.toFixed(1) + ',' + mpy.toFixed(1) + ' ' + lx.toFixed(1) + ',' + ly.toFixed(1) + '" fill="none" style="stroke:' + v + '" stroke-width="1.2" stroke-opacity="0.42"/>';
        g += '<circle cx="' + lx.toFixed(1) + '" cy="' + ly.toFixed(1) + '" r="4.5" style="fill:' + v + '"/>';
        var right = lca >= 0, tx = lx + (right ? 8 : -8);
        g += '<text class="ssc-lt" x="' + tx.toFixed(1) + '" y="' + (ly + 4).toFixed(1) + '" text-anchor="' + (right ? "start" : "end") + '">' + esc(cats[i].l[j][0]) + '</text>';
      }
      g += '<circle cx="' + hx.toFixed(1) + '" cy="' + hy.toFixed(1) + '" r="15" fill="none" style="stroke:' + v + '" stroke-opacity="0.4" stroke-width="1.2"/>';
      g += '<circle cx="' + hx.toFixed(1) + '" cy="' + hy.toFixed(1) + '" r="7.5" style="fill:' + v + '"/>';
      g += "</g>";
      s += g;
    }
    s += '<circle class="ssc-pulse" cx="' + cx + '" cy="' + cy + '" r="40" fill="none" style="stroke:var(--ssc-accent)" stroke-width="1.6"/>';
    s += '<circle class="ssc-ring" cx="' + cx + '" cy="' + cy + '" r="60" fill="none" style="stroke:var(--ssc-accent)" stroke-opacity="0.3" stroke-width="1.1" stroke-dasharray="4 8"/>';
    s += '<circle cx="' + cx + '" cy="' + cy + '" r="42" fill="url(#sscCore)"/>';
    s += '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" fill="#04121a" font-size="13" font-weight="700" letter-spacing="1.2">SECURE</text>';
    s += '<text x="' + cx + '" y="' + (cy + 13) + '" text-anchor="middle" fill="#04121a" font-size="13" font-weight="700" letter-spacing="1.2">SCOPE</text>';
    svg.innerHTML = s;

    var lg = "";
    for (var k = 0; k < N; k++) lg += '<span class="ssc-li" data-i="' + k + '" style="--n:var(--c' + k + ')"><span class="ssc-dot"></span>' + esc(cats[k].n) + "</span>";
    leg.innerHTML = lg;

    function select(i) {
      det.style.setProperty("--n", "var(--c" + i + ")");
      var c = cats[i];
      var caps = c.l.map(function (x) { return '<div class="ssc-cap"><div class="ssc-cn">' + esc(x[0]) + '</div><div class="ssc-cd">' + esc(x[1]) + "</div></div>"; }).join("");
      det.innerHTML = '<div class="ssc-dtop"><span class="ssc-dbadge">' + esc(c.n.charAt(0)) + '</span><span class="ssc-dname">' + esc(c.n) + '</span><span class="ssc-dtag">front ' + (i + 1) + " of " + N + "</span></div><p class=\"ssc-dsum\">" + esc(c.sum) + "</p>" + caps;
      leg.querySelectorAll(".ssc-li").forEach(function (el) { el.classList.toggle("on", +el.dataset.i === i); });
    }
    svg.querySelectorAll(".ssc-cat").forEach(function (el) { el.addEventListener("click", function () { select(+el.dataset.i); }); });
    leg.querySelectorAll(".ssc-li").forEach(function (el) { el.addEventListener("click", function () { select(+el.dataset.i); }); });
    select(0);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", build);
  else build();
})();
