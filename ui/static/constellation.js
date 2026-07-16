/*
 * SecureScope capability constellation — self-contained, dependency-free.
 * Renders an interactive radial mind map + detail panel into #ss-constellation.
 * No external fonts, no framework. Safe to embed on any page.
 * © 2026 Omar Rao. All rights reserved.
 */
(function () {
  function build() {
    var mount = document.getElementById("ss-constellation");
    if (!mount || mount.dataset.built) return;
    mount.dataset.built = "1";

    var cx = 380, cy = 340, Rh = 150, N;
    var cats = [
      { n: "Static analysis", c: "#38bdf8",
        sum: "Reads your source code without running it, pattern-matching for insecure code and mapping every hit to a known weakness and attacker technique.",
        l: [["Semgrep", "Fast open-source SAST engine scanning 30+ languages."],
            ["OWASP/CWE", "Rules aligned to the OWASP Top 10 and CWE/SANS Top 25."],
            ["Rulepacks", "Framework-specific packs (Flask, API, secrets) plus your own rules."],
            ["ATT&CK map", "Each finding mapped to the MITRE ATT&CK technique and tactic."],
            ["AI advisor", "LLM-generated remediation guidance and suggested patches."]] },
      { n: "Dependencies", c: "#a3e635",
        sum: "Inventories your third-party packages and flags the ones with known vulnerabilities — ranked by real-world exploit risk, not just severity.",
        l: [["OSV CVEs", "Cross-ecosystem vulnerability lookup against OSV.dev."],
            ["EPSS + KEV", "Prioritised by exploit probability (EPSS) and CISA known-exploited status."],
            ["Reachability", "Checks whether your code actually uses the vulnerable package."],
            ["Fix PRs", "One-click pull request bumping each package to its safe version."],
            ["Polyglot", "npm, cargo, go and bundler audits across every ecosystem."]] },
      { n: "Secrets & malware", c: "#fb7185",
        sum: "Hunts for leaked credentials and malicious code across the working tree and the full git history — not just the current commit.",
        l: [["Secret scan", "Detects API keys, tokens, private keys and cloud credentials."],
            ["Entropy", "Flags high-entropy strings that look like secrets without a known pattern."],
            ["Git history", "Scans past commits — secrets removed from HEAD still live in history."],
            ["YARA", "Signature matching for known malware and suspicious artifacts."],
            ["Ransomware", "Correlates findings with ransomware/APT indicators and blast-radius scoring."]] },
      { n: "Infrastructure", c: "#fbbf24",
        sum: "Checks how your code is deployed — infrastructure-as-code, containers and runtime behaviour — for misconfigurations and insecure defaults.",
        l: [["IaC checks", "Security checks across Terraform, K8s, CloudFormation, Ansible, Actions."],
            ["TF/K8s", "Cloud-native manifests scanned for insecure defaults and over-permissioning."],
            ["Trivy", "Dockerfile and container image layer CVE scanning."],
            ["Sandbox", "Optionally runs code in an isolated Docker sandbox to observe behaviour."]] },
      { n: "Governance", c: "#2dd4bf",
        sum: "Turns raw findings into audit-ready evidence and vets the integrity and health of your software supply chain.",
        l: [["PCI/NIST", "Maps findings to PCI DSS v4.0, NIST 800-53, OWASP and SANS Top 25."],
            ["Licenses", "Classifies dependency licenses for copyleft/GPL and commercial risk."],
            ["SBOM", "Generates a downloadable CycloneDX software bill of materials."],
            ["Typosquat", "Detects package name mimicry and dependency-confusion exposure."],
            ["OpenSSF", "Grades project health — maintenance, branch protection, signed releases."]] },
      { n: "Reporting", c: "#c084fc",
        sum: "Delivers results the way each audience needs — from executives reading a PDF to pipelines consuming SARIF.",
        l: [["HTML report", "Rich browser report with charts, threat scoring and attack-surface views."],
            ["PDF/SARIF", "PDF for humans, JSON for tooling, SARIF for GitHub code scanning."],
            ["Trends", "Tracks findings over time to show if your posture is improving."],
            ["PR comments", "Posts a Markdown summary straight onto the pull request."]] },
      { n: "Platform", c: "#f472b6",
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
      "#ss-constellation{padding:1rem 0;font-family:inherit}" +
      ".ssc-panel{position:relative;overflow:hidden;background:radial-gradient(58% 46% at 50% 40%,#15274a 0%,#0b1324 58%,#070c17 100%);border:1px solid rgba(120,170,255,.16);border-radius:18px;padding:26px 16px 22px}" +
      ".ssc-eye{font-size:12px;letter-spacing:.2em;text-transform:uppercase;color:#5eead4;margin:0;text-align:center}" +
      ".ssc-h{font-size:23px;font-weight:600;color:#f1f5f9;margin:8px 0 6px;line-height:1.3;text-align:center}" +
      ".ssc-sub{font-size:14px;color:#9fb0c9;line-height:1.55;margin:0 auto;text-align:center;max-width:560px}" +
      ".ssc-svg{display:block;width:100%;height:auto;margin:6px auto 0;max-width:760px}" +
      ".ssc-svg text{font-family:inherit}" +
      ".ssc-flow{stroke-dasharray:2 6;animation:sscdash 1.3s linear infinite}" +
      ".ssc-flow2{stroke-dasharray:2 6;animation:sscdash 2s linear infinite}" +
      "@keyframes sscdash{to{stroke-dashoffset:-16}}" +
      ".ssc-cat{transition:opacity .25s ease;cursor:pointer}" +
      ".ssc-svg:hover .ssc-cat{opacity:.24}.ssc-svg .ssc-cat:hover{opacity:1}" +
      ".ssc-ring{transform-origin:380px 340px;animation:sscspin 22s linear infinite}" +
      "@keyframes sscspin{to{transform:rotate(360deg)}}" +
      ".ssc-pulse{transform-origin:380px 340px;animation:sscpul 2.8s ease-out infinite}" +
      "@keyframes sscpul{0%{transform:scale(1);opacity:.45}70%{transform:scale(2.5);opacity:0}100%{opacity:0}}" +
      ".ssc-legend{display:flex;flex-wrap:wrap;justify-content:center;gap:8px 12px;margin-top:16px}" +
      ".ssc-li{display:flex;align-items:center;gap:7px;font-size:13px;color:#c4d0e2;cursor:pointer;padding:4px 11px;border-radius:999px;border:1px solid rgba(255,255,255,.08);transition:border-color .2s,background .2s}" +
      ".ssc-li:hover{border-color:var(--n);background:rgba(255,255,255,.05)}.ssc-li.on{border-color:var(--n);background:rgba(255,255,255,.08)}" +
      ".ssc-dot{width:11px;height:11px;border-radius:50%;background:var(--n);box-shadow:0 0 8px var(--n)}" +
      ".ssc-detail{margin:18px auto 0;max-width:720px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);border-left:3px solid var(--n);border-radius:12px;padding:18px 20px}" +
      ".ssc-dtop{display:flex;align-items:center;gap:11px;flex-wrap:wrap}" +
      ".ssc-dbadge{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:700;color:#04121a;background:var(--n)}" +
      ".ssc-dname{font-size:17px;font-weight:600;color:#f1f5f9}" +
      ".ssc-dtag{font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--n);margin-left:auto}" +
      ".ssc-dsum{font-size:14px;color:#aebccf;line-height:1.6;margin:11px 0 15px}" +
      ".ssc-cap{display:flex;gap:12px;padding:9px 0;border-top:1px solid rgba(255,255,255,.07)}" +
      ".ssc-cn{flex:0 0 130px;font-size:13px;font-weight:600;color:var(--n)}" +
      ".ssc-cd{flex:1;font-size:13px;color:#c1cdde;line-height:1.5}" +
      ".ssc-foot{text-align:center;font-size:12px;color:#647591;margin-top:14px}" +
      ".ssc-mobnote{display:none;text-align:center;font-size:13px;color:#9fb0c9;margin:2px 0 4px}" +
      "@media(max-width:640px){.ssc-svg{display:none}.ssc-foot{display:none}.ssc-mobnote{display:block}.ssc-panel{padding:22px 13px 18px}.ssc-h{font-size:20px}}" +
      "@media(max-width:540px){.ssc-cn{flex-basis:100%;flex-basis:104px}}";

    var st = document.createElement("style");
    st.textContent = css;
    document.head.appendChild(st);

    mount.innerHTML =
      '<div class="ssc-panel">' +
      '<p class="ssc-eye">SecureScope · capability constellation</p>' +
      '<h2 class="ssc-h">Your code enters the core. Seven fronts light up.</h2>' +
      '<p class="ssc-sub">Every scan fires signals from the core across seven fronts of security. Click any front for a full briefing on what it does.</p>' +
      '<svg class="ssc-svg" id="sscSvg" viewBox="0 0 760 700" role="img" aria-hidden="true"></svg>' +
      '<p class="ssc-mobnote">Tap a front to explore its capabilities.</p>' +
      '<div class="ssc-legend" id="sscLegend"></div>' +
      '<div class="ssc-detail" id="sscDetail"></div>' +
      '<p class="ssc-foot">Hover to isolate a front · click a front or legend chip for its full briefing</p>' +
      '</div>';

    var svg = mount.querySelector("#sscSvg"),
        leg = mount.querySelector("#sscLegend"),
        det = mount.querySelector("#sscDetail");

    var s = '<defs><radialGradient id="sscCore" cx="36%" cy="30%"><stop offset="0%" stop-color="#5cf3e4"/><stop offset="100%" stop-color="#0a8f9c"/></radialGradient></defs>';
    for (var i = 0; i < N; i++) {
      var ang = (-90 + i * (360 / N)) * Math.PI / 180, ca = Math.cos(ang), sa = Math.sin(ang);
      var hx = cx + Rh * ca, hy = cy + Rh * sa, col = cats[i].c;
      var g = '<g class="ssc-cat" data-i="' + i + '">';
      var cpx = cx + Rh * 0.55 * ca - 18 * sa, cpy = cy + Rh * 0.55 * sa + 18 * ca;
      g += '<path class="ssc-flow" d="M' + cx + ',' + cy + ' Q' + cpx.toFixed(1) + ',' + cpy.toFixed(1) + ' ' + hx.toFixed(1) + ',' + hy.toFixed(1) + '" fill="none" stroke="' + col + '" stroke-width="2.4" stroke-opacity="0.85"/>';
      var M = cats[i].l.length, spread = 40 * Math.PI / 180;
      for (var j = 0; j < M; j++) {
        var la = ang + (M > 1 ? (j - (M - 1) / 2) * (spread / (M - 1)) : 0);
        var Rl = 214 + (j % 3) * 36, lca = Math.cos(la), lsa = Math.sin(la);
        var lx = cx + Rl * lca, ly = cy + Rl * lsa;
        var mpx = hx + (lx - hx) * 0.5 - 12 * Math.sin(la), mpy = hy + (ly - hy) * 0.5 + 12 * Math.cos(la);
        g += '<path class="ssc-flow2" d="M' + hx.toFixed(1) + ',' + hy.toFixed(1) + ' Q' + mpx.toFixed(1) + ',' + mpy.toFixed(1) + ' ' + lx.toFixed(1) + ',' + ly.toFixed(1) + '" fill="none" stroke="' + col + '" stroke-width="1.3" stroke-opacity="0.45"/>';
        g += '<circle cx="' + lx.toFixed(1) + '" cy="' + ly.toFixed(1) + '" r="4.5" fill="' + col + '"/>';
      }
      g += '<circle cx="' + hx.toFixed(1) + '" cy="' + hy.toFixed(1) + '" r="18" fill="#0b1324" stroke="' + col + '" stroke-opacity="0.5" stroke-width="1.2"/>';
      g += '<circle cx="' + hx.toFixed(1) + '" cy="' + hy.toFixed(1) + '" r="7" fill="' + col + '"/>';
      var hr = ca >= 0;
      g += '<text x="' + (hx + ca * 26).toFixed(1) + '" y="' + (hy + sa * 26 + 4).toFixed(1) + '" text-anchor="' + (hr ? "start" : "end") + '" fill="' + col + '" font-size="14.5" font-weight="600">' + esc(cats[i].n) + '</text>';
      g += "</g>";
      s += g;
    }
    s += '<circle class="ssc-pulse" cx="' + cx + '" cy="' + cy + '" r="40" fill="none" stroke="#5eead4" stroke-width="1.6"/>';
    s += '<circle class="ssc-ring" cx="' + cx + '" cy="' + cy + '" r="60" fill="none" stroke="#5eead4" stroke-opacity="0.3" stroke-width="1.1" stroke-dasharray="4 8"/>';
    s += '<circle cx="' + cx + '" cy="' + cy + '" r="42" fill="url(#sscCore)"/>';
    s += '<text x="' + cx + '" y="' + (cy - 4) + '" text-anchor="middle" fill="#04121a" font-size="13" font-weight="700" letter-spacing="1.2">SECURE</text>';
    s += '<text x="' + cx + '" y="' + (cy + 13) + '" text-anchor="middle" fill="#04121a" font-size="13" font-weight="700" letter-spacing="1.2">SCOPE</text>';
    svg.innerHTML = s;

    var lg = "";
    for (var k = 0; k < N; k++) {
      lg += '<span class="ssc-li" data-i="' + k + '" style="--n:' + cats[k].c + '"><span class="ssc-dot"></span>' + esc(cats[k].n) + "</span>";
    }
    leg.innerHTML = lg;

    function esc(t) { return String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
    function select(i) {
      var c = cats[i];
      det.style.setProperty("--n", c.c);
      var caps = c.l.map(function (x) {
        return '<div class="ssc-cap"><div class="ssc-cn">' + esc(x[0]) + '</div><div class="ssc-cd">' + esc(x[1]) + "</div></div>";
      }).join("");
      det.innerHTML =
        '<div class="ssc-dtop"><span class="ssc-dbadge">' + esc(c.n.charAt(0)) + '</span>' +
        '<span class="ssc-dname">' + esc(c.n) + '</span>' +
        '<span class="ssc-dtag">front ' + (i + 1) + " of " + N + "</span></div>" +
        '<p class="ssc-dsum">' + esc(c.sum) + "</p>" + caps;
      leg.querySelectorAll(".ssc-li").forEach(function (el) { el.classList.toggle("on", +el.dataset.i === i); });
    }
    svg.querySelectorAll(".ssc-cat").forEach(function (el) { el.addEventListener("click", function () { select(+el.dataset.i); }); });
    leg.querySelectorAll(".ssc-li").forEach(function (el) { el.addEventListener("click", function () { select(+el.dataset.i); }); });
    select(0);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", build);
  else build();
})();
