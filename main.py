"""
SecureScope CLI — entry point.

Usage:
  # Single repo
  python main.py --repo https://github.com/owner/repo [OPTIONS]

  # Multi-repo (comma-separated or --repos-file)
  python main.py --repos https://github.com/org/a,https://github.com/org/b [OPTIONS]
  python main.py --repos-file repos.txt [OPTIONS]

  # Container image scan (Trivy)
  python main.py --repo https://github.com/owner/repo --image python:3.11-slim [OPTIONS]

  # Webhook server mode
  python main.py --webhook --port 8080 --webhook-secret <secret> [OPTIONS]

Options:
  --branch BRANCH          Target branch (default: main)
  --no-sandbox             Skip Docker sandbox execution
  --no-advisor             Skip Claude fix advisory (faster, no API cost)
  --commit                 Actually commit fixes (default: dry-run)
  --max-findings N         Max findings to advise on (default: 20)
  --out-dir DIR            Output directory for reports (default: ./reports)
  --sarif                  Also produce a SARIF 2.1.0 output file
  --sbom                   Also produce a CycloneDX SBOM file
  --image IMAGE            Container image to scan with Trivy (e.g. python:3.11-slim)
  --compliance             Include compliance posture section in HTML report
  --github-token TOKEN     GitHub PAT (or set GITHUB_TOKEN env var)
  --anthropic-key KEY      Anthropic API key (or set ANTHROPIC_API_KEY env var)
  --webhook                Run as a webhook server (mutually exclusive with --repo)
  --port PORT              Webhook server port (default: 8080)
  --webhook-secret SECRET  GitHub webhook secret (or set WEBHOOK_SECRET env var)
"""

import argparse
import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime


def _scan_one(repo_url: str, args, out_dir: Path) -> None:
    """Run the full scan pipeline for a single repo."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    repo_slug = repo_url.rstrip("/").split("/")[-1]

    print(f"\n{'='*60}")
    print(f"  Security Review: {repo_url}")
    print(f"{'='*60}\n")

    # ── 1. Static Analysis ──────────────────────────────────────
    if args.pr_diff:
        from analyzer import analyze_pr
        result = analyze_pr(repo_url, base_branch=args.base_branch)
        print(f"\n[+] PR diff scan ({len(result.changed_files)} changed files):")
    else:
        from analyzer import analyze
        result = analyze(repo_url)
    print(f"\n[+] Static analysis complete:")
    print(f"    Findings : {len(result.findings)}")
    print(f"    CVEs     : {len(result.dependency_vulns)}")
    for e in result.scan_errors:
        print(f"    [!] {e}")

    # ── 2. Sandbox Execution ────────────────────────────────────
    obs = None
    if not args.no_sandbox:
        print("\n[*] Starting sandbox execution...")
        from sandbox import run_in_sandbox
        obs = run_in_sandbox(result.repo_path)
        print(f"[+] Sandbox complete (exit={obs.exit_code})")
        for b in obs.suspicious_behaviors:
            print(f"    [!] {b}")
        if obs.stderr and "Docker unavailable" in obs.stderr:
            print(f"    [!] {obs.stderr}")
            obs = None

    # ── 3. Fix Advisor ──────────────────────────────────────────
    enriched = None
    if not args.no_advisor and result.findings:
        print("\n[*] Generating fix advisories via Claude API...")
        from advisor import enrich_findings, advise_runtime
        enriched = enrich_findings(result, obs, max_findings=args.max_findings)
        if obs and obs.suspicious_behaviors:
            runtime_advice = advise_runtime(obs)
            print(f"\n{'─'*50}\nRuntime Advisory:\n{runtime_advice}\n{'─'*50}")

    findings_raw = enriched or [f.to_dict() for f in result.findings]

    # ── 3b. False Positive Suppression ─────────────────────────
    suppressed_findings = []
    if result.repo_path:
        from false_positives import load_suppressions, apply_suppressions
        suppressions = load_suppressions(result.repo_path)
        if suppressions:
            active, suppressed_findings = apply_suppressions(result.findings, suppressions)
            print(f"[+] Suppressions: {len(suppressed_findings)} findings suppressed")
            result.findings = active

    # ── Secret Scanning ─────────────────────────────────────────
    secret_findings = []
    if args.secret_scan and result.repo_path:
        print("\n[*] Scanning for hardcoded secrets...")
        from secret_scanner import scan_secrets
        secret_findings = scan_secrets(result.repo_path)
        print(f"[+] Secrets: {len(secret_findings)} potential secrets found")

    # ── IaC Scanning ────────────────────────────────────────────
    iac_findings = []
    if args.iac_scan and result.repo_path:
        print("\n[*] Scanning IaC files (Checkov)...")
        from iac_scanner import scan_iac
        iac_findings = scan_iac(result.repo_path)
        print(f"[+] IaC: {len(iac_findings)} policy violations found")

    # ── 4. Compliance Posture ───────────────────────────────────
    compliance_html = ""
    if args.compliance:
        from compliance import build_compliance_posture, posture_to_html
        posture = build_compliance_posture(findings_raw)
        compliance_html = posture_to_html(posture)
        posture_path = out_dir / f"{repo_slug}_{ts}_compliance.json"
        posture_path.write_text(json.dumps({
            "pci_dss": posture.pci_dss,
            "nist": posture.nist,
            "owasp": posture.owasp,
            "sans_top25_hit": posture.sans_top25_hit,
            "coverage_pct": posture.coverage_pct,
        }, indent=2))
        print(f"[+] Compliance posture: {posture.coverage_pct}% findings mapped ({posture_path})")

    # ── 5. Trivy Container Scan ─────────────────────────────────
    container_vulns = []
    if args.image:
        from trivy_scanner import scan_container_image, scan_dockerfile
        container_vulns = scan_container_image(args.image)
        if result.repo_path:
            container_vulns += scan_dockerfile(result.repo_path)
        trivy_path = out_dir / f"{repo_slug}_{ts}_trivy.json"
        trivy_path.write_text(json.dumps([v.to_dict() for v in container_vulns], indent=2))
        print(f"[+] Trivy: {len(container_vulns)} container issues -> {trivy_path}")

    # ── 5b. OpenSSF Scorecard ───────────────────────────────────
    scorecard_data = None
    if args.scorecard:
        print("\n[*] Running OpenSSF Scorecard...")
        from scorecard import run_scorecard
        scorecard_data = run_scorecard(repo_url)
        score_val = scorecard_data.get("score")
        print(f"[+] Scorecard score: {score_val}/10" if score_val else "[!] Scorecard unavailable")

    # ── 5c. DAST ────────────────────────────────────────────────
    dast_findings = None
    if args.dast_url:
        print(f"\n[*] Running DAST against {args.dast_url}...")
        from dast import scan_with_nuclei, scan_with_zap
        dast_findings = scan_with_nuclei(args.dast_url)
        if not dast_findings:
            dast_findings = scan_with_zap(args.dast_url)
        print(f"[+] DAST: {len(dast_findings)} findings")

    # ── 5d. License Scan ────────────────────────────────────────
    license_results = None
    if args.license_scan and result.repo_path:
        print("\n[*] Scanning licenses...")
        from license_scanner import scan_licenses
        license_results = scan_licenses(result.repo_path)
        high_risk = sum(1 for r in license_results if r["risk"] == "high")
        print(f"[+] Licenses: {len(license_results)} packages, {high_risk} high-risk")

    # ── 5e. Supply Chain ────────────────────────────────────────
    supply_chain_findings = None
    if args.supply_chain and result.repo_path:
        print("\n[*] Checking supply-chain risks...")
        from supply_chain import check_dependency_confusion, check_typosquatting
        supply_chain_findings = (
            check_dependency_confusion(result.repo_path) +
            check_typosquatting(result.repo_path)
        )
        print(f"[+] Supply chain: {len(supply_chain_findings)} issues")

    # ── 5f. Trend Tracking ──────────────────────────────────────
    from trend import append_scan_record, load_trend
    append_scan_record(result, str(out_dir))
    trend_records = load_trend(repo_url, str(out_dir))

    # ── Polyglot Dependency Scan ────────────────────────────────
    polyglot_findings = []
    if args.polyglot and result.repo_path:
        print("\n[*] Running polyglot dependency scan...")
        from polyglot_scanner import scan_polyglot
        polyglot_findings = scan_polyglot(result.repo_path)
        print(f"[+] Polyglot: {len(polyglot_findings)} dependency issues across all ecosystems")

    # ── 6. Reports ──────────────────────────────────────────────
    from report import to_json, to_html
    json_path = str(out_dir / f"{repo_slug}_{ts}.json")
    html_path = str(out_dir / f"{repo_slug}_{ts}.html")
    sarif_path = str(out_dir / f"{repo_slug}_{ts}.sarif") if args.sarif else None
    to_json(result, obs, enriched, json_path)
    to_html(result, obs, enriched, html_path,
            compliance_html=compliance_html,
            container_vulns=container_vulns,
            scorecard_data=scorecard_data,
            dast_findings=dast_findings,
            license_results=license_results,
            supply_chain_findings=supply_chain_findings,
            trend_records=trend_records,
            suppressed_findings=suppressed_findings if suppressed_findings else None,
            secret_findings=secret_findings if secret_findings else None,
            iac_findings=iac_findings if iac_findings else None,
            polyglot_findings=polyglot_findings if polyglot_findings else None)

    # ── Markdown Summary ────────────────────────────────────────
    from markdown_report import to_markdown, post_pr_comment
    md_path = str(out_dir / f"{repo_slug}_{ts}.md")
    to_markdown(result, md_path, secret_findings=secret_findings, iac_findings=iac_findings)
    if args.pr_comment and args.github_token:
        post_pr_comment(repo_url, args.github_token, md_path, pr_number=getattr(args, 'pr_number', None))

    # ── 7. SARIF ────────────────────────────────────────────────
    if args.sarif:
        from sarif import to_sarif
        to_sarif(result, enriched, str(out_dir / f"{repo_slug}_{ts}.sarif"))

    # ── 8. SBOM ─────────────────────────────────────────────────
    sbom_path = str(out_dir / f"{repo_slug}_{ts}.sbom.cyclonedx.json")
    if args.sbom:
        from sbom import generate_sbom
        generate_sbom(result, sbom_path)

    # ── PDF Export ───────────────────────────────────────────────
    if args.pdf:
        from pdf_report import to_pdf
        pdf_path = str(out_dir / f"{repo_slug}_{ts}.pdf")
        to_pdf(html_path, pdf_path)

    # ── SQLite Persistence ───────────────────────────────────────
    if args.use_db:
        from db import init_db, record_scan
        init_db(args.db_path)
        record_scan(args.db_path, result, {
            "html": html_path,
            "sarif": sarif_path if args.sarif else None,
            "sbom": sbom_path if args.sbom else None,
        })
        print(f"[+] Results persisted to SQLite: {args.db_path}")

    # ── SLA Check ────────────────────────────────────────────────
    if args.sla_check and args.use_db:
        from sla_tracker import check_sla, update_sla_status
        update_sla_status(args.db_path)
        breaches = check_sla(args.db_path,
                             slack_webhook=getattr(args, 'slack_webhook', None) or None)
        if breaches:
            print(f"[!] SLA breaches: {len(breaches)} findings past SLA threshold")
        else:
            print("[+] SLA check: no breaches")

    # ── Jira Integration ─────────────────────────────────────────
    if args.jira_url and args.jira_token:
        from jira_integration import create_jira_issues
        created = create_jira_issues(
            args.jira_url,
            args.jira_email,
            args.jira_token,
            args.jira_project,
            findings_raw,
            threshold="HIGH",
        )
        print(f"[+] Jira: {len(created)} issues created")

    # ── SBOM Diff ────────────────────────────────────────────────
    if args.sbom_diff and args.sbom:
        from sbom_diff import diff_sboms, diff_to_markdown
        diff = diff_sboms(args.sbom_diff, sbom_path)
        diff_md_path = str(out_dir / f"{repo_slug}_{ts}_sbom_diff.md")
        Path(diff_md_path).write_text(diff_to_markdown(diff))
        print(f"[+] SBOM diff: {len(diff['added'])} added, {len(diff['removed'])} removed, "
              f"{len(diff['version_changed'])} changed -> {diff_md_path}")

    # ── 8b. Notifications ───────────────────────────────────────
    if args.slack_webhook:
        from notifications import send_slack_notification
        ok = send_slack_notification(result, args.slack_webhook,
                                     report_url=f"file://{html_path}")
        print(f"[+] Slack notification: {'sent' if ok else 'failed'}")

    if args.teams_webhook:
        from notifications import send_teams_notification
        ok = send_teams_notification(result, args.teams_webhook,
                                     report_url=f"file://{html_path}")
        print(f"[+] Teams notification: {'sent' if ok else 'failed'}")

    # ── 8c. GitHub Issues ───────────────────────────────────────
    if args.create_issues and args.github_token:
        from github_issues import create_issues_for_findings
        findings_raw = enriched or [f.to_dict() for f in result.findings]
        issue_results = create_issues_for_findings(
            repo_url=repo_url,
            github_token=args.github_token,
            findings=findings_raw,
            severity_threshold="ERROR",
        )
        created = sum(1 for r in issue_results if r.get("status") == "created")
        print(f"[+] GitHub Issues: {created} created, {len(issue_results)-created} already existed")

    # ── 9. Commit Fixes ─────────────────────────────────────────
    if enriched and args.github_token:
        from github_agent import commit_all_fixes
        commit_results = commit_all_fixes(
            repo_url=repo_url,
            github_token=args.github_token,
            enriched_findings=enriched,
            target_branch=args.branch,
            dry_run=not args.commit,
        )
        committed = sum(1 for r in commit_results if r.get("status") == "committed")
        print(f"\n[+] Commits: {committed}/{len(commit_results)} applied")
        commit_log = str(out_dir / f"{repo_slug}_{ts}_commits.json")
        Path(commit_log).write_text(json.dumps(commit_results, indent=2))
        print(f"[+] Commit log: {commit_log}")

    # ── Cleanup ─────────────────────────────────────────────────
    if result.repo_path and result.repo_path.startswith(str(Path(sys.prefix).parent)):
        shutil.rmtree(result.repo_path, ignore_errors=True)

    print(f"\n{'='*60}")
    print(f"  Done. Reports saved to: {out_dir}/")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecureScope — AI-powered GitHub security scanner"
    )
    # Repo targeting
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--repo", help="Single GitHub repo URL")
    target.add_argument("--repos", help="Comma-separated list of GitHub repo URLs")
    target.add_argument("--repos-file", help="File with one GitHub repo URL per line")

    parser.add_argument("--branch", default="main")
    parser.add_argument("--no-sandbox", action="store_true")
    parser.add_argument("--no-advisor", action="store_true")
    parser.add_argument("--commit", action="store_true")
    parser.add_argument("--max-findings", type=int, default=20)
    parser.add_argument("--out-dir", default="reports")

    # Existing feature flags
    parser.add_argument("--sarif", action="store_true", help="Export SARIF 2.1.0 report")
    parser.add_argument("--sbom", action="store_true", help="Export CycloneDX SBOM")
    parser.add_argument("--image", default="", help="Container image for Trivy scan")
    parser.add_argument("--compliance", action="store_true", help="Include compliance posture section")

    # v8.0.0 feature flags
    parser.add_argument("--slack-webhook", default="", metavar="URL",
                        help="Post scan results to this Slack incoming webhook URL")
    parser.add_argument("--teams-webhook", default="", metavar="URL",
                        help="Post scan results to this Microsoft Teams webhook URL")
    parser.add_argument("--create-issues", action="store_true",
                        help="Auto-create GitHub Issues for ERROR findings (requires --github-token)")
    parser.add_argument("--scorecard", action="store_true",
                        help="Run OpenSSF Scorecard for the repository")
    parser.add_argument("--dast-url", default="", metavar="URL",
                        help="Run DAST (Nuclei/ZAP) against this URL")
    parser.add_argument("--license-scan", action="store_true",
                        help="Scan dependency licenses for copyleft/compliance risk")
    parser.add_argument("--supply-chain", action="store_true",
                        help="Check for dependency confusion and typosquatting")
    parser.add_argument("--pr-diff", action="store_true",
                        help="Only scan files changed vs base branch (PR diff mode)")
    parser.add_argument("--base-branch", default="main",
                        help="Base branch for PR diff mode (default: main)")
    parser.add_argument("--suppress-fp", nargs=3, metavar=("RULE_ID", "FILE", "REASON"),
                        help="Add a false positive suppression to .secscope-suppressions.json")

    # v9.0.0 feature flags
    parser.add_argument("--secret-scan", action="store_true",
                        help="Scan for hardcoded secrets using detect-secrets")
    parser.add_argument("--iac-scan", action="store_true",
                        help="Scan IaC files (Terraform, CloudFormation, K8s, Dockerfiles) using Checkov")
    parser.add_argument("--pr-comment", action="store_true",
                        help="Post markdown summary as a GitHub PR comment (requires --github-token)")
    parser.add_argument("--pr-number", type=int, default=None,
                        help="PR number for --pr-comment (auto-detects latest open PR if omitted)")

    # v10.0.0 feature flags
    parser.add_argument("--polyglot", action="store_true",
                        help="Run polyglot dependency scan (npm, cargo, go, bundler, maven)")
    parser.add_argument("--sbom-diff", default="", metavar="OLD_SBOM",
                        help="Compare current SBOM against this CycloneDX JSON path")
    parser.add_argument("--db-path", default="secscope.db",
                        help="SQLite database path (default: secscope.db)")
    parser.add_argument("--use-db", action="store_true",
                        help="Persist scan results to SQLite database")
    parser.add_argument("--sla-check", action="store_true",
                        help="Check SLA breaches after scan (requires --use-db)")
    parser.add_argument("--jira-url", default="", help="Jira Cloud base URL")
    parser.add_argument("--jira-email", default="", help="Jira user email for Basic Auth")
    parser.add_argument("--jira-token", default="", help="Jira API token")
    parser.add_argument("--jira-project", default="", help="Jira project key (e.g. SEC)")
    parser.add_argument("--pdf", action="store_true", help="Export HTML report to PDF")
    parser.add_argument("--github-app-id", default="", help="GitHub App ID for App-based auth")
    parser.add_argument("--github-app-key", default="", help="Path to GitHub App private key PEM file")
    parser.add_argument("--max-workers", type=int, default=4,
                        help="Concurrent workers for multi-repo scanning (default: 4)")

    # Credentials
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--anthropic-key", default=os.environ.get("ANTHROPIC_API_KEY"))

    # Webhook mode
    parser.add_argument("--webhook", action="store_true", help="Run as webhook server")
    parser.add_argument("--port", type=int, default=8080, help="Webhook server port")
    parser.add_argument("--webhook-secret", default=os.environ.get("WEBHOOK_SECRET", ""),
                        help="GitHub webhook secret")

    args = parser.parse_args()

    # ── Webhook server mode ─────────────────────────────────────
    if args.webhook:
        from webhook import run_webhook_server
        run_webhook_server(
            port=args.port,
            secret=args.webhook_secret,
            out_dir=args.out_dir,
            github_token=args.github_token,
        )
        return

    # ── Validate for scan mode ──────────────────────────────────
    if not args.repo and not args.repos and not args.repos_file:
        parser.error("One of --repo, --repos, --repos-file, or --webhook is required.")

    if not args.no_advisor and not args.anthropic_key:
        print("[!] Error: ANTHROPIC_API_KEY required for advisor. Use --no-advisor or set env var.")
        sys.exit(1)
    if args.anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_key

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build repo list
    repos: list[str] = []
    if args.repo:
        repos = [args.repo]
    elif args.repos:
        repos = [r.strip() for r in args.repos.split(",") if r.strip()]
    elif args.repos_file:
        repos = [
            line.strip()
            for line in Path(args.repos_file).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]

    if not repos:
        print("[!] No repos to scan.")
        sys.exit(1)

    # ── Handle --suppress-fp (standalone: add suppression then continue) ────
    if args.suppress_fp:
        rule_id, file_path, reason = args.suppress_fp
        # We need a local path; clone the first repo if it's a URL
        import tempfile
        tmp = tempfile.mkdtemp(prefix="secscope_fp_")
        try:
            from analyzer import clone_repo
            clone_repo(repos[0], tmp)
            from false_positives import save_suppression
            save_suppression(tmp, rule_id, file_path, reason)
            print(f"[+] Suppression added: {rule_id} in {file_path}")
            # Copy suppression file back to cwd if it doesn't exist there
            import shutil as _sh
            src = Path(tmp) / ".secscope-suppressions.json"
            dst = Path(".secscope-suppressions.json")
            if src.exists() and not dst.exists():
                _sh.copy(src, dst)
        except Exception as exc:
            print(f"[!] Could not add suppression: {exc}")
        finally:
            import shutil as _sh
            _sh.rmtree(tmp, ignore_errors=True)

    if len(repos) > 1:
        print(f"[*] Multi-repo scan: {len(repos)} repositories (max_workers={args.max_workers})")
        from queue_runner import ScanQueue
        q = ScanQueue(max_workers=args.max_workers)
        for repo_url in repos:
            q.add_repo(repo_url)
        q.start(args, out_dir)
        q.wait()
        if q.failed:
            print(f"[!] {len(q.failed)} scans failed: {', '.join(q.failed)}")
    else:
        for repo_url in repos:
            try:
                _scan_one(repo_url, args, out_dir)
            except Exception as exc:
                print(f"[!] Scan failed for {repo_url}: {exc}")


if __name__ == "__main__":
    main()
