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

    # ── 6. Reports ──────────────────────────────────────────────
    from report import to_json, to_html
    json_path = str(out_dir / f"{repo_slug}_{ts}.json")
    html_path = str(out_dir / f"{repo_slug}_{ts}.html")
    to_json(result, obs, enriched, json_path)
    to_html(result, obs, enriched, html_path, compliance_html=compliance_html,
            container_vulns=container_vulns)

    # ── 7. SARIF ────────────────────────────────────────────────
    if args.sarif:
        from sarif import to_sarif
        to_sarif(result, enriched, str(out_dir / f"{repo_slug}_{ts}.sarif"))

    # ── 8. SBOM ─────────────────────────────────────────────────
    if args.sbom:
        from sbom import generate_sbom
        generate_sbom(result, str(out_dir / f"{repo_slug}_{ts}.sbom.cyclonedx.json"))

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

    # New feature flags
    parser.add_argument("--sarif", action="store_true", help="Export SARIF 2.1.0 report")
    parser.add_argument("--sbom", action="store_true", help="Export CycloneDX SBOM")
    parser.add_argument("--image", default="", help="Container image for Trivy scan")
    parser.add_argument("--compliance", action="store_true", help="Include compliance posture section")

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

    if len(repos) > 1:
        print(f"[*] Multi-repo scan: {len(repos)} repositories")

    for repo_url in repos:
        try:
            _scan_one(repo_url, args, out_dir)
        except Exception as exc:
            print(f"[!] Scan failed for {repo_url}: {exc}")


if __name__ == "__main__":
    main()
