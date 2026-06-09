"""
Security Review CLI — entry point.

Usage:
  python main.py --repo https://github.com/owner/repo [OPTIONS]

Options:
  --branch BRANCH       Target branch for commits (default: main)
  --no-sandbox          Skip Docker sandbox execution
  --no-advisor          Skip Claude fix advisory (faster, no API cost)
  --commit              Actually commit fixes (default: dry-run)
  --max-findings N      Max findings to advise on (default: 20)
  --out-dir DIR         Output directory for reports (default: ./reports)
  --github-token TOKEN  GitHub PAT (or set GITHUB_TOKEN env var)
  --anthropic-key KEY   Anthropic API key (or set ANTHROPIC_API_KEY env var)
"""

import argparse
import os
import sys
import json
import shutil
from pathlib import Path
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(
        description="GitHub Security Review with MITRE mapping and auto-fix advisor"
    )
    parser.add_argument("--repo", required=True, help="GitHub repo URL")
    parser.add_argument("--branch", default="main", help="Target branch")
    parser.add_argument("--no-sandbox", action="store_true", help="Skip Docker sandbox")
    parser.add_argument("--no-advisor", action="store_true", help="Skip Claude fix advisor")
    parser.add_argument("--commit", action="store_true", help="Commit fixes to GitHub (default: dry-run)")
    parser.add_argument("--max-findings", type=int, default=20, help="Max findings to advise on")
    parser.add_argument("--out-dir", default="reports", help="Report output directory")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"), help="GitHub PAT")
    parser.add_argument("--anthropic-key", default=os.environ.get("ANTHROPIC_API_KEY"), help="Anthropic API key")
    args = parser.parse_args()

    # Validate credentials
    if not args.no_advisor and not args.anthropic_key:
        print("[!] Error: ANTHROPIC_API_KEY required for advisor. Set env var or use --anthropic-key.")
        sys.exit(1)
    if args.commit and not args.github_token:
        print("[!] Error: GITHUB_TOKEN required for committing fixes. Set env var or use --github-token.")
        sys.exit(1)
    if args.anthropic_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_key

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    repo_slug = args.repo.rstrip("/").split("/")[-1]

    print(f"\n{'='*60}")
    print(f"  Security Review: {args.repo}")
    print(f"{'='*60}\n")

    # ── 1. Static Analysis ──────────────────────────────────────
    from analyzer import analyze
    result = analyze(args.repo)
    print(f"\n[+] Static analysis complete:")
    print(f"    Findings : {len(result.findings)}")
    print(f"    CVEs     : {len(result.dependency_vulns)}")
    if result.scan_errors:
        for e in result.scan_errors:
            print(f"    [!] {e}")

    # ── 2. Sandbox Execution ────────────────────────────────────
    obs = None
    if not args.no_sandbox:
        print("\n[*] Starting sandbox execution...")
        from sandbox import run_in_sandbox
        obs = run_in_sandbox(result.repo_path)
        print(f"[+] Sandbox complete (exit={obs.exit_code})")
        if obs.suspicious_behaviors:
            print(f"    [!] Suspicious behaviors: {len(obs.suspicious_behaviors)}")
            for b in obs.suspicious_behaviors:
                print(f"        - {b}")
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

    # ── 4. Reports ──────────────────────────────────────────────
    from report import to_json, to_html
    json_path = str(out_dir / f"{repo_slug}_{ts}.json")
    html_path = str(out_dir / f"{repo_slug}_{ts}.html")
    to_json(result, obs, enriched, json_path)
    to_html(result, obs, enriched, html_path)

    # ── 5. Commit Fixes ─────────────────────────────────────────
    if enriched and args.github_token:
        from github_agent import commit_all_fixes
        commit_results = commit_all_fixes(
            repo_url=args.repo,
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


if __name__ == "__main__":
    main()
