"""
Webhook server — listens for GitHub push/pull_request events and triggers SecureScope scans.

Usage:
    python webhook.py --port 8080 --secret <your-webhook-secret> --out-dir ./reports

GitHub setup:
    Payload URL : http://your-host:8080/webhook
    Content type: application/json
    Secret      : <same as --secret>
    Events      : push, pull_request
"""

import argparse
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


_SCAN_LOCK = threading.Lock()


def _verify_signature(payload: bytes, secret: str, sig_header: str) -> bool:
    """Verify GitHub's X-Hub-Signature-256 header."""
    if not sig_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


def _trigger_scan(repo_url: str, branch: str, out_dir: str, github_token: str | None) -> None:
    """Run a full SecureScope scan in a background thread."""
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    repo_slug = repo_url.rstrip("/").split("/")[-1]
    print(f"\n[webhook] Triggered scan: {repo_url} @ {branch}")

    try:
        from analyzer import analyze
        from report import to_json, to_html
        from sarif import to_sarif
        from sbom import generate_sbom
        from compliance import build_compliance_posture, posture_to_html

        result = analyze(repo_url)
        findings_raw = [f.to_dict() for f in result.findings]

        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)

        to_json(result, path=str(out / f"{repo_slug}_{ts}.json"))
        to_html(result, path=str(out / f"{repo_slug}_{ts}.html"))
        to_sarif(result, path=str(out / f"{repo_slug}_{ts}.sarif"))
        generate_sbom(result, path=str(out / f"{repo_slug}_{ts}.sbom.cyclonedx.json"))

        posture = build_compliance_posture(findings_raw)
        posture_path = out / f"{repo_slug}_{ts}_compliance.json"
        posture_path.write_text(json.dumps({
            "pci_dss": posture.pci_dss,
            "nist": posture.nist,
            "owasp": posture.owasp,
            "sans_top25_hit": posture.sans_top25_hit,
            "coverage_pct": posture.coverage_pct,
        }, indent=2))

        print(f"[webhook] Scan complete: {repo_url} — {len(result.findings)} findings")
    except Exception as exc:
        print(f"[webhook] Scan error: {exc}")


def _make_handler(secret: str, out_dir: str, github_token: str | None):
    class WebhookHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # suppress default access log

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok","service":"SecureScope-webhook"}')
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/webhook":
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)

            # Signature verification
            sig = self.headers.get("X-Hub-Signature-256", "")
            if secret and not _verify_signature(payload, secret, sig):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error":"invalid signature"}')
                return

            try:
                event = json.loads(payload)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return

            event_type = self.headers.get("X-GitHub-Event", "")
            repo_url = event.get("repository", {}).get("clone_url", "")
            branch = (
                event.get("ref", "refs/heads/main").replace("refs/heads/", "")
                if event_type == "push"
                else event.get("pull_request", {}).get("head", {}).get("ref", "main")
            )

            if not repo_url:
                self.send_response(422)
                self.end_headers()
                return

            if event_type in ("push", "pull_request"):
                t = threading.Thread(
                    target=_trigger_scan,
                    args=(repo_url, branch, out_dir, github_token),
                    daemon=True,
                )
                t.start()
                self.send_response(202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({"accepted": True, "repo": repo_url, "branch": branch}).encode()
                )
            else:
                # Ignore other events (star, fork, etc.)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"accepted":false,"reason":"unsupported event"}')

    return WebhookHandler


def run_webhook_server(port: int = 8080, secret: str = "", out_dir: str = "reports",
                       github_token: str | None = None) -> None:
    handler = _make_handler(secret, out_dir, github_token)
    server = HTTPServer(("0.0.0.0", port), handler)
    print(f"[webhook] SecureScope webhook server listening on :{port}")
    print(f"[webhook] POST /webhook  — GitHub push/PR trigger")
    print(f"[webhook] GET  /health   — liveness check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[webhook] Shutting down.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecureScope GitHub Webhook Server")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--secret", default=os.environ.get("WEBHOOK_SECRET", ""))
    parser.add_argument("--out-dir", default="reports")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    args = parser.parse_args()

    run_webhook_server(
        port=args.port,
        secret=args.secret,
        out_dir=args.out_dir,
        github_token=args.github_token,
    )
