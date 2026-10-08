# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
In-network collector runtime (Phase 2).

Runs *inside* the customer network: reads a local target config, collects a
read-only snapshot per target with the matching connector, runs the assessors,
and builds a posture object. Optionally ships that posture — **findings only,
never credentials** — to the hosted dashboard's ingest endpoint over TLS.

Credentials are resolved locally (e.g. from environment variables named by each
target), used only by the connector, and never placed in the payload.

Config (infra_targets.json) is a list of targets, e.g.:
    [
      {"id":"esxi01","kind":"vmware_esxi","host":"esxi01.local",
       "user":"readonly","password_env":"ESXI01_PW","insecure":false},
      {"id":"aws-prod","kind":"aws_account","region":"us-east-1","profile":"secaudit"}
    ]

Usage:
    python -m infra.collector --config infra_targets.json             # print posture
    python -m infra.collector --config infra_targets.json \
        --ingest-url https://host/api/infra/ingest --token-env INFRA_INGEST_TOKEN
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error

from .base import Target, assess_snapshot, summarize
from .report import build_infra_posture


def collect_snapshot(target: dict) -> dict:
    """Collect a read-only snapshot for one target using its connector.

    Never raises: on any failure returns a minimal snapshot so the assessor
    emits UNKNOWN findings rather than aborting the run.
    """
    kind = target.get("kind", "")
    try:
        if kind in ("vmware_esxi", "vmware_vcenter"):
            from .connectors import vmware as vmw
            pw = os.environ.get(target.get("password_env", ""), "")
            snap = vmw.collect_snapshot(
                target["host"], target.get("user", ""), pw,
                insecure=bool(target.get("insecure")))
            snap.setdefault("id", target.get("id"))
            return snap
        if kind == "aws_account":
            from .connectors import aws as awsc
            snap = awsc.collect_snapshot(
                region=target.get("region", "us-east-1"), profile=target.get("profile", ""))
            snap["id"] = target.get("id") or snap.get("host")
            return snap
    except Exception as exc:
        return {"kind": kind, "id": target.get("id"), "host": target.get("host", ""),
                "_error": f"{type(exc).__name__}"}
    return {"kind": kind, "id": target.get("id"), "host": target.get("host", "")}


def run(config_path: str) -> dict:
    """Assess every target in the config and return a posture object."""
    targets = json.loads(open(config_path, encoding="utf-8").read())
    assessments = []
    for t in targets:
        snap = collect_snapshot(t)
        target = Target(id=t.get("id") or snap.get("host") or t.get("kind", ""),
                        kind=t.get("kind", ""), host=snap.get("host", t.get("host", "")))
        findings = assess_snapshot(target.kind, snap)
        assessments.append(summarize(target, findings))
    return build_infra_posture(assessments)


def submit(posture: dict, ingest_url: str, token: str, collector_id: str = "") -> bool:
    """POST the posture (findings only) to the ingest endpoint. Returns success."""
    if not ingest_url or not token:
        return False
    payload = dict(posture)
    # Only an explicitly-provided id is sent — never the machine hostname — so
    # the collector doesn't leak environment details it wasn't asked to.
    payload["collector_id"] = collector_id or ""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(ingest_url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "X-Infra-Token": token,
        "User-Agent": "SecureScope-Collector",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        print(f"[collector] ingest failed: HTTP {e.code}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[collector] ingest failed: {type(e).__name__}", file=sys.stderr)
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="SecureScope infrastructure collector")
    p.add_argument("--config", required=True, help="Path to infra_targets.json")
    p.add_argument("--ingest-url", default="", help="Dashboard ingest endpoint (optional)")
    p.add_argument("--token-env", default="INFRA_INGEST_TOKEN", help="Env var holding the ingest token")
    p.add_argument("--collector-id", default="", help="Identifier for this collector")
    p.add_argument("--out", default="", help="Write the posture JSON to this file")
    args = p.parse_args(argv)

    posture = run(args.config)
    text = json.dumps(posture, indent=2)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
    else:
        print(text)

    if args.ingest_url:
        token = os.environ.get(args.token_env, "")
        ok = submit(posture, args.ingest_url, token, args.collector_id)
        print(f"[collector] ingest {'ok' if ok else 'skipped/failed'}", file=sys.stderr)

    return 1 if posture["totals"]["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
