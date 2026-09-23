# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Infrastructure assessment CLI (Phase 1) — validate assessors without live infra.

    # Assess from a normalized snapshot file (a list of snapshots, or one):
    python -m infra.cli --snapshot host.json

    # Live read-only vSphere collection then assess (needs pyVmomi + creds):
    python -m infra.cli --vsphere HOST --user U --password-env VS_PW

Prints a JSON posture object (see infra.report.build_infra_posture). Read-only.
"""

import argparse
import json
import os
import sys

from .report import assess_snapshots, build_infra_posture


def _load_snapshots(path: str) -> list:
    data = json.loads(open(path, encoding="utf-8").read())
    return data if isinstance(data, list) else [data]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="SecureScope infrastructure assessment")
    p.add_argument("--snapshot", help="Path to a normalized snapshot JSON (list or object)")
    p.add_argument("--vsphere", help="vSphere/ESXi host to collect read-only (needs pyVmomi)")
    p.add_argument("--user", default="", help="vSphere username (read-only role)")
    p.add_argument("--password-env", default="", help="Env var holding the vSphere password")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification (lab only)")
    args = p.parse_args(argv)

    snapshots = []
    if args.snapshot:
        snapshots = _load_snapshots(args.snapshot)
    elif args.vsphere:
        from .connectors import vmware as vmw
        pw = os.environ.get(args.password_env, "")
        try:
            snapshots = [vmw.collect_snapshot(args.vsphere, args.user, pw, insecure=args.insecure)]
        except Exception as exc:
            print(f"[infra] collection failed: {exc}", file=sys.stderr)
            return 2
    else:
        p.error("provide --snapshot or --vsphere")

    posture = build_infra_posture(assess_snapshots(snapshots))
    print(json.dumps(posture, indent=2))
    # Non-zero exit if any FAIL — handy for CI gating.
    return 1 if posture["totals"]["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
