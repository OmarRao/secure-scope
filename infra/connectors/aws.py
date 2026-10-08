# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Read-only AWS connector — produces a normalized account snapshot.

DORMANT by default: delegates to the existing cspm.py (read-only boto3). With no
boto3 or no credentials it returns a snapshot whose cspm result is
`available: False`, which the assessor renders as an UNKNOWN posture — never a
crash. Credentials are resolved by the in-network collector and never sent to
the hosted dashboard.
"""


def available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except Exception:
        return False


def collect_snapshot(region: str = "us-east-1", profile: str = "") -> dict:
    """Return {kind, host, cspm} using cspm.scan_aws (strictly read-only)."""
    import cspm
    result = cspm.scan_aws(region=region, profile=profile)
    return {"kind": "aws_account", "host": f"aws:{region}", "cspm": result}
