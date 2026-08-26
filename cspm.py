# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
Cloud Security Posture Management (CSPM) — read-only AWS checks.

A lightweight, opt-in posture scan for an AWS account: public S3 buckets, IAM
users without MFA, and security groups open to the world. It is strictly
read-only (describe/list/get calls) and never mutates cloud state.

Requires the maintainer's action: install boto3 and provide credentials (an
access key with read-only/SecurityAudit permissions, or an assumed role). With
no boto3 or no credentials it degrades gracefully to an explanatory result — it
never raises into the caller.

The pure classification/formatting is unit tested; the boto3 calls are thin.
"""

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _finding(check: str, resource: str, severity: str, detail: str) -> dict:
    return {"check": check, "resource": resource,
            "severity": severity.upper(), "detail": detail}


def boto3_available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except Exception:
        return False


def _check_s3_public(session) -> list:
    findings = []
    s3 = session.client("s3")
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                uri = (grant.get("Grantee", {}) or {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    findings.append(_finding(
                        "S3 public access", f"s3://{name}", "HIGH",
                        "Bucket ACL grants access to all/authenticated users."))
                    break
        except Exception:
            continue
    return findings


def _check_iam_mfa(session) -> list:
    findings = []
    iam = session.client("iam")
    try:
        for u in iam.list_users().get("Users", []):
            uname = u["UserName"]
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                findings.append(_finding(
                    "IAM user without MFA", uname, "MEDIUM",
                    "Console/API user has no MFA device registered."))
    except Exception:
        pass
    return findings


def _check_open_security_groups(session) -> list:
    findings = []
    try:
        ec2 = session.client("ec2")
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            for perm in sg.get("IpPermissions", []):
                for rng in perm.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        port = perm.get("FromPort", "all")
                        findings.append(_finding(
                            "Security group open to the world",
                            sg.get("GroupId", "?"), "HIGH",
                            f"Ingress from 0.0.0.0/0 on port {port}."))
    except Exception:
        pass
    return findings


def scan_aws(region: str = "us-east-1", profile: str = "") -> dict:
    """Run read-only AWS posture checks. Never raises; returns a result dict.

    {available, error, findings: [...], counts: {by severity}}
    """
    if not boto3_available():
        return {"available": False,
                "error": "boto3 not installed — `pip install boto3` and provide AWS credentials.",
                "findings": [], "counts": {}}
    try:
        import boto3
        session = (boto3.Session(profile_name=profile, region_name=region)
                   if profile else boto3.Session(region_name=region))
        # A cheap call to confirm credentials resolve before doing real work.
        session.client("sts").get_caller_identity()
    except Exception as e:
        return {"available": False,
                "error": f"AWS credentials unavailable: {type(e).__name__}",
                "findings": [], "counts": {}}

    findings = []
    for check in (_check_s3_public, _check_iam_mfa, _check_open_security_groups):
        try:
            findings.extend(check(session))
        except Exception:
            continue
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)
    return {"available": True, "error": "",
            "findings": findings, "counts": summarize(findings)}


def summarize(findings: list) -> dict:
    """Count findings by severity (pure)."""
    counts = {}
    for f in findings or []:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
