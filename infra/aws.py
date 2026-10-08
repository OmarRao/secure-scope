# Copyright (c) 2026 Omar Rao
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Available under the GNU Affero General Public License v3.0, or under a
# separate commercial license. See LICENSE and COMMERCIAL-LICENSE.md.

"""
AWS cloud posture (CSPM) assessor — wraps the existing read-only cspm.py checks
into the infrastructure assessor framework.

Pure over a snapshot of the form {"cspm": <result from cspm.scan_aws()>}, so it
is fixture-tested without AWS. The live boto3 collection lives in
infra.connectors.aws and stays dormant without boto3 + credentials.
"""

from .base import Assessor, Finding, register

# Map each cspm check to a control id, title, severity, framework + remediation.
_CONTROLS = {
    "S3 public access": {
        "control": "CIS-AWS-2.1.5", "title": "S3 bucket public access", "sev": "HIGH",
        "nist": "AC-3", "fix": "Enable S3 Block Public Access and remove public ACL grants."},
    "IAM user without MFA": {
        "control": "CIS-AWS-1.10", "title": "IAM user without MFA", "sev": "MEDIUM",
        "nist": "IA-2", "fix": "Register an MFA device for the user, or enforce MFA via policy."},
    "Security group open to the world": {
        "control": "CIS-AWS-5.2", "title": "Security group open to 0.0.0.0/0", "sev": "HIGH",
        "nist": "SC-7", "fix": "Restrict ingress to specific source CIDRs; avoid 0.0.0.0/0."},
}
# Human "no issues" labels for PASS synthesis when a category is clean.
_PASS_LABEL = {
    "S3 public access": "No public S3 buckets",
    "IAM user without MFA": "All IAM users have MFA",
    "Security group open to the world": "No security groups open to the world",
}


class AWSAccountAssessor(Assessor):
    id = "aws.cspm"
    domain = "cloud"
    kinds = ("aws_account",)

    def assess(self, snapshot: dict) -> list:
        snap = snapshot or {}
        host = snap.get("host", "aws-account")
        cspm = snap.get("cspm") or {}

        # Not configured / no creds → a single UNKNOWN finding, never a crash.
        if not cspm.get("available"):
            return [Finding(
                assessor=self.id, control="CIS-AWS", title="AWS posture not assessed",
                severity="INFO", status="UNKNOWN", resource=host,
                detail=cspm.get("error") or "AWS credentials/boto3 not configured.",
                remediation="Provide read-only AWS credentials (SecurityAudit) to the collector.")]

        out = []
        seen = set()
        for f in cspm.get("findings", []) or []:
            check = f.get("check", "")
            meta = _CONTROLS.get(check)
            seen.add(check)
            if not meta:
                continue
            out.append(Finding(
                assessor=self.id, control=meta["control"], title=meta["title"],
                severity=f.get("severity", meta["sev"]), status="FAIL",
                resource=f.get("resource", host), detail=f.get("detail", ""),
                remediation=meta["fix"], frameworks={"CIS": meta["control"], "NIST": meta["nist"]}))

        # Synthesize a PASS for every category that was checked and came back clean.
        for check, meta in _CONTROLS.items():
            if check not in seen:
                out.append(Finding(
                    assessor=self.id, control=meta["control"], title=_PASS_LABEL[check],
                    severity=meta["sev"], status="PASS", resource=host,
                    detail=f"No findings for: {check}.",
                    frameworks={"CIS": meta["control"], "NIST": meta["nist"]}))
        return out


register(AWSAccountAssessor())
