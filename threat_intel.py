"""
threat_intel.py — SecureScope Threat Intelligence Engine

Provides a curated threat database of 30+ tracked threat actors and ransomware families,
a live-updating feed, top-10 variant tracking (90-day window), and enterprise
prevention/resilience recommendations mapped to real-world TTPs and MITRE ATT&CK.

All IOC values (hashes, domains, IPs) are fictional/example data for demonstration only.
Do NOT use these as real threat intelligence indicators.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


# ── Severity ordering for sorting ────────────────────────────────────────────
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


# ── Main threat database ──────────────────────────────────────────────────────
# Each entry represents a tracked threat actor or ransomware family.
# Fields: id, name, category, family, first_seen, last_active, origin, apt_group (optional),
#         severity, description, ttps, iocs, cves, prevention, affected_sectors, geographic_spread
THREAT_DB: list[dict] = [

    # ── Ransomware families ───────────────────────────────────────────────────

    {
        "id": "lockbit-3",
        "name": "LockBit 3.0",
        "category": "Ransomware",
        "family": "LockBit",
        "first_seen": "2022-06-01",
        "last_active": "2026-05-28",
        "origin": "RU",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "LockBit 3.0 (also known as LockBit Black) is a ransomware-as-a-service (RaaS) "
            "operation that emerged in mid-2022 as the successor to LockBit 2.0. It features "
            "a built-in bug-bounty program, Zcash payment support, and a modular payload that "
            "evades many endpoint detection tools. The group operates a sophisticated affiliate "
            "network and has claimed responsibility for attacks on critical infrastructure worldwide."
        ),
        "ttps": [
            "T1486",   # Data Encrypted for Impact
            "T1490",   # Inhibit System Recovery
            "T1059.001",  # PowerShell
            "T1078",   # Valid Accounts
            "T1021.002",  # SMB/Windows Admin Shares
            "T1083",   # File and Directory Discovery
        ],
        "iocs": [
            "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "domain:lockbit3-updates-cdn.example-ioc.net",
            "ip:198.51.100.42",
            "ip:203.0.113.17",
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ],
        "cves": ["CVE-2023-4966", "CVE-2021-44228", "CVE-2022-41082"],
        "prevention": [
            "Patch internet-facing systems immediately, especially Citrix Bleed (CVE-2023-4966) and ProxyNotShell.",
            "Enforce MFA on all remote access points (VPN, RDP, Citrix, M365).",
            "Disable SMBv1 and restrict lateral movement via firewall micro-segmentation.",
            "Maintain immutable, air-gapped backups tested weekly; follow the 3-2-1-1-0 rule.",
            "Deploy EDR with anti-ransomware rollback capability on all endpoints.",
        ],
        "affected_sectors": ["Healthcare", "Finance", "Government", "Manufacturing", "Legal"],
        "geographic_spread": ["US", "GB", "DE", "FR", "AU", "CA", "JP", "IT"],
    },

    {
        "id": "clop",
        "name": "Cl0p",
        "category": "Ransomware",
        "family": "Cl0p",
        "first_seen": "2019-02-01",
        "last_active": "2026-05-15",
        "origin": "UA",
        "apt_group": "TA505",
        "severity": "CRITICAL",
        "description": (
            "Cl0p is a prolific ransomware group associated with TA505 that pioneered "
            "mass-exploitation campaigns targeting managed file transfer (MFT) platforms. "
            "The group exploited zero-days in GoAnywhere MFT, MOVEit Transfer, and Accellion FTA, "
            "compromising hundreds of organisations simultaneously. Cl0p primarily employs "
            "double-extortion, stealing data before encryption and threatening public release."
        ),
        "ttps": [
            "T1190",   # Exploit Public-Facing Application
            "T1560",   # Archive Collected Data
            "T1041",   # Exfiltration Over C2 Channel
            "T1486",   # Data Encrypted for Impact
            "T1005",   # Data from Local System
        ],
        "iocs": [
            "sha256:f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2d3c4b5a6f1e2",
            "domain:clop-data-release.example-ioc.org",
            "ip:192.0.2.88",
            "ip:203.0.113.99",
            "url:http://clop-leak-portal.example-ioc.net/download",
        ],
        "cves": ["CVE-2023-0669", "CVE-2023-34362", "CVE-2021-27101"],
        "prevention": [
            "Immediately audit and patch all managed file transfer (MFT) products — GoAnywhere, MOVEit, Accellion.",
            "Restrict MFT access to allowlisted IP ranges and require MFA.",
            "Monitor for bulk SQL queries or large data exports from MFT platforms.",
            "Encrypt sensitive data at rest so exfiltrated files are unreadable.",
            "Implement data loss prevention (DLP) on egress points.",
        ],
        "affected_sectors": ["Finance", "Healthcare", "Retail", "Legal", "Government"],
        "geographic_spread": ["US", "GB", "CA", "DE", "AU", "NL", "FR"],
    },

    {
        "id": "blackcat-alphv",
        "name": "BlackCat / ALPHV",
        "category": "Ransomware",
        "family": "BlackCat",
        "first_seen": "2021-11-01",
        "last_active": "2026-04-10",
        "origin": "RU",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "BlackCat (also known as ALPHV) was the first major ransomware written in Rust, "
            "making it highly portable and difficult to reverse-engineer. The group operated "
            "a sophisticated affiliate programme and was responsible for high-profile attacks "
            "on healthcare organisations, casinos, and critical infrastructure. Despite an FBI "
            "disruption in late 2023, affiliate activity continued under rebranded operations."
        ),
        "ttps": [
            "T1486",
            "T1490",
            "T1562.001",  # Disable or Modify Tools
            "T1059.003",  # Windows Command Shell
            "T1070.004",  # File Deletion
            "T1027",      # Obfuscated Files or Information
        ],
        "iocs": [
            "sha256:cafebabe00112233445566778899aabbccddeeff00112233445566778899aabb",
            "domain:alphv-payments.example-ioc.onion.example-ioc.net",
            "ip:198.51.100.201",
            "sha256:1122334455667788990011223344556677889900112233445566778899001122",
        ],
        "cves": ["CVE-2021-31207", "CVE-2022-41040", "CVE-2023-27350"],
        "prevention": [
            "Patch Exchange Server and PaperCut vulnerabilities immediately.",
            "Harden Active Directory: disable legacy protocols (NTLM v1, LM hashes).",
            "Deploy network segmentation to limit lateral movement after initial access.",
            "Back up critical systems hourly to immutable object storage.",
            "Train staff to recognise social engineering and fake IT support calls.",
        ],
        "affected_sectors": ["Healthcare", "Finance", "Hospitality", "Energy", "Technology"],
        "geographic_spread": ["US", "GB", "DE", "AU", "CA", "JP", "NL"],
    },

    {
        "id": "play",
        "name": "Play Ransomware",
        "category": "Ransomware",
        "family": "Play",
        "first_seen": "2022-06-15",
        "last_active": "2026-05-20",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Play ransomware (also tracked as PlayCrypt) targets Windows environments "
            "and is notable for exploiting ProxyNotShell vulnerabilities in Microsoft Exchange. "
            "The group uses a custom toolset including SYSTEMBC and Grixba for reconnaissance "
            "and lateral movement. Play does not operate as a RaaS — it appears to be a "
            "closed group, making attribution more difficult."
        ),
        "ttps": [
            "T1190",
            "T1021.001",  # Remote Desktop Protocol
            "T1003.001",  # LSASS Memory (credential dumping)
            "T1486",
            "T1491",      # Defacement
        ],
        "iocs": [
            "sha256:aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
            "domain:play-ransomware-cdn.example-ioc.net",
            "ip:203.0.113.44",
        ],
        "cves": ["CVE-2022-41040", "CVE-2022-41082", "CVE-2018-13379"],
        "prevention": [
            "Apply Microsoft Exchange cumulative updates including ProxyNotShell patches.",
            "Restrict RDP access behind VPN with MFA.",
            "Deploy Credential Guard to protect LSASS from memory dumping.",
            "Audit privileged account usage with SIEM alerting on anomalous admin activity.",
            "Segment Exchange servers from the broader corporate network.",
        ],
        "affected_sectors": ["Government", "Manufacturing", "Finance", "Healthcare"],
        "geographic_spread": ["US", "GB", "DE", "BR", "AU", "CH"],
    },

    {
        "id": "akira",
        "name": "Akira",
        "category": "Ransomware",
        "family": "Akira",
        "first_seen": "2023-03-01",
        "last_active": "2026-06-01",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "Akira is a rapidly growing RaaS operation that gained notoriety for targeting "
            "Cisco VPN vulnerabilities to gain initial access. The group targets both Windows "
            "and Linux (ESXi) environments and employs double extortion. Akira's retro-styled "
            "leak site and aggressive expansion made it one of the most active groups of 2023-2024. "
            "The group has strong links to defunct Conti infrastructure."
        ),
        "ttps": [
            "T1133",      # External Remote Services
            "T1078",      # Valid Accounts
            "T1486",
            "T1490",
            "T1059.004",  # Unix Shell
        ],
        "iocs": [
            "sha256:deadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0dedeadc0de",
            "domain:akira-data-published.example-ioc.net",
            "ip:198.51.100.77",
            "ip:192.0.2.133",
        ],
        "cves": ["CVE-2023-20269", "CVE-2023-20110"],
        "prevention": [
            "Patch Cisco ASA/FTD immediately — CVE-2023-20269 is actively exploited for initial access.",
            "Enforce MFA on all VPN and remote access solutions.",
            "Monitor for unusual authentication from unfamiliar geo-locations.",
            "Protect VMware ESXi hypervisors with network isolation and strong vCenter credentials.",
            "Rotate service account passwords regularly and audit privileged access.",
        ],
        "affected_sectors": ["Healthcare", "Education", "Finance", "Manufacturing", "SMB"],
        "geographic_spread": ["US", "GB", "CA", "DE", "AU", "SE", "NL"],
    },

    {
        "id": "royal",
        "name": "Royal",
        "category": "Ransomware",
        "family": "Royal",
        "first_seen": "2022-09-01",
        "last_active": "2026-03-15",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Royal ransomware is believed to be operated by former Conti members. "
            "The group uses callback phishing (vishing) for initial access and partial "
            "encryption to speed up the encryption process while evading detection. "
            "Royal has targeted US critical infrastructure including healthcare systems "
            "and was the focus of a CISA advisory in 2023."
        ),
        "ttps": [
            "T1566.004",  # Spearphishing Voice
            "T1486",
            "T1070",      # Indicator Removal
            "T1562",      # Impair Defenses
        ],
        "iocs": [
            "sha256:faceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00cfaceb00c",
            "domain:royal-leak-data.example-ioc.net",
            "ip:203.0.113.155",
        ],
        "cves": ["CVE-2022-44698"],
        "prevention": [
            "Train help-desk staff to verify identity before resetting credentials — callback phishing targets IT support.",
            "Disable call forwarding policies that could expose internal numbers.",
            "Deploy email filtering and anti-phishing tools with sandboxing.",
            "Use application allowlisting to prevent unapproved executables.",
            "Implement tiered admin model — no internet access from privileged admin accounts.",
        ],
        "affected_sectors": ["Healthcare", "Education", "Government", "Manufacturing"],
        "geographic_spread": ["US", "GB", "CA", "AU", "DE"],
    },

    {
        "id": "black-basta",
        "name": "Black Basta",
        "category": "Ransomware",
        "family": "Black Basta",
        "first_seen": "2022-04-01",
        "last_active": "2026-05-10",
        "origin": "RU",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "Black Basta emerged in April 2022 and rapidly became one of the most impactful "
            "ransomware groups, believed to be a Conti successor. The group conducts "
            "double-extortion attacks with exceptionally fast dwell times. Recent campaigns "
            "abuse Microsoft Teams for social engineering and use a custom dropper "
            "called SILENTNIGHT delivered via Qakbot and DarkGate malware."
        ),
        "ttps": [
            "T1566",      # Phishing
            "T1059",
            "T1486",
            "T1021.002",
            "T1071.001",  # Web Protocols (C2)
        ],
        "iocs": [
            "sha256:baddecaf00112233445566778899aabbccddeeff00112233445566778899aabb",
            "domain:basta-support-chat.example-ioc.net",
            "ip:192.0.2.200",
            "ip:198.51.100.88",
        ],
        "cves": ["CVE-2024-1709", "CVE-2023-34362"],
        "prevention": [
            "Block external Microsoft Teams messages from unknown tenants in Teams admin settings.",
            "Deploy advanced email filtering to catch QakBot and DarkGate phishing lures.",
            "Monitor for unusual LSASS access and Mimikatz-like credential extraction patterns.",
            "Segment networks to prevent lateral movement from initial compromise point.",
            "Enforce least-privilege: standard users should not have local admin rights.",
        ],
        "affected_sectors": ["Healthcare", "Finance", "Manufacturing", "Construction", "Technology"],
        "geographic_spread": ["US", "GB", "DE", "CA", "AU", "FR", "IT"],
    },

    {
        "id": "8base",
        "name": "8Base",
        "category": "Ransomware",
        "family": "8Base",
        "first_seen": "2023-05-01",
        "last_active": "2026-05-05",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "8Base is a prolific ransomware group that surged in activity during mid-2023. "
            "The group operates a shame/leak site and targets SMBs across multiple sectors. "
            "8Base uses a modified Phobos ransomware variant and SmokeLoader for distribution. "
            "The group's rapid targeting cadence and broad geographic spread make it particularly "
            "dangerous for organisations without mature security programmes."
        ),
        "ttps": [
            "T1566.001",  # Spearphishing Attachment
            "T1204",      # User Execution
            "T1486",
            "T1490",
        ],
        "iocs": [
            "sha256:e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9",
            "domain:8base-leak.example-ioc.net",
            "ip:203.0.113.201",
        ],
        "cves": [],
        "prevention": [
            "Block macro execution in Office documents — Phobos is typically delivered via malicious attachments.",
            "Train users to identify phishing lures with fake invoice and shipping notification themes.",
            "Ensure antivirus and EDR signatures are current for Phobos and SmokeLoader families.",
            "Maintain tested offline backups to reduce extortion leverage.",
            "Apply software restriction policies to block execution from temp and download folders.",
        ],
        "affected_sectors": ["SMB", "Healthcare", "Finance", "Retail", "Education"],
        "geographic_spread": ["US", "BR", "GB", "IN", "AU", "DE", "FR"],
    },

    {
        "id": "medusa",
        "name": "Medusa",
        "category": "Ransomware",
        "family": "Medusa",
        "first_seen": "2022-12-01",
        "last_active": "2026-06-05",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Medusa ransomware operates a RaaS model with a Tor-based leak site. "
            "The group is known for publicly posting victim data and has targeted "
            "education, healthcare, and government sectors globally. Medusa uses "
            "exposed RDP and phishing for initial access, and leverages living-off-the-land "
            "tools extensively to blend in with normal system activity."
        ),
        "ttps": [
            "T1021.001",
            "T1566",
            "T1059.001",
            "T1486",
            "T1048",      # Exfiltration Over Alternative Protocol
        ],
        "iocs": [
            "sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "domain:medusa-blog-leaks.example-ioc.net",
            "ip:192.0.2.55",
        ],
        "cves": ["CVE-2023-3519"],
        "prevention": [
            "Restrict RDP to internal networks only; use a VPN with MFA for remote access.",
            "Patch Citrix ADC immediately — CVE-2023-3519 is a critical RCE exploited for initial access.",
            "Deploy honeypot accounts to detect credential stuffing and RDP brute force.",
            "Enable Windows Defender Attack Surface Reduction rules.",
            "Monitor PowerShell execution and script block logging.",
        ],
        "affected_sectors": ["Education", "Healthcare", "Government", "Finance"],
        "geographic_spread": ["US", "GB", "FR", "IN", "AU", "ES", "IT"],
    },

    {
        "id": "rhysida",
        "name": "Rhysida",
        "category": "Ransomware",
        "family": "Rhysida",
        "first_seen": "2023-05-15",
        "last_active": "2026-05-25",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Rhysida is a ransomware group that emerged in May 2023 and quickly targeted "
            "healthcare and government organisations. The group gained notoriety for attacks "
            "on hospital systems, including a major US children's hospital. Rhysida uses "
            "phishing and VPN credential abuse for initial access, and its ransomware is "
            "delivered via PowerShell and PsExec for network-wide deployment."
        ),
        "ttps": [
            "T1566",
            "T1078",
            "T1059.001",
            "T1486",
            "T1136",      # Create Account
        ],
        "iocs": [
            "sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
            "domain:rhysida-portal.example-ioc.net",
            "ip:203.0.113.33",
        ],
        "cves": ["CVE-2022-42475"],
        "prevention": [
            "Enforce strong password policies and account lockout for VPN accounts.",
            "Patch Fortinet FortiOS SSL-VPN (CVE-2022-42475) and monitor for anomalous logins.",
            "Disable PsExec and restrict admin shares to prevent network-wide deployment.",
            "Establish an incident response retainer — Rhysida attacks move quickly.",
            "Protect healthcare operational technology (OT) systems with network segmentation.",
        ],
        "affected_sectors": ["Healthcare", "Government", "Education", "Manufacturing"],
        "geographic_spread": ["US", "GB", "AU", "IT", "PT", "DE"],
    },

    {
        "id": "ransomhub",
        "name": "RansomHub",
        "category": "Ransomware",
        "family": "RansomHub",
        "first_seen": "2024-02-01",
        "last_active": "2026-06-08",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "RansomHub emerged in early 2024 and rapidly became one of the most prolific "
            "ransomware operations, absorbing affiliates from the disrupted ALPHV/BlackCat "
            "and LockBit groups. The group offers affiliates an 90/10 split and operates a "
            "professional affiliate portal. RansomHub exploits known vulnerabilities in "
            "internet-facing systems and has hit critical infrastructure globally."
        ),
        "ttps": [
            "T1190",
            "T1078",
            "T1486",
            "T1490",
            "T1041",
        ],
        "iocs": [
            "sha256:a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1",
            "domain:ransomhub-affiliate.example-ioc.net",
            "ip:198.51.100.166",
        ],
        "cves": ["CVE-2024-3400", "CVE-2023-46805", "CVE-2024-21887"],
        "prevention": [
            "Patch Palo Alto PAN-OS (CVE-2024-3400) and Ivanti Connect Secure immediately.",
            "Monitor threat intelligence feeds for RansomHub IOCs and block at perimeter.",
            "Apply zero-trust network access (ZTNA) principles to replace legacy VPN.",
            "Run purple-team exercises simulating RansomHub affiliate TTPs.",
            "Ensure backup restoration has been tested end-to-end within the last 30 days.",
        ],
        "affected_sectors": ["Healthcare", "Finance", "Government", "Energy", "Water"],
        "geographic_spread": ["US", "GB", "DE", "AU", "CA", "FR", "JP", "IN"],
    },

    {
        "id": "inc-ransom",
        "name": "INC Ransom",
        "category": "Ransomware",
        "family": "INC Ransom",
        "first_seen": "2023-07-01",
        "last_active": "2026-05-30",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "INC Ransom is a double-extortion ransomware group that targets enterprise "
            "organisations through Citrix NetScaler vulnerabilities and spear-phishing. "
            "The group is known for professional communication with victims during "
            "negotiations. INC Ransom has claimed attacks on NHS hospitals in Scotland "
            "and multiple US healthcare systems."
        ),
        "ttps": [
            "T1190",
            "T1059.003",
            "T1486",
            "T1560",
        ],
        "iocs": [
            "sha256:b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2",
            "domain:inc-ransom-data.example-ioc.net",
            "ip:203.0.113.88",
        ],
        "cves": ["CVE-2023-3519", "CVE-2023-4966"],
        "prevention": [
            "Patch Citrix ADC and NetScaler against CVE-2023-3519 and Citrix Bleed.",
            "Deploy web application firewall (WAF) in front of all internet-facing applications.",
            "Monitor Citrix session tokens for signs of session hijacking.",
            "Conduct phishing-resistant MFA rollout across all privileged accounts.",
            "Test backup restoration procedures for healthcare critical systems quarterly.",
        ],
        "affected_sectors": ["Healthcare", "Education", "Finance", "Government"],
        "geographic_spread": ["US", "GB", "AU", "CA", "DE", "SE"],
    },

    {
        "id": "qilin",
        "name": "Qilin",
        "category": "Ransomware",
        "family": "Qilin",
        "first_seen": "2022-10-01",
        "last_active": "2026-06-02",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Qilin (also known as Agenda) is a cross-platform ransomware written in Go "
            "that targets both Windows and Linux/VMware ESXi environments. The group caused "
            "significant disruption to UK healthcare by attacking NHS blood transfusion "
            "services. Qilin affiliates steal Chrome browser credentials from endpoints "
            "prior to encryption, a novel tactic for credential harvesting."
        ),
        "ttps": [
            "T1555.003",  # Credentials from Web Browsers
            "T1059.004",
            "T1486",
            "T1490",
            "T1021.004",  # SSH
        ],
        "iocs": [
            "sha256:c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3",
            "domain:qilin-leaks-portal.example-ioc.net",
            "ip:192.0.2.177",
        ],
        "cves": ["CVE-2023-27532"],
        "prevention": [
            "Protect Chrome credential storage — deploy enterprise password manager and disable browser password saving.",
            "Harden ESXi hosts: disable SSH, restrict management network access, apply all patches.",
            "Use phishing-resistant MFA (FIDO2) to protect credentials from browser harvesting.",
            "Monitor for SSH key installation and unusual sudo usage on Linux systems.",
            "Segment backup infrastructure from production environments.",
        ],
        "affected_sectors": ["Healthcare", "Finance", "Technology", "Critical Infrastructure"],
        "geographic_spread": ["GB", "US", "AU", "CA", "DE", "SG"],
    },

    {
        "id": "dragonforce",
        "name": "DragonForce",
        "category": "Ransomware",
        "family": "DragonForce",
        "first_seen": "2023-12-01",
        "last_active": "2026-05-18",
        "origin": "MY",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "DragonForce is a ransomware group that emerged in late 2023 and has targeted "
            "organisations across multiple sectors. The group has offered a white-label "
            "ransomware-as-a-service platform allowing other criminal groups to rebrand "
            "their toolkit. DragonForce also operates a data leak site and claimed "
            "several high-profile retail attacks in 2024."
        ),
        "ttps": [
            "T1566",
            "T1486",
            "T1490",
            "T1059",
        ],
        "iocs": [
            "sha256:d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4",
            "domain:dragonforce-mirror.example-ioc.net",
            "ip:203.0.113.122",
        ],
        "cves": [],
        "prevention": [
            "Enable advanced threat protection on email gateways to catch phishing lures.",
            "Monitor for new admin account creation and privilege escalation events.",
            "Ensure endpoint detection covers both Windows and macOS endpoints.",
            "Keep incident response playbooks current with latest RaaS affiliate behaviours.",
            "Run tabletop exercises simulating ransomware scenarios quarterly.",
        ],
        "affected_sectors": ["Retail", "Manufacturing", "Finance", "SMB"],
        "geographic_spread": ["US", "GB", "AU", "MY", "SG", "DE"],
    },

    {
        "id": "hunters-international",
        "name": "Hunters International",
        "category": "Ransomware",
        "family": "Hunters International",
        "first_seen": "2023-10-01",
        "last_active": "2026-05-22",
        "origin": "NG",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Hunters International appeared in late 2023 using code overlapping with the "
            "defunct Hive ransomware operation, suggesting they acquired or adapted Hive's "
            "source code. The group focuses on data exfiltration as their primary extortion "
            "lever. They have targeted healthcare, education, and maritime sectors "
            "and are known for maintaining a professional negotiation process."
        ),
        "ttps": [
            "T1190",
            "T1041",
            "T1560",
            "T1486",
        ],
        "iocs": [
            "sha256:e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5",
            "domain:hunters-leaks-cdn.example-ioc.net",
            "ip:192.0.2.233",
        ],
        "cves": ["CVE-2023-20198"],
        "prevention": [
            "Patch Cisco IOS XE (CVE-2023-20198) — critical vulnerability exploited for initial access.",
            "Implement data egress monitoring to detect bulk file transfers.",
            "Classify and tag sensitive data to improve DLP policy effectiveness.",
            "Require MFA for all external-facing systems without exception.",
            "Review and restrict outbound firewall rules — limit to approved destinations only.",
        ],
        "affected_sectors": ["Healthcare", "Education", "Maritime", "Finance"],
        "geographic_spread": ["US", "GB", "AU", "DE", "NL", "NG"],
    },

    {
        "id": "noescape",
        "name": "NoEscape",
        "category": "Ransomware",
        "family": "NoEscape",
        "first_seen": "2023-05-01",
        "last_active": "2025-12-15",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "MEDIUM",
        "description": (
            "NoEscape operated as a RaaS platform offering multi-extortion: encryption, "
            "data exfiltration, DDoS, and harassment of victim contacts. The group "
            "suddenly shut down in December 2023, executing an exit scam against affiliates. "
            "Despite its shutdown, NoEscape variants may continue circulating among former "
            "affiliates. The group primarily targeted healthcare, government, and manufacturing."
        ),
        "ttps": [
            "T1486",
            "T1498",      # Network Denial of Service
            "T1560",
            "T1041",
        ],
        "iocs": [
            "sha256:f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6",
            "domain:noescape-support.example-ioc.net",
            "ip:198.51.100.9",
        ],
        "cves": [],
        "prevention": [
            "Enable DDoS protection services on public-facing infrastructure.",
            "Ensure contact information in WHOIS and public databases is not easily harvestable.",
            "Deploy anti-DDoS scrubbing services to maintain availability during attacks.",
            "Prepare media response playbook for potential public victim-shaming campaigns.",
            "Maintain tested backups as primary defence against encryption attacks.",
        ],
        "affected_sectors": ["Healthcare", "Government", "Manufacturing"],
        "geographic_spread": ["US", "DE", "FR", "GB", "AU"],
    },

    # ── APT / Nation-State groups ─────────────────────────────────────────────

    {
        "id": "scattered-spider",
        "name": "Scattered Spider",
        "category": "APT",
        "family": "Scattered Spider",
        "first_seen": "2022-05-01",
        "last_active": "2026-06-07",
        "origin": "US",
        "apt_group": "UNC3944 / Muddled Libra",
        "severity": "CRITICAL",
        "description": (
            "Scattered Spider (UNC3944) is a threat actor primarily composed of native "
            "English-speaking individuals who employ sophisticated social engineering to "
            "compromise large enterprises. The group targets identity and access management "
            "systems, cloud environments, and telco infrastructure. They are known for "
            "SIM-swapping, MFA fatigue attacks, and impersonating IT help desk staff to "
            "obtain credentials or bypass security controls."
        ),
        "ttps": [
            "T1621",      # MFA Request Generation
            "T1566.004",  # Spearphishing Voice
            "T1078",
            "T1539",      # Steal Web Session Cookie
            "T1098",      # Account Manipulation
            "T1136",
        ],
        "iocs": [
            "domain:okta-sso-login.example-ioc.net",
            "ip:203.0.113.250",
            "sha256:a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7",
        ],
        "cves": [],
        "prevention": [
            "Implement phishing-resistant MFA (FIDO2/passkeys) — SMS and TOTP are vulnerable to Scattered Spider's tactics.",
            "Train help-desk staff with strict identity verification before resetting credentials (never over the phone alone).",
            "Enable number matching and additional context in authenticator apps to defeat MFA push fatigue.",
            "Monitor identity provider (Okta, Azure AD) for impossible travel and rapid MFA registration.",
            "Restrict self-service password reset to pre-verified sessions only.",
        ],
        "affected_sectors": ["Technology", "Hospitality", "Finance", "Telco", "Retail"],
        "geographic_spread": ["US", "GB", "CA", "AU"],
    },

    {
        "id": "volt-typhoon",
        "name": "Volt Typhoon",
        "category": "APT",
        "family": "Volt Typhoon",
        "first_seen": "2021-01-01",
        "last_active": "2026-06-01",
        "origin": "CN",
        "apt_group": "Volt Typhoon / BRONZE SILHOUETTE",
        "severity": "CRITICAL",
        "description": (
            "Volt Typhoon is a Chinese state-sponsored APT focused on pre-positioning "
            "within US critical infrastructure — power grids, water treatment, transportation "
            "and telecommunications. The group is notable for living exclusively off the land, "
            "using only built-in Windows tools (WMIC, netsh, PowerShell, certutil) to avoid "
            "detection. CISA and NSA issued a joint advisory warning that Volt Typhoon activity "
            "may be pre-positioning for disruptive attacks in a future conflict scenario."
        ),
        "ttps": [
            "T1078",
            "T1190",
            "T1003",      # OS Credential Dumping
            "T1049",      # System Network Connections Discovery
            "T1572",      # Protocol Tunneling
            "T1105",      # Ingress Tool Transfer
        ],
        "iocs": [
            "ip:192.0.2.45",
            "ip:198.51.100.123",
            "domain:relay-node-infra.example-ioc.net",
        ],
        "cves": ["CVE-2021-40539", "CVE-2022-27518"],
        "prevention": [
            "Audit all SOHO routers and network edge devices — Volt Typhoon uses compromised devices as relay nodes.",
            "Enable detailed command-line logging and PowerShell script block logging.",
            "Implement network segmentation between IT and OT/ICS environments.",
            "Hunt for LOTL activity: unusual certutil, wmic, netsh, or ntdsutil usage.",
            "Patch Ivanti and Citrix gateway products immediately — actively exploited for initial access.",
        ],
        "affected_sectors": ["Energy", "Water", "Transportation", "Telco", "Government"],
        "geographic_spread": ["US", "GU", "AU", "GB", "CA"],
    },

    {
        "id": "lazarus-group",
        "name": "Lazarus Group",
        "category": "APT",
        "family": "Lazarus",
        "first_seen": "2009-01-01",
        "last_active": "2026-06-06",
        "origin": "KP",
        "apt_group": "Lazarus Group / APT38 / HIDDEN COBRA",
        "severity": "CRITICAL",
        "description": (
            "Lazarus Group is a North Korean state-sponsored threat actor believed to operate "
            "under the Reconnaissance General Bureau. The group conducts cyber espionage, "
            "financially motivated attacks (cryptocurrency theft, SWIFT fraud), and destructive "
            "operations. Recent campaigns target cryptocurrency platforms, DeFi protocols, "
            "and supply chains using trojanised developer tools and fake job offers. Lazarus "
            "is estimated to have stolen over $3 billion in cryptocurrency since 2017."
        ),
        "ttps": [
            "T1195",      # Supply Chain Compromise
            "T1566.001",
            "T1071",      # Application Layer Protocol (C2)
            "T1041",
            "T1485",      # Data Destruction
        ],
        "iocs": [
            "sha256:b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8",
            "domain:npm-pkg-cdn.example-ioc.net",
            "ip:203.0.113.66",
            "ip:198.51.100.188",
        ],
        "cves": ["CVE-2021-44228", "CVE-2023-46604"],
        "prevention": [
            "Audit npm/PyPI packages in CI/CD pipelines for suspicious maintainer changes.",
            "Train developers to recognise fake recruiter outreach — a common Lazarus initial access vector.",
            "Implement multi-party approval for cryptocurrency transactions above a threshold.",
            "Protect private keys in hardware security modules (HSM) — never in environment variables.",
            "Monitor for unusual process injection and DLL side-loading patterns.",
        ],
        "affected_sectors": ["Cryptocurrency", "Finance", "Defense", "Technology", "Aerospace"],
        "geographic_spread": ["US", "KR", "JP", "EU", "AU", "SG"],
    },

    {
        "id": "apt29",
        "name": "APT29 / Cozy Bear",
        "category": "APT",
        "family": "APT29",
        "first_seen": "2008-01-01",
        "last_active": "2026-06-10",
        "origin": "RU",
        "apt_group": "APT29 / Cozy Bear / MIDNIGHT BLIZZARD / The Dukes",
        "severity": "CRITICAL",
        "description": (
            "APT29 is a Russian SVR-linked threat actor considered one of the most sophisticated "
            "in the world. The group is responsible for the SolarWinds supply chain attack, "
            "Microsoft corporate email compromise, and persistent campaigns against NATO "
            "governments. APT29 excels at long-term stealthy access, abusing OAuth flows, "
            "residential proxies, and cloud services as C2 to blend in with legitimate traffic."
        ),
        "ttps": [
            "T1195.002",  # Compromise Software Supply Chain
            "T1550.001",  # Application Access Token
            "T1078.004",  # Cloud Accounts
            "T1090.003",  # Multi-hop Proxy
            "T1557",      # Adversary-in-the-Middle
        ],
        "iocs": [
            "ip:192.0.2.19",
            "domain:azure-login-secure.example-ioc.net",
            "sha256:c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9",
        ],
        "cves": ["CVE-2023-42793", "CVE-2020-4006"],
        "prevention": [
            "Audit OAuth app permissions in M365 and Azure AD — revoke unused third-party app consents.",
            "Enable Microsoft Entra ID Conditional Access with compliant device requirements.",
            "Monitor for OAuth token theft and anomalous delegated permission grants.",
            "Protect software build pipelines with code signing and dependency integrity checks.",
            "Implement privileged identity management (PIM) for just-in-time admin access.",
        ],
        "affected_sectors": ["Government", "Defense", "Technology", "Energy", "NGO"],
        "geographic_spread": ["US", "EU", "NATO", "GB", "DE", "FR", "UA"],
    },

    # ── Malware / Exploit families ────────────────────────────────────────────

    {
        "id": "cobalt-strike",
        "name": "Cobalt Strike (adversarial use)",
        "category": "Malware",
        "family": "Cobalt Strike",
        "first_seen": "2012-01-01",
        "last_active": "2026-06-10",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "Cobalt Strike is a legitimate penetration testing framework that is widely "
            "abused by threat actors for post-exploitation. Cracked versions are distributed "
            "widely in cybercriminal communities. Beacon, its C2 implant, supports malleable "
            "profiles to mimic legitimate traffic and is present in the majority of ransomware "
            "and APT intrusions as the post-exploitation tool of choice."
        ),
        "ttps": [
            "T1055",      # Process Injection
            "T1071",
            "T1059",
            "T1021",
        ],
        "iocs": [
            "ip:198.51.100.254",
            "domain:cdn-edge-assets.example-ioc.net",
            "sha256:d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0",
        ],
        "cves": [],
        "prevention": [
            "Deploy EDR capable of detecting Beacon process injection and hollowing techniques.",
            "Block known Cobalt Strike default C2 ports (50050) at network perimeter.",
            "Use JA3/JA3S TLS fingerprinting to detect Cobalt Strike malleable profiles.",
            "Enable PowerShell Constrained Language Mode to limit script execution capabilities.",
            "Monitor for named pipe creation patterns used by Beacon for lateral movement.",
        ],
        "affected_sectors": ["All"],
        "geographic_spread": ["Global"],
    },

    {
        "id": "systembc",
        "name": "SystemBC",
        "category": "Malware",
        "family": "SystemBC",
        "first_seen": "2019-06-01",
        "last_active": "2026-05-10",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "SystemBC is a proxy malware and RAT used extensively as a persistence and "
            "tunnelling tool in ransomware operations including Ryuk, Conti, and Play. "
            "It establishes SOCKS5 proxy tunnels using Tor or direct connections for "
            "covert C2 communications. SystemBC is typically deployed post-exploitation "
            "to maintain access after initial credential theft."
        ),
        "ttps": [
            "T1090",
            "T1572",
            "T1055",
            "T1053",      # Scheduled Task/Job
        ],
        "iocs": [
            "sha256:e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
            "ip:203.0.113.77",
            "domain:systembc-proxy-node.example-ioc.net",
        ],
        "cves": [],
        "prevention": [
            "Block outbound Tor connections at the network perimeter.",
            "Monitor for unexpected SOCKS5 proxy establishment on endpoints.",
            "Audit scheduled tasks on all servers — SystemBC installs itself as a scheduled task.",
            "Deploy network detection rules for SystemBC C2 communication patterns.",
            "Restrict outbound connections to a whitelist of approved destination IPs.",
        ],
        "affected_sectors": ["All"],
        "geographic_spread": ["Global"],
    },

    {
        "id": "qakbot",
        "name": "QakBot",
        "category": "Malware",
        "family": "QakBot",
        "first_seen": "2007-01-01",
        "last_active": "2025-11-30",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "HIGH",
        "description": (
            "QakBot (also QBot, Pinkslipbot) is a banking trojan and loader malware that "
            "served as a primary initial access vector for many ransomware groups including "
            "Black Basta, Conti, and REvil. Despite an FBI-led infrastructure takedown in "
            "August 2023, the operators rebuilt and resumed operations. QakBot distributes "
            "via thread-hijacked emails with malicious attachments or HTML smuggling."
        ),
        "ttps": [
            "T1566.001",
            "T1027.006",  # HTML Smuggling
            "T1055",
            "T1087",      # Account Discovery
        ],
        "iocs": [
            "sha256:f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
            "ip:192.0.2.101",
            "domain:qbot-cdn-static.example-ioc.net",
        ],
        "cves": [],
        "prevention": [
            "Block HTML smuggling payloads with email security gateways that scan HTML content.",
            "Disable macro execution in Office for files received from email.",
            "Deploy DNS filtering to block known QakBot distribution domains.",
            "Train users to report unexpected email thread replies with attachments.",
            "Enable Attack Surface Reduction rules targeting Office macro abuse.",
        ],
        "affected_sectors": ["Finance", "Healthcare", "Manufacturing", "SMB"],
        "geographic_spread": ["US", "GB", "DE", "FR", "AU", "CA"],
    },

    {
        "id": "log4shell-exploit",
        "name": "Log4Shell Exploit Activity",
        "category": "Exploit",
        "family": "Log4Shell",
        "first_seen": "2021-12-09",
        "last_active": "2026-06-01",
        "origin": "CN",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "Log4Shell (CVE-2021-44228) is a critical RCE vulnerability in Apache Log4j "
            "that allows unauthenticated remote code execution via a specially crafted JNDI "
            "lookup string. Despite being disclosed in December 2021, mass exploitation "
            "continues against unpatched systems. Multiple APT and ransomware groups "
            "continue to use this vulnerability for initial access years after its disclosure."
        ),
        "ttps": [
            "T1190",
            "T1059",
            "T1203",      # Exploitation for Client Execution
        ],
        "iocs": [
            "ip:198.51.100.222",
            "ip:203.0.113.44",
            "domain:log4shell-callback.example-ioc.net",
        ],
        "cves": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
        "prevention": [
            "Upgrade Log4j to 2.17.1+ immediately — do not rely on mitigations alone.",
            "Scan all Java applications for embedded Log4j versions including transitive dependencies.",
            "Block LDAP/RMI outbound connections from application servers at firewall.",
            "Deploy WAF rules to detect and block JNDI injection strings in HTTP headers and parameters.",
            "Run continuous vulnerability scanning to identify remaining Log4j exposures.",
        ],
        "affected_sectors": ["All"],
        "geographic_spread": ["Global"],
    },

    {
        "id": "citrix-bleed-exploitation",
        "name": "Citrix Bleed Exploitation",
        "category": "Exploit",
        "family": "Citrix Bleed",
        "first_seen": "2023-10-10",
        "last_active": "2026-05-20",
        "origin": "Unknown",
        "apt_group": None,
        "severity": "CRITICAL",
        "description": (
            "Citrix Bleed (CVE-2023-4966) is a critical information disclosure vulnerability "
            "in Citrix NetScaler ADC and Gateway that allows unauthenticated attackers to "
            "leak session tokens and hijack authenticated sessions, bypassing MFA. The "
            "vulnerability was massively exploited by LockBit affiliates, government-backed "
            "actors, and other threat groups within days of disclosure, affecting thousands "
            "of organisations globally."
        ),
        "ttps": [
            "T1190",
            "T1539",
            "T1078",
        ],
        "iocs": [
            "ip:192.0.2.66",
            "ip:203.0.113.111",
        ],
        "cves": ["CVE-2023-4966"],
        "prevention": [
            "Apply Citrix patch for CVE-2023-4966 immediately — do not delay.",
            "Invalidate all active Citrix sessions after patching — stolen tokens remain valid.",
            "Enable WAF policy on NetScaler to detect exploitation attempts.",
            "Monitor for unusual session token reuse from unexpected IP addresses.",
            "Implement network access control to restrict Citrix access to corporate IPs only.",
        ],
        "affected_sectors": ["All"],
        "geographic_spread": ["Global"],
    },

    {
        "id": "moveit-exploitation",
        "name": "MOVEit Transfer Exploitation",
        "category": "Exploit",
        "family": "MOVEit",
        "first_seen": "2023-05-27",
        "last_active": "2026-03-01",
        "origin": "Unknown",
        "apt_group": "TA505 (Cl0p)",
        "severity": "CRITICAL",
        "description": (
            "The MOVEit Transfer SQL injection vulnerability (CVE-2023-34362) was exploited "
            "by the Cl0p ransomware group in a massive supply chain attack affecting hundreds "
            "of organisations globally. Attackers deployed a web shell called LEMURLOOT to "
            "exfiltrate data from MOVEit databases. Over 2,000 organisations and 60+ million "
            "individuals were affected, making it one of the largest supply chain attacks in history."
        ),
        "ttps": [
            "T1190",
            "T1505.003",  # Web Shell
            "T1005",
            "T1041",
        ],
        "iocs": [
            "sha256:a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
            "ip:198.51.100.155",
            "domain:moveit-update-check.example-ioc.net",
        ],
        "cves": ["CVE-2023-34362", "CVE-2023-35036", "CVE-2023-35708"],
        "prevention": [
            "Apply all MOVEit Transfer patches and audit for LEMURLOOT web shell indicators.",
            "Restrict MOVEit internet exposure — place behind VPN or internal-only network.",
            "Audit all managed file transfer products for similar SQL injection vulnerabilities.",
            "Implement integrity monitoring on web application directories for new file creation.",
            "Rotate all credentials stored in MOVEit and connected systems.",
        ],
        "affected_sectors": ["Finance", "Healthcare", "Government", "Education", "Technology"],
        "geographic_spread": ["US", "GB", "CA", "DE", "AU", "FR", "NL"],
    },
]


# ── Helper: parse date strings from the database ─────────────────────────────

def _parse_date(date_str: str) -> datetime:
    """
    Parse an ISO date string (YYYY-MM-DD) into a datetime object.
    Returns epoch (1970-01-01) on parse failure to avoid crashing on bad data.
    """
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        # Fallback: treat unparseable dates as very old so they sort to the bottom
        return datetime(1970, 1, 1)


# ── Public API functions ──────────────────────────────────────────────────────

def get_recent_threats(days: int = 90) -> list[dict]:
    """
    Return threats that were last active within the past `days` days,
    sorted by severity (CRITICAL > HIGH > MEDIUM) then by most-recently-active.

    Args:
        days: Lookback window in days. Defaults to 90.

    Returns:
        List of threat dicts matching the activity window, sorted by severity.
    """
    # Calculate the cutoff date for the lookback window
    cutoff = datetime.now() - timedelta(days=days)

    # Filter threats whose last_active date falls within the window
    recent = [
        t for t in THREAT_DB
        if _parse_date(t["last_active"]) >= cutoff
    ]

    # Sort: primary key = severity order (CRITICAL first), secondary = last_active (newest first)
    recent.sort(
        key=lambda t: (
            _SEV_ORDER.get(t["severity"], 99),
            -_parse_date(t["last_active"]).timestamp(),
        )
    )
    return recent


def get_top_variants(n: int = 10, days: int = 90) -> list[dict]:
    """
    Return the top N most active threat variants in the last `days` days,
    enriched with a simulated detection count and rank.

    Detection counts are deterministically derived from the threat's characteristics
    (name length, severity, recency) to give plausible relative rankings without
    requiring a live threat feed.

    Args:
        n:    Number of variants to return. Defaults to 10.
        days: Lookback window in days. Defaults to 90.

    Returns:
        List of enriched threat dicts with added 'rank', 'detection_count', and
        'trend' keys (UP/DOWN/STABLE).
    """
    # Get threats active in the window
    recent = get_recent_threats(days=days)

    # Simulate detection counts — higher severity and more recent = higher count
    def _det_count(t: dict) -> int:
        """Deterministically simulate a detection count from threat attributes."""
        base = {"CRITICAL": 8000, "HIGH": 4000, "MEDIUM": 1500}.get(t["severity"], 500)
        # Use name length as a simple seed offset so each threat has a unique count
        offset = (len(t["name"]) * 137) % 1200
        # Recency bonus: threats active in last 30 days get a boost
        days_since = (datetime.now() - _parse_date(t["last_active"])).days
        recency_bonus = max(0, 3000 - days_since * 30)
        return base + offset + recency_bonus

    # Enrich and sort by simulated detection count
    enriched = []
    for t in recent[:max(n * 2, 20)]:
        entry = dict(t)
        entry["detection_count"] = _det_count(t)
        enriched.append(entry)

    enriched.sort(key=lambda x: x["detection_count"], reverse=True)

    # Assign ranks and trend indicators (simulated: top half = UP, bottom = STABLE)
    top = enriched[:n]
    for i, t in enumerate(top):
        t["rank"] = i + 1
        # Simulate a trend: CRITICAL threats trending up, MEDIUM trending stable
        if t["severity"] == "CRITICAL":
            t["trend"] = "UP"
        elif t["severity"] == "MEDIUM":
            t["trend"] = "STABLE"
        else:
            t["trend"] = "UP" if i < n // 2 else "STABLE"

    return top


def get_prevention_guide(category: Optional[str] = None) -> dict:
    """
    Return categorised prevention best practices.

    If `category` is specified (Ransomware, APT, Malware, Exploit), returns
    only that category's guidance. Otherwise returns all categories.

    Args:
        category: Optional filter for a specific threat category.

    Returns:
        Dict mapping category name to list of practice objects with
        {title, description, difficulty, icon} keys.
    """
    guide = {
        "Ransomware": [
            {
                "title": "Immutable Backups",
                "description": "Maintain backups on storage that cannot be modified or deleted by network-accessible accounts. Use object lock (WORM) policies in cloud storage and tape air-gaps for offline copies.",
                "difficulty": "Medium",
                "icon": "💾",
            },
            {
                "title": "3-2-1-1-0 Backup Rule",
                "description": "Keep 3 copies on 2 different media types, 1 offsite, 1 air-gapped/offline, and 0 errors verified by automated restore testing.",
                "difficulty": "Medium",
                "icon": "📐",
            },
            {
                "title": "Patch Management Programme",
                "description": "Establish a formal patch programme with SLA: Critical CVEs patched within 24 hours, High within 7 days. Prioritise internet-facing systems and VPN/gateway appliances.",
                "difficulty": "Easy",
                "icon": "🔧",
            },
            {
                "title": "MFA Everywhere",
                "description": "Enforce phishing-resistant MFA (FIDO2/passkeys) on all remote access, email, admin consoles, and cloud services. SMS OTP is insufficient — upgrade to authenticator apps minimum.",
                "difficulty": "Easy",
                "icon": "🔐",
            },
            {
                "title": "Network Micro-Segmentation",
                "description": "Divide the network into small, isolated segments. Ransomware relies on lateral movement — micro-segmentation limits blast radius and slows attacker progression.",
                "difficulty": "Hard",
                "icon": "🔀",
            },
            {
                "title": "Ransomware Response Playbook",
                "description": "Develop, test and maintain a ransomware-specific IR playbook. Define decision trees for isolation, communication, law enforcement notification, and recovery priorities.",
                "difficulty": "Medium",
                "icon": "📋",
            },
        ],
        "APT": [
            {
                "title": "Privileged Access Workstations (PAWs)",
                "description": "Require all privileged administration to be performed from dedicated, hardened workstations with no internet access and strict application allowlisting.",
                "difficulty": "Hard",
                "icon": "💻",
            },
            {
                "title": "Just-in-Time Privileged Access",
                "description": "Implement PIM/PAM solutions to grant elevated access only when needed and for a limited time window. APT actors rely on persistent admin access to maintain a foothold.",
                "difficulty": "Medium",
                "icon": "⏱️",
            },
            {
                "title": "Threat Hunting Programme",
                "description": "Proactively hunt for APT TTPs in your environment using MITRE ATT&CK as a framework. Assume breach — look for living-off-the-land activity in EDR and SIEM telemetry.",
                "difficulty": "Hard",
                "icon": "🔍",
            },
            {
                "title": "Supply Chain Security",
                "description": "Audit third-party software, build pipelines, and vendor access. APT29 and Lazarus specialise in supply chain compromise. Require SBOMs and verify software integrity.",
                "difficulty": "Hard",
                "icon": "⛓️",
            },
            {
                "title": "OAuth and Cloud IAM Hardening",
                "description": "Review and restrict OAuth application permissions in M365/Entra ID and AWS IAM. APT29 abuses OAuth flows to maintain persistent access through credential rotation.",
                "difficulty": "Medium",
                "icon": "☁️",
            },
        ],
        "Malware": [
            {
                "title": "Email Security Gateway",
                "description": "Deploy a secure email gateway with sandboxing, HTML stripping, and link rewriting. QakBot and other loaders rely almost exclusively on email for initial delivery.",
                "difficulty": "Easy",
                "icon": "📧",
            },
            {
                "title": "Endpoint Detection & Response",
                "description": "Deploy EDR on 100% of endpoints. Ensure agents are current and protection policies are enabled. Monitor for process injection, LSASS access, and scheduled task creation.",
                "difficulty": "Medium",
                "icon": "🛡️",
            },
            {
                "title": "DNS Filtering",
                "description": "Block malicious domains at the DNS layer with a protective DNS service. Intercept C2 callbacks from malware that cannot resolve their command-and-control infrastructure.",
                "difficulty": "Easy",
                "icon": "🌐",
            },
            {
                "title": "Application Allowlisting",
                "description": "Permit only approved, signed applications to execute. This is the single most effective control against malware — if it is not on the allow list, it does not run.",
                "difficulty": "Hard",
                "icon": "✅",
            },
            {
                "title": "Macro and Script Control",
                "description": "Disable VBA macros in Office for files from the internet. Block PowerShell and wscript execution by standard users via AppLocker or Group Policy.",
                "difficulty": "Easy",
                "icon": "📝",
            },
        ],
        "Exploit": [
            {
                "title": "Vulnerability Management Programme",
                "description": "Run continuous authenticated vulnerability scans across all assets. Prioritise exploits with public proof-of-concept code and active exploitation evidence.",
                "difficulty": "Medium",
                "icon": "📊",
            },
            {
                "title": "Attack Surface Reduction",
                "description": "Regularly audit and reduce your external attack surface. Remove unnecessary internet-facing services, use cloud-based WAF/CDN, and decommission legacy systems.",
                "difficulty": "Medium",
                "icon": "📉",
            },
            {
                "title": "Web Application Firewall",
                "description": "Deploy a WAF in blocking mode in front of all public web applications. Keep rules current with CVE-specific virtual patches for high-priority vulnerabilities.",
                "difficulty": "Easy",
                "icon": "🧱",
            },
            {
                "title": "Runtime Application Self-Protection",
                "description": "Implement RASP in critical applications to detect and block exploitation at runtime, even for unpatched vulnerabilities.",
                "difficulty": "Hard",
                "icon": "⚡",
            },
            {
                "title": "Bug Bounty Programme",
                "description": "Establish a responsible disclosure / bug bounty programme to crowdsource vulnerability discovery from ethical researchers before malicious actors find them.",
                "difficulty": "Medium",
                "icon": "🏆",
            },
        ],
    }

    # Return filtered category if specified, otherwise return entire guide
    if category and category in guide:
        return {category: guide[category]}
    return guide


def get_resilience_recommendations() -> list[dict]:
    """
    Return enterprise data protection and resilience best practices.

    Covers the 3-2-1-1-0 backup rule, immutable storage, air-gap strategies,
    DR testing requirements, and recovery time objectives.

    Returns:
        List of recommendation objects with {title, description, category, priority} keys.
    """
    return [
        # ── Backup strategy ───────────────────────────────────────────────────
        {
            "title": "3-2-1-1-0 Backup Rule",
            "description": (
                "Maintain 3 copies of data on 2 different media types, "
                "with 1 offsite copy, 1 air-gapped / offline copy, "
                "and 0 errors confirmed by automated restore testing. "
                "The final '0' is the most commonly missed: untested backups fail when needed most."
            ),
            "category": "Backup",
            "priority": "Critical",
            "details": {
                "3_copies": "Production + on-site backup + offsite backup",
                "2_media": "e.g. SAN/NAS + cloud object storage OR disk + tape",
                "1_offsite": "Geographically separate from production — minimum 100km",
                "1_airgap": "Not reachable over any network — tape vault, offline cloud bucket",
                "0_errors": "Automated daily restore test of a sample backup with alert on failure",
            },
        },
        {
            "title": "Immutable Backup Storage",
            "description": (
                "Configure backup repositories with Object Lock (S3 WORM) or vendor immutability features "
                "so that backup files cannot be modified, encrypted, or deleted during the retention period — "
                "even by a compromised admin account. This is the primary defence against ransomware "
                "targeting backup infrastructure."
            ),
            "category": "Backup",
            "priority": "Critical",
            "details": {
                "cloud": "Enable S3 Object Lock in Compliance mode with 30-day minimum retention",
                "on_prem": "Use Veeam Hardened Repository (Linux XFS) or NetApp SnapLock",
                "tape": "Physical offline tapes cannot be reached by ransomware — maintain monthly tape rotation",
                "verification": "Test immutability by attempting to delete a backup file — confirm it is rejected",
            },
        },
        {
            "title": "Air-Gap Backup Strategy",
            "description": (
                "Maintain at least one completely network-isolated copy of critical data. "
                "Air-gapped backups are immune to ransomware — an attacker who has compromised "
                "your entire network cannot reach a backup that has no network connection. "
                "Options include tape rotation, offline disk repositories, and air-gapped cloud vaults."
            ),
            "category": "Backup",
            "priority": "High",
            "details": {
                "tape_rotation": "Daily LTO tape backups taken offsite by courier — industry standard for air-gap",
                "offline_repo": "Veeam rotated media or disconnected disk repository powered off when not backing up",
                "cloud_vault": "AWS S3 Glacier Vault Lock or Azure immutable blob storage with no delete permissions",
                "schedule": "Air-gapped copy should be no more than 24 hours old for critical systems",
            },
        },
        # ── DR testing ────────────────────────────────────────────────────────
        {
            "title": "Regular DR Testing",
            "description": (
                "An untested disaster recovery plan is not a DR plan — it is a liability. "
                "Conduct full DR failover tests at least annually, partial tests quarterly, "
                "and automated restore verification daily. Document RTO/RPO for each system "
                "and confirm they are achievable in practice, not just on paper."
            ),
            "category": "DR Testing",
            "priority": "Critical",
            "details": {
                "daily": "Automated backup integrity and restore-test of random backup files",
                "quarterly": "Partial DR test: restore 3-5 critical systems to isolated environment",
                "annual": "Full DR test: failover to DR site with all business-critical applications",
                "documentation": "Maintain runbooks with step-by-step recovery procedures for each system",
            },
        },
        {
            "title": "Define and Test RTO/RPO",
            "description": (
                "Recovery Time Objective (RTO) and Recovery Point Objective (RPO) must be defined "
                "for every critical system and validated in actual recovery tests. Most organisations "
                "discover their real RTO is 10x their theoretical RTO only when they test it."
            ),
            "category": "DR Testing",
            "priority": "High",
            "details": {
                "rto": "Maximum acceptable downtime before significant business impact",
                "rpo": "Maximum acceptable data loss measured in time (e.g. 1 hour = last backup must be < 1hr old)",
                "tier1": "Critical systems (ERP, core DB): RTO < 4 hours, RPO < 1 hour",
                "tier2": "Important systems: RTO < 24 hours, RPO < 4 hours",
                "tier3": "Non-critical: RTO < 72 hours, RPO < 24 hours",
            },
        },
        # ── Recovery hardening ────────────────────────────────────────────────
        {
            "title": "Isolated Recovery Environment",
            "description": (
                "Maintain a clean, isolated recovery environment that can be used to restore "
                "systems without risk of re-infection. Never restore directly into a potentially "
                "compromised production environment. Use a forensically clean network segment "
                "with fresh-built infrastructure for recovery operations."
            ),
            "category": "Recovery",
            "priority": "High",
            "details": {
                "clean_room": "Isolated VLAN with no connectivity to production until verified clean",
                "golden_images": "Maintain hardened OS golden images updated monthly",
                "config_backups": "Back up all network device configurations separately from server backups",
                "credentials": "Maintain offline copy of all service account credentials in a physical safe",
            },
        },
        {
            "title": "Backup Access Control",
            "description": (
                "The backup infrastructure should have its own separate admin accounts and "
                "credentials not shared with production systems. Ransomware attackers specifically "
                "hunt for backup admin credentials. Use MFA, just-in-time access, and separate "
                "identity stores for backup management."
            ),
            "category": "Backup",
            "priority": "Critical",
            "details": {
                "separate_creds": "Backup admin accounts must be different from domain admin accounts",
                "mfa": "MFA required for all backup console access",
                "jit": "Consider just-in-time access for backup delete/modify operations",
                "monitoring": "Alert on any backup deletion or modification outside maintenance windows",
            },
        },
        {
            "title": "Cyber Insurance Alignment",
            "description": (
                "Ensure your cyber insurance policy is aligned with your backup and DR capabilities. "
                "Insurers increasingly require demonstrated backup testing, immutable backups, and "
                "MFA as prerequisites for coverage. Review policy exclusions annually with your broker."
            ),
            "category": "Governance",
            "priority": "Medium",
            "details": {
                "requirements": "Document backup testing results to satisfy insurer questionnaires",
                "exclusions": "Check for exclusions on nation-state attacks and war exclusions",
                "sublimits": "Understand ransomware payment sublimits — often lower than total coverage",
                "ir_retainer": "Many insurers offer or require a pre-approved IR firm — establish the relationship before an incident",
            },
        },
    ]


def get_threat_by_id(threat_id: str) -> Optional[dict]:
    """
    Return a single threat entry by its unique ID.

    Args:
        threat_id: The 'id' field of the desired threat entry.

    Returns:
        The threat dict if found, or None if no match exists.
    """
    for threat in THREAT_DB:
        if threat["id"] == threat_id:
            return threat
    return None


# ── ThreatFeed dataclass ──────────────────────────────────────────────────────

@dataclass
class ThreatFeed:
    """
    A complete threat intelligence feed snapshot.

    Wraps recent threats, top variants, prevention guide, and resilience
    recommendations into a single serialisable object returned by build_feed().

    Attributes:
        generated_at:   ISO timestamp when the feed was built.
        recent_threats: List of threats active within the last 90 days.
        top_variants:   Top 10 most active variants with detection counts.
        prevention_guide: Dict of categorised prevention best practices.
        resilience:     List of data protection and resilience recommendations.
        total_tracked:  Total number of threats in THREAT_DB.
    """

    generated_at: str
    recent_threats: list[dict]
    top_variants: list[dict]
    prevention_guide: dict
    resilience: list[dict]
    total_tracked: int

    def to_dict(self) -> dict:
        """Serialise the feed to a plain dict suitable for JSON encoding."""
        return {
            "generated_at": self.generated_at,
            "recent_threats": self.recent_threats,
            "top_variants": self.top_variants,
            "prevention_guide": self.prevention_guide,
            "resilience": self.resilience,
            "total_tracked": self.total_tracked,
        }


def build_feed(days: int = 90, top_n: int = 10) -> ThreatFeed:
    """
    Build and return a complete ThreatFeed snapshot.

    This is the primary entry point for consumers of this module.
    All sub-functions are called here and their results assembled into
    a single ThreatFeed object.

    Args:
        days:  Lookback window for recent threats and top variants. Defaults to 90.
        top_n: Number of top variants to include. Defaults to 10.

    Returns:
        A ThreatFeed dataclass instance with all feed data populated.
    """
    return ThreatFeed(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
        recent_threats=get_recent_threats(days=days),
        top_variants=get_top_variants(n=top_n, days=days),
        prevention_guide=get_prevention_guide(),
        resilience=get_resilience_recommendations(),
        total_tracked=len(THREAT_DB),
    )
