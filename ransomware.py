"""
Ransomware Intelligence Engine
================================
Analyses static-analysis findings and source code for patterns that match known
ransomware families, APT groups and active exploit variants.

Returns a RansomwareReport dataclass consumed by the report template.
"""

from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ── Ransomware Family Intelligence Database ────────────────────────────────────

RANSOMWARE_DB: list[dict] = [
    {
        "id": "LOCKBIT",
        "name": "LockBit 3.0",
        "alias": ["LockBit Black", "LockBit 2.0"],
        "family": "LockBit",
        "type": "Ransomware-as-a-Service (RaaS)",
        "apt_group": "LockBit Cartel",
        "origin": "Russia / Eastern Europe",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2019",
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "encryption": ["AES-256-CBC", "RSA-2048"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2023-4966", "CVE-2021-44228", "CVE-2023-0669"],
        "mitre_techniques": ["T1486", "T1083", "T1059", "T1490", "T1027", "T1562"],
        "sectors_targeted": ["Healthcare", "Finance", "Government", "Manufacturing", "Legal"],
        "known_victims": ["Boeing", "ICBC", "Royal Mail", "CDW"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 847},
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 213},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 189},
            {"country": "Canada", "coords": [56.13, -106.34], "incidents": 156},
            {"country": "France", "coords": [46.22, 2.21], "incidents": 134},
            {"country": "Australia", "coords": [-25.27, 133.77], "incidents": 98},
            {"country": "Italy", "coords": [41.87, 12.56], "incidents": 87},
            {"country": "Brazil", "coords": [-14.23, -51.92], "incidents": 76},
            {"country": "Spain", "coords": [40.46, -3.74], "incidents": 65},
            {"country": "Japan", "coords": [36.20, 138.25], "incidents": 54},
        ],
        "behavior_patterns": [
            "file_encryption", "file_enumeration", "shadow_copy_deletion",
            "process_termination", "persistence", "lateral_movement",
            "credential_theft", "data_exfiltration"
        ],
        "ransom_note_keywords": ["lockbit", "restore-my-files", ".lockbit"],
        "description": "Most prolific ransomware group globally. Uses triple extortion — encryption, data leak, DDoS. Known for fastest encryption speed via multi-threading.",
    },
    {
        "id": "CLOP",
        "name": "Cl0p",
        "alias": ["TA505", "FIN11", "Lace Tempest"],
        "family": "Cl0p",
        "type": "Big Game Hunting / RaaS",
        "apt_group": "TA505 / FIN11",
        "origin": "Russia / Ukraine",
        "origin_flag": "🇷🇺",
        "origin_coords": [50.45, 30.52],
        "active_since": "2019",
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "encryption": ["RC4", "AES-256"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2023-34362", "CVE-2023-0669", "CVE-2022-35914"],
        "mitre_techniques": ["T1486", "T1059", "T1083", "T1190", "T1566"],
        "sectors_targeted": ["Finance", "Healthcare", "Education", "Government"],
        "known_victims": ["MOVEit users (2000+ orgs)", "GoAnywhere users", "Accellion users"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 612},
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 198},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 145},
            {"country": "Canada", "coords": [56.13, -106.34], "incidents": 134},
            {"country": "Netherlands", "coords": [52.13, 5.29], "incidents": 89},
        ],
        "behavior_patterns": [
            "file_encryption", "file_enumeration", "data_exfiltration",
            "supply_chain_attack", "ssrf", "sql_injection"
        ],
        "ransom_note_keywords": ["clop", "clop^_-", "ClopReadMe"],
        "description": "Pioneered mass-exploitation of file-transfer platforms. MOVEit attack compromised 2000+ organisations globally. Focuses on data theft over encryption.",
    },
    {
        "id": "BLACKCAT",
        "name": "BlackCat / ALPHV",
        "alias": ["ALPHV", "Noberus"],
        "family": "BlackCat",
        "type": "Ransomware-as-a-Service (RaaS)",
        "apt_group": "BlackCat Cartel",
        "origin": "Russia",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2021",
        "status": "DISRUPTED",
        "severity": "CRITICAL",
        "encryption": ["ChaCha20", "AES-128"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2021-31207", "CVE-2022-24521", "CVE-2019-0708"],
        "mitre_techniques": ["T1486", "T1083", "T1059.001", "T1082", "T1027", "T1490"],
        "sectors_targeted": ["Healthcare", "Finance", "Energy", "Government"],
        "known_victims": ["Change Healthcare (UnitedHealth)", "MGM Resorts", "Caesars"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 423},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 167},
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 145},
            {"country": "Australia", "coords": [-25.27, 133.77], "incidents": 112},
            {"country": "India", "coords": [20.59, 78.96], "incidents": 89},
        ],
        "behavior_patterns": [
            "file_encryption", "file_enumeration", "shadow_copy_deletion",
            "credential_theft", "lateral_movement", "persistence", "data_exfiltration"
        ],
        "ransom_note_keywords": ["ALPHV", "blackcat", "RECOVER-FILES"],
        "description": "First major ransomware written in Rust. Cross-platform (Windows/Linux/VMware). Change Healthcare attack disrupted US pharmacy networks for weeks.",
    },
    {
        "id": "RYUK",
        "name": "Ryuk",
        "alias": ["Wizard Spider", "UNC1878"],
        "family": "Ryuk / Hermes",
        "type": "Human-Operated Ransomware",
        "apt_group": "Wizard Spider",
        "origin": "Russia / CIS",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2018",
        "status": "EVOLVED",
        "severity": "HIGH",
        "encryption": ["RSA-2048", "AES-256"],
        "double_extortion": False,
        "lateral_movement": True,
        "cves": ["CVE-2020-1472", "CVE-2019-0708", "CVE-2018-8453"],
        "mitre_techniques": ["T1486", "T1059", "T1490", "T1548", "T1078"],
        "sectors_targeted": ["Healthcare", "Government", "Logistics"],
        "known_victims": ["Universal Health Services", "Tribune Publishing", "US Coast Guard"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 534},
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 98},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 76},
            {"country": "Spain", "coords": [40.46, -3.74], "incidents": 67},
        ],
        "behavior_patterns": [
            "file_encryption", "shadow_copy_deletion", "process_termination",
            "persistence", "network_propagation", "hardcoded_credentials"
        ],
        "ransom_note_keywords": ["ryuk", "RyukReadMe", "UNIQUE_ID_DO_NOT_REMOVE"],
        "description": "Targets high-value organisations. Deployed after TrickBot/BazarLoader initial access. Known for disabling backups before encryption.",
    },
    {
        "id": "CONTI",
        "name": "Conti",
        "alias": ["Wizard Spider", "Gold Blackwood"],
        "family": "Conti",
        "type": "Human-Operated RaaS",
        "apt_group": "Wizard Spider / Conti Cartel",
        "origin": "Russia",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2020",
        "status": "DEFUNCT",
        "severity": "HIGH",
        "encryption": ["AES-256", "ChaCha"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2021-34527", "CVE-2021-26855", "CVE-2020-1472"],
        "mitre_techniques": ["T1486", "T1059", "T1078", "T1021", "T1570"],
        "sectors_targeted": ["Healthcare", "Government", "Critical Infrastructure"],
        "known_victims": ["Costa Rica Government", "Ireland HSE", "Shutterfly"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 427},
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 143},
            {"country": "Costa Rica", "coords": [9.74, -83.75], "incidents": 27},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 89},
            {"country": "Ireland", "coords": [53.41, -8.24], "incidents": 34},
        ],
        "behavior_patterns": [
            "file_encryption", "file_enumeration", "shadow_copy_deletion",
            "credential_theft", "lateral_movement", "data_exfiltration",
            "process_termination", "persistence"
        ],
        "ransom_note_keywords": ["conti", "CONTI_LOG", "readme.txt"],
        "description": "Responsible for crippling Ireland's national healthcare system (HSE). Leaked its own source code in 2022. Spawned multiple successor groups.",
    },
    {
        "id": "WANNACRY",
        "name": "WannaCry",
        "alias": ["WanaCrypt0r", "WCRY"],
        "family": "WannaCry",
        "type": "Worm-Ransomware",
        "apt_group": "Lazarus Group (North Korea)",
        "origin": "North Korea",
        "origin_flag": "🇰🇵",
        "origin_coords": [40.34, 127.51],
        "active_since": "2017",
        "status": "LEGACY",
        "severity": "HIGH",
        "encryption": ["AES-128-CBC", "RSA-2048"],
        "double_extortion": False,
        "lateral_movement": True,
        "cves": ["CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0143"],
        "mitre_techniques": ["T1486", "T1210", "T1059", "T1490", "T1485"],
        "sectors_targeted": ["Healthcare", "Telecom", "Government", "Manufacturing"],
        "known_victims": ["NHS UK", "FedEx", "Telefonica", "Renault", "Russian Railways"],
        "impact_regions": [
            {"country": "United Kingdom", "coords": [55.37, -3.43], "incidents": 47},
            {"country": "Russia", "coords": [61.52, 105.31], "incidents": 1000},
            {"country": "Ukraine", "coords": [48.37, 31.16], "incidents": 200},
            {"country": "China", "coords": [35.86, 104.19], "incidents": 300},
            {"country": "India", "coords": [20.59, 78.96], "incidents": 150},
            {"country": "Spain", "coords": [40.46, -3.74], "incidents": 89},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 76},
        ],
        "behavior_patterns": [
            "file_encryption", "network_propagation", "shadow_copy_deletion",
            "smb_exploitation", "hardcoded_credentials"
        ],
        "ransom_note_keywords": ["WannaDecryptor", "@Please_Read_Me@", ".WNCRY"],
        "description": "Exploited EternalBlue (NSA exploit). Infected 200,000+ systems in 150 countries in 24 hours. Attributed to North Korean Lazarus Group. Kill-switch domain stopped spread.",
    },
    {
        "id": "REVIL",
        "name": "REvil / Sodinokibi",
        "alias": ["Sodinokibi", "Gold Southfield"],
        "family": "REvil",
        "type": "Ransomware-as-a-Service (RaaS)",
        "apt_group": "Gold Southfield",
        "origin": "Russia",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2019",
        "status": "DISRUPTED",
        "severity": "HIGH",
        "encryption": ["Salsa20", "Curve25519"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2021-30116", "CVE-2020-1472", "CVE-2019-2725"],
        "mitre_techniques": ["T1486", "T1059", "T1078", "T1190", "T1566"],
        "sectors_targeted": ["MSP", "Agriculture", "Technology", "Finance"],
        "known_victims": ["Kaseya VSA (1500 MSPs)", "JBS Foods", "Quanta Computer"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 312},
            {"country": "Brazil", "coords": [-14.23, -51.92], "incidents": 87},
            {"country": "Germany", "coords": [51.16, 10.45], "incidents": 65},
            {"country": "Australia", "coords": [-25.27, 133.77], "incidents": 54},
        ],
        "behavior_patterns": [
            "file_encryption", "file_enumeration", "data_exfiltration",
            "supply_chain_attack", "credential_theft", "persistence"
        ],
        "ransom_note_keywords": ["revil", "sodinokibi", "[random]-readme.txt"],
        "description": "Sophisticated RaaS that pioneered auctioning stolen data. Kaseya attack triggered $70M ransom demand — largest at the time. Dismantled by RU-FSB in Jan 2022.",
    },
    {
        "id": "DARKSIDE",
        "name": "DarkSide",
        "alias": ["Carbon Spider", "Gold Dupont"],
        "family": "DarkSide",
        "type": "Ransomware-as-a-Service (RaaS)",
        "apt_group": "Carbon Spider",
        "origin": "Russia / Eastern Europe",
        "origin_flag": "🇷🇺",
        "origin_coords": [55.75, 37.62],
        "active_since": "2020",
        "status": "REBRANDED",
        "severity": "CRITICAL",
        "encryption": ["ChaCha20", "RSA-1024"],
        "double_extortion": True,
        "lateral_movement": True,
        "cves": ["CVE-2021-20016", "CVE-2019-0708"],
        "mitre_techniques": ["T1486", "T1059", "T1078", "T1190", "T1082"],
        "sectors_targeted": ["Energy", "Oil & Gas", "Finance", "Manufacturing"],
        "known_victims": ["Colonial Pipeline", "Brenntag"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 156},
            {"country": "France", "coords": [46.22, 2.21], "incidents": 34},
            {"country": "Brazil", "coords": [-14.23, -51.92], "incidents": 28},
        ],
        "behavior_patterns": [
            "file_encryption", "data_exfiltration", "credential_theft",
            "lateral_movement", "persistence", "process_termination"
        ],
        "ransom_note_keywords": ["darkside", "README.darkside"],
        "description": "Colonial Pipeline attack (2021) caused fuel shortages across US East Coast. Group claimed to 'only target companies that can pay' — later rebranded as BlackMatter.",
    },
    {
        "id": "LAZARUS",
        "name": "Lazarus Group",
        "alias": ["Hidden Cobra", "APT38", "Guardians of Peace"],
        "family": "Multiple (Maui, VHD, WannaCry)",
        "type": "Nation-State / APT",
        "apt_group": "Lazarus Group (DPRK RGB)",
        "origin": "North Korea",
        "origin_flag": "🇰🇵",
        "origin_coords": [40.34, 127.51],
        "active_since": "2009",
        "status": "ACTIVE",
        "severity": "CRITICAL",
        "encryption": ["AES-128", "RSA"],
        "double_extortion": False,
        "lateral_movement": True,
        "cves": ["CVE-2017-0144", "CVE-2022-47966", "CVE-2022-3236"],
        "mitre_techniques": ["T1486", "T1059", "T1566", "T1078", "T1195", "T1485"],
        "sectors_targeted": ["Finance", "Crypto", "Healthcare", "Defense", "Nuclear"],
        "known_victims": ["Sony Pictures", "Bangladesh Bank ($81M)", "Axie Infinity ($625M)"],
        "impact_regions": [
            {"country": "United States", "coords": [37.09, -95.71], "incidents": 234},
            {"country": "South Korea", "coords": [35.90, 127.76], "incidents": 456},
            {"country": "Japan", "coords": [36.20, 138.25], "incidents": 123},
            {"country": "Bangladesh", "coords": [23.68, 90.35], "incidents": 12},
            {"country": "India", "coords": [20.59, 78.96], "incidents": 87},
        ],
        "behavior_patterns": [
            "file_encryption", "credential_theft", "supply_chain_attack",
            "data_exfiltration", "persistence", "weak_cryptography", "hardcoded_credentials"
        ],
        "ransom_note_keywords": ["maui", "_READ_ME_FOR_DECRYPT"],
        "description": "North Korean state-sponsored APT. Funds regime through financial cybercrime. Responsible for some of the largest crypto heists in history. Healthcare targeting to fund weapons programs.",
    },
]

# ── Ransomware CVE Cross-Reference ────────────────────────────────────────────

RANSOMWARE_CVES: dict[str, dict] = {
    "CVE-2017-0144": {"name": "EternalBlue", "family": "WannaCry / NotPetya", "cvss": 9.3, "desc": "SMBv1 RCE exploited globally by WannaCry and NotPetya"},
    "CVE-2021-44228": {"name": "Log4Shell", "family": "Multiple (LockBit, Conti)", "cvss": 10.0, "desc": "Apache Log4j2 RCE, exploited by ransomware groups for initial access"},
    "CVE-2021-34527": {"name": "PrintNightmare", "family": "Conti, Vice Society", "cvss": 8.8, "desc": "Windows Print Spooler RCE / LPE used for privilege escalation"},
    "CVE-2021-26855": {"name": "ProxyLogon", "family": "Multiple", "cvss": 9.8, "desc": "Microsoft Exchange pre-auth RCE — ransomware initial access vector"},
    "CVE-2020-1472":  {"name": "Zerologon", "family": "Ryuk, Conti", "cvss": 10.0, "desc": "Netlogon privilege escalation — instant domain compromise"},
    "CVE-2019-0708":  {"name": "BlueKeep", "family": "Multiple", "cvss": 9.8, "desc": "RDP wormable RCE — unauthenticated remote code execution"},
    "CVE-2023-34362": {"name": "MOVEit SQLi", "family": "Cl0p", "cvss": 9.8, "desc": "MOVEit Transfer SQL injection — Cl0p mass exploitation campaign"},
    "CVE-2023-0669":  {"name": "GoAnywhere RCE", "family": "Cl0p", "cvss": 7.2, "desc": "GoAnywhere MFT pre-auth RCE used by Cl0p for initial access"},
    "CVE-2023-4966":  {"name": "Citrix Bleed", "family": "LockBit, Medusa", "cvss": 9.4, "desc": "Citrix NetScaler session token leak — unauthenticated session hijacking"},
    "CVE-2022-47966": {"name": "ManageEngine RCE", "family": "Lazarus Group", "cvss": 9.8, "desc": "Zoho ManageEngine pre-auth RCE used by North Korean APT"},
    "CVE-2021-30116": {"name": "Kaseya VSA", "family": "REvil", "cvss": 9.8, "desc": "Kaseya VSA credential leak + RCE — REvil supply chain attack"},
    "CVE-2021-20016": {"name": "SonicWall SSL-VPN", "family": "DarkSide", "cvss": 9.8, "desc": "SonicWall SSL-VPN SQL injection used by DarkSide for initial access"},
}

# ── Behavioral Pattern Signatures ─────────────────────────────────────────────

BEHAVIOR_SIGNATURES: dict[str, dict] = {
    "file_encryption": {
        "label": "File Encryption",
        "icon": "🔐",
        "description": "Reads and re-encrypts files using symmetric/asymmetric crypto",
        "mitre": "T1486",
        "severity": "CRITICAL",
        "patterns": [
            # AES/RSA/ChaCha crypto combined with file operations
            r"AES|Fernet|ChaCha20|encrypt|cipher",
            r"open\(.*['\"][awb+]+['\"].*\)",
            r"\.encrypt\(|\.update\(.*encode|write.*encrypt",
        ],
        "rule_keywords": ["crypto", "aes", "encrypt", "fernet", "cipher", "rsa"],
        "cwe_matches": ["CWE-327", "CWE-326"],
    },
    "file_enumeration": {
        "label": "File Enumeration",
        "icon": "📂",
        "description": "Recursively traverses directories targeting specific file extensions",
        "mitre": "T1083",
        "severity": "HIGH",
        "patterns": [
            r"os\.walk|Path\.rglob|glob\.glob",
            r"\.(docx?|xlsx?|pdf|jpg|png|zip|sql|bak|key|pem)",
        ],
        "rule_keywords": ["path.traversal", "directory", "glob", "walk"],
        "cwe_matches": ["CWE-22"],
    },
    "shadow_copy_deletion": {
        "label": "Shadow Copy Deletion",
        "icon": "🗑️",
        "description": "Deletes Windows VSS shadow copies to prevent recovery",
        "mitre": "T1490",
        "severity": "CRITICAL",
        "patterns": [
            r"vssadmin|wmic.*shadowcopy|bcdedit.*recoveryenabled",
            r"delete.*shadow|shadow.*delete",
        ],
        "rule_keywords": ["vssadmin", "shadowcopy", "wmic"],
        "cwe_matches": [],
    },
    "process_termination": {
        "label": "Security Process Kill",
        "icon": "🔪",
        "description": "Terminates AV/EDR/backup processes before encryption",
        "mitre": "T1562.001",
        "severity": "CRITICAL",
        "patterns": [
            r"taskkill|kill.*process|os\.kill|signal\.SIGKILL",
            r"subprocess.*taskkill|psutil.*kill",
        ],
        "rule_keywords": ["subprocess", "taskkill", "os.kill", "process"],
        "cwe_matches": ["CWE-78"],
    },
    "persistence": {
        "label": "Persistence Mechanism",
        "icon": "🔗",
        "description": "Establishes startup persistence via registry, cron, or services",
        "mitre": "T1547",
        "severity": "HIGH",
        "patterns": [
            r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"crontab|schtasks|systemd.*enable|rc\.local",
            r"winreg|_winreg|reg\.exe",
        ],
        "rule_keywords": ["registry", "cron", "startup", "service"],
        "cwe_matches": [],
    },
    "credential_theft": {
        "label": "Credential Harvesting",
        "icon": "🔑",
        "description": "Extracts credentials from memory, files, or environment variables",
        "mitre": "T1552",
        "severity": "CRITICAL",
        "patterns": [
            r"password.*=.*['\"][^'\"]{6,}",
            r"os\.environ.*(?:pass|key|secret|token|cred)",
            r"LSASS|mimikatz|sekurlsa",
        ],
        "rule_keywords": ["hardcoded", "password", "secret", "credentials", "token"],
        "cwe_matches": ["CWE-798", "CWE-312"],
    },
    "data_exfiltration": {
        "label": "Data Exfiltration",
        "icon": "📤",
        "description": "Uploads sensitive data to remote C2 before encryption",
        "mitre": "T1041",
        "severity": "HIGH",
        "patterns": [
            r"requests\.post|urllib.*urlopen|http\.client",
            r"ftp|sftp|smb|upload.*file",
            r"base64.*encode.*send|compress.*upload",
        ],
        "rule_keywords": ["ssrf", "requests", "urllib", "upload", "post"],
        "cwe_matches": ["CWE-918"],
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "icon": "🌐",
        "description": "Spreads to other systems via network shares, RDP, or SMB",
        "mitre": "T1021",
        "severity": "HIGH",
        "patterns": [
            r"subprocess.*psexec|wmic.*node|net use|net view",
            r"socket|paramiko|smb|winrm",
        ],
        "rule_keywords": ["subprocess", "command.injection", "network", "socket"],
        "cwe_matches": ["CWE-78"],
    },
    "weak_cryptography": {
        "label": "Weak Cryptographic Keys",
        "icon": "🔓",
        "description": "Uses weak algorithms (MD5/SHA1/ECB) that ransomware can exploit for key recovery",
        "mitre": "T1600",
        "severity": "HIGH",
        "patterns": [
            r"md5|sha1|des|ecb|rc4",
            r"hashlib\.md5|hashlib\.sha1",
        ],
        "rule_keywords": ["weak", "md5", "sha1", "crypto", "ecb"],
        "cwe_matches": ["CWE-327", "CWE-328"],
    },
    "hardcoded_credentials": {
        "label": "Hardcoded Credentials",
        "icon": "📌",
        "description": "Hardcoded secrets enable attackers to authenticate and deploy ransomware",
        "mitre": "T1552.001",
        "severity": "CRITICAL",
        "patterns": [
            r"password\s*=\s*['\"][^'\"]{4,}",
            r"api_key\s*=|secret\s*=|token\s*=",
        ],
        "rule_keywords": ["hardcoded", "secret", "credentials", "password"],
        "cwe_matches": ["CWE-798"],
    },
    "sql_injection": {
        "label": "SQL Injection (Initial Access)",
        "icon": "💉",
        "description": "SQLi can be used for initial access or credential theft to deliver ransomware",
        "mitre": "T1190",
        "severity": "HIGH",
        "patterns": [],
        "rule_keywords": ["sql", "injection", "tainted"],
        "cwe_matches": ["CWE-89"],
    },
    "command_injection": {
        "label": "Command Injection (Execution)",
        "icon": "⚡",
        "description": "OS command injection enables direct payload execution",
        "mitre": "T1059",
        "severity": "CRITICAL",
        "patterns": [],
        "rule_keywords": ["command.injection", "subprocess", "shell", "os.system"],
        "cwe_matches": ["CWE-78"],
    },
    "ssrf": {
        "label": "SSRF (C2 Reachback)",
        "icon": "🔄",
        "description": "SSRF allows ransomware to communicate with C2 infrastructure",
        "mitre": "T1090",
        "severity": "HIGH",
        "patterns": [],
        "rule_keywords": ["ssrf", "request.forgery", "internal"],
        "cwe_matches": ["CWE-918"],
    },
    "deserialization": {
        "label": "Unsafe Deserialization",
        "icon": "📦",
        "description": "Deserialization vulnerabilities enable RCE for ransomware deployment",
        "mitre": "T1059",
        "severity": "CRITICAL",
        "patterns": [
            r"pickle\.loads|yaml\.load\s*\(",
            r"unserialize|deserialize",
        ],
        "rule_keywords": ["deserialization", "pickle", "yaml.load", "unsafe"],
        "cwe_matches": ["CWE-502"],
    },
}

# ── Blast Radius Scoring ────────────────────────────────────────────────────────

BLAST_RADIUS_WEIGHTS = {
    "file_encryption":      25,
    "shadow_copy_deletion": 20,
    "lateral_movement":     20,
    "credential_theft":     15,
    "data_exfiltration":    15,
    "process_termination":  10,
    "persistence":          10,
    "command_injection":    10,
    "deserialization":      10,
    "hardcoded_credentials": 8,
    "sql_injection":         8,
    "ssrf":                  6,
    "weak_cryptography":     5,
    "file_enumeration":      5,
}

BLAST_RADIUS_LEVELS = [
    (80, "CATASTROPHIC", "#7c3aed", "Full infrastructure compromise. Data encryption, exfiltration, and unrecoverable destruction likely."),
    (60, "SEVERE",       "#dc2626", "Wide lateral spread possible. Multiple systems at risk of encryption and credential compromise."),
    (40, "HIGH",         "#d97706", "Significant risk of data theft and partial system compromise. Lateral movement plausible."),
    (20, "MODERATE",     "#2563eb", "Limited blast radius. Isolated exploitation possible but containable with rapid response."),
    (0,  "LOW",          "#16a34a", "Minimal ransomware indicators detected. Standard hardening recommended."),
]


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class DetectedBehavior:
    key: str
    label: str
    icon: str
    mitre: str
    severity: str
    description: str
    matched_findings: list[dict] = field(default_factory=list)
    match_count: int = 0


@dataclass
class FamilyMatch:
    family: dict
    confidence: int          # 0-100
    matched_behaviors: list[str] = field(default_factory=list)
    matched_cves: list[str] = field(default_factory=list)


@dataclass
class RansomwareReport:
    # Core risk
    ransomware_score: int = 0           # 0-100
    blast_radius_score: int = 0         # 0-100
    blast_label: str = "LOW"
    blast_color: str = "#16a34a"
    blast_description: str = ""
    is_apt: bool = False
    apt_confidence: int = 0             # 0-100

    # Detected
    detected_behaviors: list[DetectedBehavior] = field(default_factory=list)
    family_matches: list[FamilyMatch] = field(default_factory=list)
    primary_family: Optional[FamilyMatch] = None

    # CVEs
    active_cves: list[dict] = field(default_factory=list)

    # Affected sections (files)
    affected_sections: list[dict] = field(default_factory=list)

    # Summary
    behavior_count: int = 0
    critical_behavior_count: int = 0


# ── Detection Engine ──────────────────────────────────────────────────────────

def _normalize_rule(rule_id: str) -> str:
    return rule_id.lower().replace("-", ".").replace("_", ".")


def _finding_matches_behavior(finding: dict, behavior_key: str, sig: dict) -> bool:
    rule = _normalize_rule(finding.get("rule_id", ""))
    cwe  = (finding.get("cwe") or "").upper()

    # Match by CWE
    if cwe and cwe in sig.get("cwe_matches", []):
        return True

    # Match by rule keyword
    for kw in sig.get("rule_keywords", []):
        if kw.lower() in rule:
            return True

    return False


def detect(
    findings: list[dict],
    repo_path: Optional[str] = None,
) -> RansomwareReport:
    """
    Main entry point.  Pass the list of Finding dicts from the scan result.
    Returns a fully-populated RansomwareReport.
    """
    report = RansomwareReport()
    if not findings:
        return report

    # ── 1. Detect behaviors ───────────────────────────────────────────────────
    detected: dict[str, DetectedBehavior] = {}

    for bkey, sig in BEHAVIOR_SIGNATURES.items():
        matched = [f for f in findings if _finding_matches_behavior(f, bkey, sig)]
        if matched:
            db = DetectedBehavior(
                key=bkey,
                label=sig["label"],
                icon=sig["icon"],
                mitre=sig["mitre"],
                severity=sig["severity"],
                description=sig["description"],
                matched_findings=matched[:5],   # cap for display
                match_count=len(matched),
            )
            detected[bkey] = db

    report.detected_behaviors = sorted(
        detected.values(),
        key=lambda b: (b.severity != "CRITICAL", b.severity != "HIGH", -b.match_count)
    )
    report.behavior_count = len(detected)
    report.critical_behavior_count = sum(
        1 for b in detected.values() if b.severity == "CRITICAL"
    )

    # ── 2. Match ransomware families ──────────────────────────────────────────
    matches: list[FamilyMatch] = []

    for fam in RANSOMWARE_DB:
        required = fam.get("behavior_patterns", [])
        if not required:
            continue

        hit = [b for b in required if b in detected]
        if not hit:
            continue

        confidence = min(int((len(hit) / max(len(required), 1)) * 100), 95)

        # Boost confidence for CVE overlap
        cve_hits: list[str] = []
        for cve in fam.get("cves", []):
            if cve in RANSOMWARE_CVES:
                cve_hits.append(cve)

        if cve_hits:
            confidence = min(confidence + 10, 95)

        if confidence >= 20:
            matches.append(FamilyMatch(
                family=fam,
                confidence=confidence,
                matched_behaviors=hit,
                matched_cves=cve_hits,
            ))

    report.family_matches = sorted(matches, key=lambda m: -m.confidence)
    if report.family_matches:
        report.primary_family = report.family_matches[0]

    # ── 3. APT determination ──────────────────────────────────────────────────
    apt_families = [
        m for m in report.family_matches
        if "APT" in m.family.get("apt_group", "").upper()
        or "Lazarus" in m.family.get("apt_group", "")
        or m.family.get("type", "").startswith("Nation")
    ]
    if apt_families:
        report.is_apt = True
        report.apt_confidence = apt_families[0].confidence

    # ── 4. Blast radius ───────────────────────────────────────────────────────
    raw_blast = sum(
        BLAST_RADIUS_WEIGHTS.get(bkey, 0) for bkey in detected
    )
    report.blast_radius_score = min(raw_blast, 100)

    for threshold, label, color, desc in BLAST_RADIUS_LEVELS:
        if report.blast_radius_score > threshold:
            report.blast_label = label
            report.blast_color = color
            report.blast_description = desc
            break

    # ── 5. Ransomware score ───────────────────────────────────────────────────
    family_boost = min(
        max((m.confidence for m in report.family_matches), default=0), 40
    )
    behavior_score = min(report.behavior_count * 8 + report.critical_behavior_count * 6, 60)
    report.ransomware_score = min(behavior_score + family_boost, 100)

    # ── 6. Active CVEs ────────────────────────────────────────────────────────
    seen_cves: set[str] = set()
    for m in report.family_matches:
        for cve_id in m.family.get("cves", []):
            if cve_id not in seen_cves and cve_id in RANSOMWARE_CVES:
                info = RANSOMWARE_CVES[cve_id].copy()
                info["id"] = cve_id
                info["family_name"] = m.family["name"]
                report.active_cves.append(info)
                seen_cves.add(cve_id)

    report.active_cves.sort(key=lambda c: -c.get("cvss", 0))

    # ── 7. Affected sections (files) ─────────────────────────────────────────
    file_map: dict[str, dict] = defaultdict(lambda: {"behaviors": set(), "count": 0})
    for bkey, beh in detected.items():
        for f in beh.matched_findings:
            fpath = f.get("file", "unknown")
            file_map[fpath]["behaviors"].add(beh.label)
            file_map[fpath]["count"] += 1

    report.affected_sections = [
        {
            "file": fp,
            "behavior_count": info["count"],
            "behaviors": sorted(info["behaviors"]),
        }
        for fp, info in sorted(file_map.items(), key=lambda x: -x[1]["count"])
    ][:20]

    return report
