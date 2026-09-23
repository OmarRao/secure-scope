# SecureScope — Infrastructure Security Assessment (Design)

> Status: **Draft for review** · Owner: Omar Rao · Target: SecureScope v3.x
> This document proposes extending SecureScope from a **code + cloud** scanner
> into a **full-stack infrastructure security posture platform**: source → IaC →
> containers → cloud → **on-prem datacenter** (hypervisors, storage, physical
> hosts, network) with a data-protection / cyber-resilience focus.

---

## 1. Goals & non-goals

**Goals**
- Assess the security posture of *running* infrastructure, not just infra-as-code files.
- Cover on-prem targets that a cloud-hosted scanner cannot reach today: hypervisors, storage arrays, bare-metal/BMC, network devices, live Kubernetes.
- Lead with a **data-protection & ransomware-resilience** assessment (the differentiator) on top of standard CIS-style hardening.
- Reuse existing SecureScope machinery: KEV/EPSS enrichment, compliance mapping, drift alerts (watch-monitor), evidence packs, the report/PDF pipeline.
- Ship incrementally and **dormant-by-default** — every assessor is inert until credentials/targets are configured, so nothing changes for existing users.

**Non-goals (initially)**
- No active exploitation, no config *mutation* — strictly read-only assessment.
- No replacement for a full EDR/SIEM; SecureScope assesses posture, it does not do runtime detection.
- No credential storage in the hosted app (see §4 security model).

---

## 2. The core architectural constraint

SecureScope today is a **hosted Flask app on Render**. It can reach the public
internet (repos, URLs) but **cannot reach private management networks** — an
ESXi host, a SAN controller, or an iDRAC BMC live on isolated networks. On-prem
assessment therefore requires a component that runs *inside* the customer network.

Two supported deployment models:

### 2a. Collector model (recommended)
A lightweight **SecureScope Collector** runs inside the network (container, VM,
or Windows service). It:
1. Reads a local job/target config (which hosts, which read-only credentials).
2. Runs the relevant **assessors** locally against the targets.
3. Ships back **only findings** (normalized JSON) to the hosted dashboard over TLS — **credentials never leave the network**.

```
 ┌─────────────── customer network ───────────────┐        ┌── hosted ──┐
 │  vCenter   SAN   iDRAC   AD   K8s   switches    │        │            │
 │     ▲       ▲      ▲      ▲    ▲       ▲         │        │ dashboard  │
 │     └───────┴──────┴──read-only┴───────┘        │        │  + report  │
 │                  │                              │        │            │
 │        ┌─────────▼──────────┐   findings JSON   │        │            │
 │        │ SecureScope        │ ───────(TLS)──────┼───────▶│  ingest    │
 │        │ Collector          │                   │        │  API       │
 │        └────────────────────┘                   │        │            │
 └─────────────────────────────────────────────────┘        └────────────┘
```

### 2b. Self-hosted model
Run the entire SecureScope stack on-prem (Docker + Helm artifacts already exist).
Simplest for air-gapped sites; the collector and dashboard are the same deployment.

> **Decision needed:** target the **collector model** first (keeps the hosted
> dashboard, minimal on-prem footprint), with self-hosted as a documented option.

---

## 3. Assessor architecture (the plugin framework)

Everything is built around one small, uniform interface so new targets are
additive and independently testable.

```python
# infra/base.py  (Phase 1)
class Assessor(Protocol):
    id: str                       # "vmware.esxi", "storage.netapp", ...
    domain: str                   # "hypervisor" | "data_protection" | "storage" | ...
    def applies(self, target: Target) -> bool: ...
    def assess(self, target: Target, conn: Connector) -> list[Finding]: ...

@dataclass
class Target:                     # what to assess + how to reach it (no secrets inline)
    id: str; kind: str; host: str; cred_ref: str; tags: dict

@dataclass
class Finding:                    # one normalized posture finding
    assessor: str; control: str; title: str; severity: str   # CRITICAL..INFO
    status: str                   # PASS | FAIL | WARN | UNKNOWN
    resource: str; detail: str; remediation: str
    frameworks: dict              # {"CIS": "1.2", "NIST": "AC-3", ...}
    cve: str | None; kev: bool; epss: float
```

- **Connectors** abstract the protocol (vSphere API, WinRM, SSH, SNMP, vendor REST). A connector exposes only read verbs.
- **Assessors** are pure logic over connector responses → findings. They are unit-tested against **recorded fixtures** (no live infra needed to develop/CI).
- **Credential resolution** is indirection only: assessors get a `cred_ref`; the collector resolves it locally from its own secret store (env, vault, file). The hosted app never sees a `cred_ref`'s value.
- **Registry**: assessors self-register by `domain`; the runner selects by target kind + enabled domains.

This mirrors the existing dormant `cspm.py` pattern (graceful when no creds/SDK),
generalized into a framework.

---

## 4. Security & safety model (non-negotiable)

1. **Read-only.** Connectors expose only describe/get/list/show verbs. No assessor mutates a target. Enforced by connector design + code review.
2. **Least privilege.** Documented minimal read-only role per target (e.g. vCenter *Read-only* role, AWS *SecurityAudit*, a read-only AD account).
3. **Credentials never leave the network.** The hosted dashboard receives findings only; it never receives or stores infra credentials. The collector holds them locally.
4. **Explicit authorization.** A target must be listed in the collector's own config by an operator; nothing is discovered-and-assessed without opt-in.
5. **Fail-safe.** Unreachable target / missing SDK / bad cred → `UNKNOWN` finding, never a crash; one target's failure never aborts the run.
6. **Auditable.** Every assessment run records what was assessed, when, by which collector — no raw secrets in logs.
7. **Transport.** Collector→dashboard over TLS with a scoped ingest token; the token authorizes *submitting findings*, nothing else.

---

## 5. Assessment domains & example controls

| Domain | Targets | Example read-only checks |
|---|---|---|
| **Hypervisor** | VMware vSphere/ESXi, Hyper-V, Proxmox, Nutanix, XCP-ng | Lockdown mode, SSH/shell, MOB, TLS version, NTP/syslog, VM isolation, secure boot, **outdated build → KEV/CVE** |
| **⭐ Data protection & resilience** | Veeam, Commvault, Rubrik, Cohesity, NetBackup; backup repos/storage | Immutability/Object-Lock/WORM, air-gap, encryption in-transit/at-rest, MFA on console, least-priv service accounts, network isolation, **3-2-1-1-0 scoring**, last successful restore test, RPO/RTO gaps |
| **Storage** | SAN/NAS/object (Dell/EMC, NetApp, Pure, HPE) | Snapshot immutability, insecure protocols (SMBv1, open NFS exports), default creds, replication, firmware CVE |
| **Physical / BMC** | iDRAC, iLO, IPMI; bare-metal OS | Exposed IPMI, default BMC creds, firmware CVE, OS CIS benchmark, open ports/weak TLS |
| **Network** | Firewalls, switches, routers (Cisco, Palo Alto, Fortinet) | Config review, segmentation/VLAN isolation, exposed mgmt planes, weak ciphers, DNSSEC |
| **Live Kubernetes** | Clusters (kube-bench) | CIS benchmark, RBAC, pod-security standards, network policies, exposed etcd/dashboard |
| **Identity** | Active Directory / Entra ID, PKI | Privileged & stale accounts, Kerberoasting exposure, **ADCS ESC1–8**, LAPS, password policy, expiring certs/weak keys |
| **OS & data services** | Windows/RHEL/Ubuntu; SQL Server, Oracle, PostgreSQL, MongoDB; M365/Workspace | CIS OS hardening, missing patches, disk encryption, DB default creds/TDE/exposed ports/audit logging, tenant posture |

---

## 6. Cross-cutting capabilities (reuse existing modules)

- **Compliance overlay** — map every finding to CIS Controls, NIST CSF/800-53, ISO 27001, PCI-DSS, and **DORA / NIS2** (extends `compliance.py`).
- **KEV/EPSS for infra** — extend the dependency exploit-intel enrichment to ESXi builds, BMC/storage firmware, network OS (`exploit_intel.py`).
- **Posture drift alerts** — scheduled re-assessment + "host X left lockdown mode / immutability disabled on repo Y" alerts (extends the watch-monitor + escalation logic).
- **Auditor evidence packs** — export infra posture as SOC 2 / ISO / DORA evidence (`evidence_pack.py`).
- **Unified posture score** — one trended number across code → cloud → datacenter, plus a **ransomware-resilience index** derived from the data-protection domain.
- **Remediation runbooks** — per-finding hardening steps in the report.
- **Report/PDF** — a new **Infrastructure Posture** section in the existing report + PDF pipeline.

---

## 7. Data model & dashboard integration

- **Ingest API** (hosted): `POST /api/infra/ingest` — accepts a signed findings batch from a collector (scoped token), stores per-target latest posture (Firestore), like the badge score store.
- **Report section**: "Infrastructure Posture" — per-domain pass/fail, severity rollup, resilience index, drift vs. last run.
- **Portfolio**: infra targets appear alongside repos with a posture grade and trend (reuses portfolio + trend rendering).

---

## 8. Phased delivery

| Phase | Deliverable | Needs from you |
|---|---|---|
| **1** | Assessor **framework** (`infra/base.py`, registry, runner) + **VMware ESXi/vSphere** assessor (fixture-tested) + **Infrastructure Posture** report section. Dormant. | Nothing — builds + tests against fixtures |
| **2** | **Collector** runtime + ingest API; activate **CSPM (AWS)** through the framework | AWS read-only creds or a vCenter read-only account to validate |
| **3** | **Data-protection & resilience** assessors (immutability, 3-2-1-1-0, recovery readiness) | A backup platform / storage target to validate |
| **4** | **Storage + BMC/physical**, **network devices** | Lab targets |
| **5** | **Identity (AD/Entra, ADCS)**, **OS/DB** assessors | Read-only AD account / hosts |
| **6** | **Cross-cutting**: compliance overlay, KEV-for-infra, drift alerts, evidence packs, unified resilience score | — |

Each phase is independently shippable, dormant until configured, and does not
alter existing scan behavior.

---

## 9. Risks & open questions

- **Validation without a lab.** Assessors are fixture-tested in CI, but real-world accuracy needs at least one live target per domain. Which do you have access to first (vCenter? a backup repo? an AD test forest?)?
- **Vendor API sprawl.** Storage/backup vendors each have their own SDKs; we'll prioritize by what you run (Veeam + VMware first?).
- **Packaging the collector.** Container is easiest; a Windows service may be needed for Hyper-V/AD sites.
- **Scope of "physical".** BMC (iDRAC/iLO/IPMI) is API-assessable; deeper hardware attestation (TPM/secure-boot chains) is a later, larger effort.
- **Licensing.** Assessors are first-party AGPL/commercial; any vendor SDKs pulled in must be license-reviewed (as we do for deps).

---

## 10. Recommendation

Approve **Phase 1** (framework + VMware ESXi assessor + Infrastructure Posture
report section, all dormant and fixture-tested). It commits us to the
architecture with zero risk to the running app, and gives a concrete assessor to
validate against a read-only vCenter whenever you're ready. The
data-protection/resilience domain (Phase 3) is where the unique value lands and
should be prioritized right after the framework proves out.
