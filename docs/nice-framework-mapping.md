# NICE Framework Alignment — Cyber Defense Analyst (PR-CDA-001)

Maps HACK THE SOC content to the **NICE Workforce Framework for Cybersecurity**
(NIST SP 800-181r1) work role **Cyber Defense Analyst (PR-CDA-001)** — the role a
SOC analyst is hired into. This is a curriculum-alignment reference for colleges
and employers, not a certification claim. TKS = Task / Knowledge / Skill.

The platform covers the large majority of the PR-CDA-001 TKS themes; each is
mapped to the concrete rooms, lessons, and scenarios that build it.

---

## Coverage by competency area

| NICE TKS theme (PR-CDA-001) | Platform content |
|---|---|
| **Analyze network/host traffic & logs to identify anomalies** | Rooms: `log-entry-anatomy`, `windows-event-logs`, `linux-log-analysis`, `networking-fundamentals`, `tcpip-deep-dive`, `dns-deep-dive`, `tls-encrypted-traffic`. All `log_analysis` tasks (108 across the platform). |
| **Characterize & analyze activity to determine threats (triage)** | Rooms: `alert-triage`, `investigation-methodology`, `soc-structure`. Live Dashboard triage + incident report. |
| **Use SIEM/EDR tooling & query languages** | Rooms: `siem-fundamentals`, `sentinel-fundamentals`, `wazuh-fundamentals`, `crowdstrike-falcon`, `sentinelone`, `defender-xdr`, `endpoint-security-fundamentals`. `query_fill` tasks (KQL/SPL). |
| **Apply MITRE ATT&CK to detections** | Rooms: `mitre-attack`. Every `log_analysis`/`analyst_choice` event carries a real `mitre_technique`. `scripts/coverage-report.mjs`: 89/106 practised techniques taught. |
| **Identity & authentication attack analysis** | Rooms: `identity-basics`, `active-directory`, `kerberos-authentication`, `auth-identity-monitoring`, `privileged-access-monitoring`, `windows-protocols-lateral`. Scenarios: kerberoasting, AS-REP roasting, DCSync→Golden Ticket, NTLM relay, AiTM token theft, MFA fatigue. |
| **Malware & endpoint threat analysis** | Rooms: `malware-types`, `malware-analysis-fundamentals`, `memory-disk-forensics`. Scenarios: LockBit ransomware, ESXi hypervisor ransomware, LOLBins, cryptominers. |
| **Cloud security monitoring** | Rooms: `cloud-security-monitoring`, `aws-security`. Scenarios: S3 exfil, IAM escalation, OAuth persistence, K8s pod escape, cloud cryptomining. |
| **Web application attack analysis** | Rooms: `web-application-security`, `web-attacks-practice`. Scenario: SQLi → web shell. |
| **Incident response process & escalation** | Rooms: `incident-response-fundamentals` (SANS PICERL + NIST SP 800-61 Rev 2, with a Rev 3 / CSF 2.0 note), `playbook-execution`. |
| **Digital forensics & evidence handling** | Rooms: `digital-forensics-basics`, `memory-disk-forensics`, `timestamps-and-timelines`, `encoding-encryption-hashing`. |
| **Threat intelligence & IOC analysis** | Rooms: `threat-hunting-fundamentals`, `ioc-analysis`, `tunneling-c2-channels`, `security-products-behaviour`. |
| **Data exfiltration & insider threat** | Rooms in Data Security category; `attackTypeLessons` exfiltration/DLP lesson. Scenarios: insider-threat finance, impossible travel. |
| **Vulnerability context & prioritisation** | Rooms: `vulnerability-management`, `asset-context-prioritisation`. |
| **Report writing / communicating findings** | Scenario Investigation Report (verdict + reasoning + IOCs + narrative, rubric-graded, fabrication-checked) and Dashboard incident report. Reports are now persisted and reviewable. |

---

## Known gaps (from `coverage-report.mjs`, 2026-08-05)

17 practised ATT&CK techniques still lack a dedicated teaching room — run the
script for the live list. Notable examples: T1114.002 (Remote Email Collection),
T1098.005 (Device Registration) — rooms in progress; and several discovery/impact
techniques (T1033, T1057, T1485, T1539, T1657) currently taught only implicitly.

## How to keep this current

- `node scripts/coverage-report.mjs` — MITRE technique coverage (practised vs taught).
- Re-map here whenever a room category is added.
- This is a *self-assessment* against public NICE TKS statements, not an
  accredited mapping; a college adopting the platform can use it as the basis for
  its own syllabus crosswalk.
