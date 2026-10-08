# MITRE ATT&CK v18 to v19 mapping (as applied to this repo)

Source of truth: the official STIX bundles in `mitre-attack/attack-stix-data`
(`enterprise-attack-18.1.json` vs `enterprise-attack-19.2.json`, `revoked-by`
relationships), cross-checked against the v19 release notes at
attack.mitre.org/resources/updates/updates-april-2026/ (v19.0 released 28 April 2026;
current point release v19.2).

## Tactics

| v18 | v19 | Notes |
| --- | --- | --- |
| TA0005 Defense Evasion | TA0005 **Stealth** | Same ID, new name. Hiding, blending in, obfuscation, masquerading, indicator removal that is not log tampering. |
| (none) | TA0112 **Defense Impairment** | New tactic. Directly breaking or degrading security tools, logging, firewalls, auth controls. |

v19 matrix column order: Reconnaissance, Resource Development, Initial Access, Execution,
Persistence, Privilege Escalation, Stealth, Defense Impairment, Credential Access,
Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact.

## Revoked techniques (all 17 in v19)

| v18 ID | v18 name | v19 ID | v19 name | v19 tactic |
| --- | --- | --- | --- | --- |
| T1562 | Impair Defenses | T1685 | Disable or Modify Tools | Defense Impairment |
| T1562.001 | Impair Defenses: Disable or Modify Tools | T1685 | Disable or Modify Tools | Defense Impairment |
| T1562.002 | Impair Defenses: Disable Windows Event Logging | T1685.001 | Disable or Modify Tools: Disable or Modify Windows Event Log | Defense Impairment |
| T1562.003 | Impair Defenses: Impair Command History Logging | T1690 | Prevent Command History Logging | Defense Impairment |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | T1686 | Disable or Modify System Firewall | Defense Impairment |
| T1562.006 | Impair Defenses: Indicator Blocking | T1685 | Disable or Modify Tools | Defense Impairment |
| T1562.007 | Impair Defenses: Disable or Modify Cloud Firewall | T1686.001 | Disable or Modify System Firewall: Cloud Firewall | Defense Impairment |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | T1685.002 | Disable or Modify Tools: Disable or Modify Cloud Log | Defense Impairment |
| T1562.009 | Impair Defenses: Safe Mode Boot | T1688 | Safe Mode Boot | Defense Impairment |
| T1562.010 | Impair Defenses: Downgrade Attack | T1689 | Downgrade Attack | Defense Impairment |
| T1562.011 | Impair Defenses: Spoof Security Alerting | T1685.003 | Disable or Modify Tools: Modify or Spoof Tool UI | Defense Impairment |
| T1562.012 | Impair Defenses: Disable or Modify Linux Audit System | T1685.004 | Disable or Modify Tools: Disable or Modify Linux Audit System Log | Defense Impairment |
| T1562.013 | Impair Defenses: Disable or Modify Network Device Firewall | T1686.002 | Disable or Modify System Firewall: Network Device Firewall | Defense Impairment |
| T1070.001 | Indicator Removal: Clear Windows Event Logs | T1685.005 | Disable or Modify Tools: Clear Windows Event Logs | Defense Impairment |
| T1070.002 | Indicator Removal: Clear Linux or Mac System Logs | T1685.006 | Disable or Modify Tools: Clear Linux or Mac System Logs | Defense Impairment |
| T1656 | Impersonation | T1684.001 | Social Engineering: Impersonation | Stealth |
| T1672 | Email Spoofing | T1684.002 | Social Engineering: Email Spoofing | Stealth |

The remaining T1070 sub-techniques (T1070.003 Clear Command History, .004 File Deletion,
.006 Timestomp, ...) keep their IDs and now sit under Stealth.

Also fixed while here (revoked earlier, in ATT&CK v17): T1574.002 DLL Side-Loading was
merged into T1574.001 Hijack Execution Flow: DLL.

## Techniques that kept their ID but changed tactic (used in this repo)

| Technique | v18 tactics | v19 tactics |
| --- | --- | --- |
| Every former Defense Evasion technique not listed below (T1027, T1036, T1055, T1070, T1078, T1134, T1197, T1218, T1497, T1542, T1564, T1620 ...) | Defense Evasion (+ others) | Stealth (+ the same others) |
| T1112 Modify Registry | Defense Evasion, Persistence | Defense Impairment, Persistence |
| T1207 Rogue Domain Controller | Defense Evasion | Defense Impairment |
| T1222 (.001/.002) File and Directory Permissions Modification | Defense Evasion | Defense Impairment (sub-techniques renamed Windows Permissions / Linux and Mac Permissions) |
| T1484 (.001/.002) Domain or Tenant Policy Modification | Defense Evasion, Privilege Escalation | Defense Impairment, Privilege Escalation |
| T1553 (incl. .005 Mark-of-the-Web Bypass) Subvert Trust Controls | Defense Evasion | Defense Impairment |
| T1556 (incl. .006 MFA, .009 Conditional Access Policies) Modify Authentication Process | Credential Access, Defense Evasion, Persistence | Defense Impairment, Persistence, Credential Access |
| T1578 (.001-.005) Modify Cloud Compute Infrastructure | Defense Evasion | Defense Impairment |
| T1548 Abuse Elevation Control Mechanism | Privilege Escalation, Defense Evasion | Privilege Escalation only |
| T1550 Use Alternate Authentication Material (Pass the Hash/Ticket, Web Session Cookie, App Access Token) | Defense Evasion, Lateral Movement | Lateral Movement only |
| T1610 Deploy Container | Defense Evasion, Execution | Execution only |
| T1574 Hijack Execution Flow (incl. .001 DLL, .006 Dynamic Linker Hijacking) | Persistence, Privilege Escalation, Defense Evasion | Stealth, Execution |
| T1127 / T1127.001 Trusted Developer Utilities Proxy Execution | Defense Evasion | Stealth, Execution |
| T1197 BITS Jobs | Defense Evasion, Persistence | Stealth, Persistence, Execution |

Renames with the same ID: T1211 Exploitation for Defense Evasion is now Exploitation for
Stealth; T1557.001 is now Name Resolution Poisoning and SMB Relay.

## House rules for content

- Structured fields (`mitre_technique`, `mitre`, `mitreTechnique`, `mitre_tactic`,
  `tactic`, `phase`, answer keys) carry v19 values only.
- Teaching text uses the v19 ID and may add a short "formerly Txxxx" note where it helps a
  learner who will meet the old ID in older reports or vendor tooling.
- Vendor-native enums that are the vendor's own taxonomy stay as the vendor emits them, for
  example the GuardDuty finding type `DefenseEvasion:IAMUser/AnomalousBehavior` and the
  Defender for Endpoint alert category `DefenseEvasion`.
- `scripts/validate-content.mjs` and `scripts/validate-scenarios.mjs` reject a revoked v18
  ID unless it sits next to a legacy marker ("formerly", "was", "legacy", "revoked", ...)
  or next to its v19 replacement.
