# SOC Log Realism — How Each Data Source Actually Reports

**Purpose:** the authoritative reference for what a *real* SOC log looks like per data source — the log types, the real field namespaces, and the hard rule that **each source reports only what it can physically see**. This grounds the Dashboard live-feed audit and the "don't let an EDR report Event Viewer fields" requirement.

**Note:** the external web-research workflow was rate-limited across repeated attempts, so this synthesis draws on the platform's own 14 vendor field-reference memory files (Check Point, FortiGate, MS Graph, O365 DLP, Azure AD, EDR, AD/DC, DNS, DLP, cloud, IAM/PAM, WAF, NAC, UEBA, DB) plus established SIEM/ECS conventions — which *are* the vendor standards.

---

## The one rule that matters most: a source sees only its own layer

Every data source sits at one layer of the stack and can only report what that layer observes. The realism failures a student notices instantly are **layer violations**:

| Source | CAN see | CANNOT see (never emits) |
|---|---|---|
| **Firewall / NGFW** | IPs, ports, protocols, bytes, app-ID, allow/deny, threat sigs | **process names**, file hashes, registry, user logons (it's on the wire, not the host) |
| **EDR** | processes, command lines, file writes, registry, module loads, host network conns | raw router traffic, other hosts' internal logs, cloud API calls |
| **Windows Security (AD/DC)** | logon events, Kerberos, group changes, privilege use (the "Event Viewer" Security channel) | process command lines with full args (that's Sysmon/EDR), network payloads |
| **Sysmon** | its OWN channel: process create (ID 1), network (3), file (11), registry (13), DNS (22) | it is NOT the Windows Security channel and NOT an EDR product |
| **O365 / Azure AD** | sign-ins, mailbox ops, admin changes, DLP matches (cloud audit) | on-host processes, on-prem network traffic |
| **DNS** | queries, response codes, answers | the process that made the query *unless* it's Sysmon Event 22 (host-side) |
| **CloudTrail** | AWS API calls, IAM, S3, EC2 control-plane | on-host activity, non-AWS systems |

**The specific failure the user called out:** an event tagged `source: "edr"` that carries `winlog.event_id: "4624"` and Windows-Security "Event Viewer" fields is impossible — that's the **Windows Security log channel**, a different source. An EDR (CrowdStrike/SentinelOne/Defender) reports through its *own* product schema. Sysmon is also its own source. Mixing them is the #1 realism tell.

---

## Per-source reference

### 1. EDR — CrowdStrike Falcon / SentinelOne / Microsoft Defender for Endpoint / Sophos
**Log types:** process rollup, network connect, file write, module load, credential-access detection, quarantine/prevention.
**Real fields by vendor (use the vendor's namespace, do not mix):**
- **CrowdStrike:** `crowdstrike.event_simplename` (ProcessRollup2, NetworkConnectIP4, NewExecutableWritten, CredentialDumpingTool), `crowdstrike.detection.{technique_id,tactic,severity,pattern_disposition}`, `crowdstrike.behaviors`, `crowdstrike.sensor.id`, plus ECS `process.*`, `host.*`, `user.name`.
- **SentinelOne:** `s1.event_type` (PROCESS_CREATION, IP_CONNECT, FILE_CREATION), `s1.threat.{name,id}`, `s1.detection.classification`, `s1.mitigation_status`.
- **Defender for Endpoint (MDE):** the Advanced Hunting schema — `DeviceProcessEvents`/`DeviceNetworkEvents` fields: `DeviceName`, `ActionType`, `FileName`, `FolderPath`, `ProcessCommandLine`, `InitiatingProcessFileName`, `AccountName`, `SHA256`, `ReportId`, `event.provider: "Microsoft Defender ATP"`. **NOT** `winlog.*`.
**Boundary:** LSASS dump = `process.target.access_rights: "0x1FFFFF"` (CrowdStrike) — never a firewall or O365 concept.

### 2. Windows Security / Active Directory / Domain Controller ("the Event Viewer Security log")
**This is the real "Event Viewer" source** — `source: "ad"` or `"windows_security"`, vendor "Microsoft Active Directory".
**Log types (by Event ID):** 4624 logon success, 4625 logon failure, 4768 Kerberos TGT, 4769 TGS, 4740 lockout, 4728 group add, 4672 special privileges, 4662 object access (DCSync), 1102 log cleared.
**Real fields:** `winlog.event_id`, `winlog.channel: "Security"`, `winlog.provider_name: "Microsoft-Windows-Security-Auditing"`, `winlog.event_data.{LogonType,TargetUserName,SubStatus,TicketEncryptionType,ServiceName,IpAddress}`, ECS `event.code`/`event.action`/`event.outcome`.
**Key SubStatus codes:** `0xC000006A` wrong password (spray), `0xC0000064` no such user, `0xC0000234` locked. **TicketEncryptionType `0x17`** = RC4 = Kerberoasting tell; `0x12` = AES normal.

### 3. Sysmon — its own endpoint channel
`source: "sysmon"`, vendor "Microsoft Sysmon". **Event 1** (process create): `winlog.event_data.{Image,CommandLine,ParentImage,Hashes,IntegrityLevel}`. **Event 3** network, **Event 11** file, **Event 13** registry, **Event 22** DNS query (`QueryName`, `QueryResults`). It is neither the Security channel nor an EDR product — keep it distinct.

### 4. Firewall / NGFW — Palo Alto / Check Point / FortiGate / Cisco
**Log types:** traffic (allow/deny), threat/IPS, URL filtering.
**Real fields:** Palo Alto `pan.{app,action,rule,threat_name}` + `source.ip`/`destination.ip`/`network.protocol`; Check Point `cp.{action,blade,service}` + `src`/`dst`/`proto`; FortiGate `data.{type,subtype,action,srcip,dstip,sentbyte,rcvdbyte}`.
**Hard boundary:** **NO `process.name`** — a firewall on the wire cannot see a process. This is the classic realism bug.

### 5. Identity — O365 / Azure AD / Okta
**Log types:** sign-in success/fail, MFA, mailbox rule, admin role change, OAuth consent, DLP match.
**Real fields:** O365/Azure AD `data.office365.{Operation,Workload,UserId,ActorIpAddress,ResultStatus,ErrorNumber}` + top-level `GeoLocation.country_name`; Okta `okta.{event_type,outcome.result,client.geographical_context,risk.reasons}`.
**Boundary:** identity logs describe *sign-ins and cloud actions*, never on-host processes.

### 6. Network — DNS / Proxy / VPN
DNS: Windows DNS or Sysmon Event 22 fields (`QueryName`, `QueryResults`) — **not** invented analytics like `dns.entropy_score` (that's a SIEM-computed field, not raw telemetry). Proxy: `url.full`, `http.request.method`, `http.response.status_code`, user-agent. VPN: `gp.*` (GlobalProtect) tunnel/gateway/device-registered fields.

### 7. Cloud — AWS CloudTrail / GCP Audit / Azure Activity
CloudTrail: `aws.cloudtrail.{event_name,event_source,user_identity.arn,source_ip_address}`. GCP: `gcp.audit.{operationName?,methodName,principalEmail,callerIp}` (use `source: "cloud_gcp"`, not `"cloudtrail"`). Azure: `azure.activitylogs.*` / `data.office365.*` for Entra. Each cloud has its OWN namespace — don't label a GCP event as CloudTrail.

### 8. DLP / WAF / NAC / UEBA / DB (specialist sources)
Each has a distinct real namespace: DLP `data.office365.DlpRuleMatch`/Purview `PolicyDetails.*`; WAF `waf.{action,rule_id,matched_field}` + `url.full`; NAC Cisco ISE `cisco.ise.{posture_assessment_status,selected_vlan}`; UEBA `ueba.{risk_score,anomaly_type}` (a *computed analytics* layer — legitimately carries scores, unlike raw telemetry); DB Guardium/`db.{statement,operation,rows_affected}`.

---

## The "SIEM-computed vs raw telemetry" distinction (a subtle realism rule)

A raw device log carries **facts the device observed**. Fields like entropy scores, "attempt_count", "unique_usernames", risk scores, and "AttackPattern" labels are **SIEM/UEBA correlation output**, not raw device telemetry. Putting them inside a raw device `raw` block is unrealistic (and, in a training log, often leaks the answer). Correct homes: a UEBA/analytics event (`source: "ueba"`) or a clearly-namespaced `siem.*`/correlation field — never inside a raw firewall/DNS/Windows record.

---

## Applying this to the Dashboard (what the audit checks)

1. **Every live-feed event's `source` + `vendor` + `raw` namespace must agree** — no EDR wearing Windows-Security/Event-Viewer fields, no firewall with `process.name`, no GCP labeled CloudTrail.
2. **Foundation-tier (Easy) events must be simple** — plain descriptions, a focused field set, single-host, no lateral-movement/Kerberos/cloud-pivot concepts.
3. **Each company's feed must use its declared stack** — RocketStack shows CrowdStrike/AWS/Okta, MedCore shows SentinelOne/Check Point, etc. — not a random vendor salad.
4. **Descriptions describe what that source reports** — an O365 event narrates a sign-in/mail action, an EDR event narrates a process, a firewall event narrates a connection.

---

## Dashboard live-feed audit — findings & what was fixed

A full audit of the real-time Dashboard feed sources (companyProfiles.ts, benignEvents.ts, scenarios.ts foundation/core stories, useLiveEvents.ts enrichment, EventFeed rendering) against the three lenses.

### 🔴 The headline finding (now fixed): the *enrichment layer* was re-contaminating clean source data
The source data was largely clean, but **`enrichEvent()` in useLiveEvents.ts stamped Sysmon/Windows "Event Viewer" fields onto every EDR event system-wide** — exactly the "EDR wearing Sysmon clothing" problem. A student clicking a **CrowdStrike** event saw both `crowdstrike.event_simplename: ProcessRollup2` *and* a fabricated `winlog.event_data.Image`. It hit the **Easy-tier foundation stories** (phishing-malware, usb-malware) students see first, and inflated each EDR event's field count with ~8 fake keys.

**Fix applied:** gated every Windows/Sysmon enrichment block on the actual source —
- Sysmon Event 1/3/11/13/22 fields (process/net/file/registry/DNS) now added **only when `source === "sysmon"`**.
- Windows Security auth fields (4624/4625/4740) added **only when `source` is `ad`/`windows_security`**.
- EDR products (CrowdStrike/SentinelOne/Sophos/Defender-for-Endpoint) keep their native schema untouched.
- Also fixed the hardcoded `ParentImage` path (explorer.exe → `C:\Windows\explorer.exe`, not System32).
**Verified in the browser:** CrowdStrike/MDE events now carry **no** `winlog.event_data.Image`; real Sysmon events still keep their winlog fields.

### 🟡 Source-label mislabels (now fixed)
- `companyProfiles.ts` **mc_ad_007** (Cisco VPN session): `source: "ad"` → **`"vpn"`**.
- `companyProfiles.ts` **qb_fwd_01** (O365 inbox-rule): `source: "okta"` + mixed okta/o365 raw → **`"o365"`**, vendor Exchange Online, cleaned raw.
- `benignEvents.ts` **b_fp_006/007/010** (Azure AD sign-ins): `source: "ad"` → **`"o365"`** (matches the file's own `b_o365_az_*` convention).
- `benignEvents.ts` **b_fp_008** (MDE service install): dropped `winlog.event_id: 7045` → MDE-native **`mde.action_type: "ServiceInstalled"`**.
- `scenarios.ts` **evt_03_dlp_alert**: `event_type: "edr_alert"` → **`"dlp_alert"`**; **evt_imp_04_inboxrule**: `"email_received"` → **`"account_modify"`**.

### ✅ Verified correct (no change needed)
- **Every EDR vendor** uses its native namespace in source data (crowdstrike.*/s1.*/sophos.*/MDE Advanced-Hunting) — the contamination was purely in enrichment, now fixed.
- **Windows Security (`ad`)** events with `winlog.event_id 4624/4625/4634` are the *real* Event Viewer Security log — correct, not contamination.
- **Firewalls** (Palo Alto/Check Point/FortiGate/Cisco): network fields only, **no process.name**. Each company uses its declared firewall (RocketStack=FortiGate, not Check Point).
- **Complexity/level is well-sized:** foundation stories are single-host, EDR-only, 4 events, plain-English — correct for Easy. Core stories stay one-host/one-user. Pacing ~85% benign, 1–2 events/tick — a beginner isn't buried. (The enrichment fix also removed the field-bloat that was undermining foundation simplicity.)
- **Coverage:** all 5 companies' feeds match their declared stacks — no wrong-vendor bleed.

### Dashboard-only recommendations status
1. Gate Sysmon/winlog enrichment to native sources — **✅ done**
2. Fix hardcoded ParentImage path — **✅ done**
3. Gate DNS Sysmon-22 stamp to sysmon-only — **✅ done**
4. Relabel mislabeled-source events — **✅ done**
5. Fix two scenario event_type labels — **✅ done**

No Learning-Room or scenario-content changes were made; the foundation/core stories, complexity tiering, and pacing were verified appropriate and left as-is.

---

## Round 2 — full-scenario realism pass + progressive fidelity + Raw tab

A second pass (2026-07-17) extended the audit beyond the live feed to **every attack scenario in `scenarios.ts`**, plus two realism *features*. Grounded in a fresh research pass whose high-confidence, adversarially-verified findings anchored: **(a)** Microsoft Defender for Endpoint `DeviceProcessEvents` PascalCase schema + `InitiatingProcess*` lineage; **(b)** the Sysmon **ProcessGUID** as the correlation key that threads Event 1→3→22 for one process, making a multi-stage chain read as one coherent story rather than disconnected rows.

### A. Scenario data fixes (all 18 builders audited)
- **4 wrong `source`** — Sysmon-native events (winlog Event 22 DNS queries) mislabeled `source: "dns"`/"Windows DNS"; relabeled `sysmon`. (evt_phish_dns_c2, evt_dns_02/04/05)
- **2 wrong `event_type`** — cloud/UEBA alerts typed `edr_alert`; corrected to `ueba_anomaly`. (evt_10_app_still_active, evt_insider_ueba_alert)
- **8 cross-source contaminations removed** — firewall events carrying `process.name` (PSEXESVC/certutil/regsvr32); an EDR registry event carrying Sysmon `winlog.event_data.*`; several `source: "sysmon"` events using ECS field names instead of native `winlog.event_data.*`. All rewritten to the source's own schema.
- **ProcessGUID correlation added** to the Sysmon chains: powershell.exe (PID 5512) across registry+DNS in the phishing→exfil story; update.exe (PID 4488) across 3 DNS-tunnel events; PSEXESVC.exe chain completed with ParentProcessGuid links in ransomware.
- **Deliberately left as-is** (verified authentic, not bugs): Windows Defender Event 5001 mixing `windefend.*` + `winlog.*` (it's one first-party product logging its own tamper event); CrowdStrike ancestor-process (`grandparent`) fields; FortiGate comma-joined multi-destination IP string (aggregated log line, pedagogically load-bearing).

### B. Progressive fidelity (clean beginner → production-grade advanced)
Log fidelity is now a property of the **session**, not the event. When the session's story is **advanced-tier** (Hard), *every* event — benign background noise included — gets a source-appropriate handful of real, low-signal metadata fields (CrowdStrike `aid`/`cid`/`ConfigBuild`, Windows `SubjectLogonId`/`RecordNumber`, firewall `session.id`/`rule.uuid`, cloud `correlation.id`/`request.id`). Foundation/core (Easy/Medium) sessions stay clean for a brand-new learner. Applied **uniformly to benign + attack** on purpose: if only malicious rows were "fuller", field count would leak the answer. Every added field is neutral metadata (no verdict language), preserving the no-hints rule, and values are seeded off `event.id` so they're stable across re-renders. Implemented via a session-level `enrichWithFidelity` wrapper around `enrichEvent`; tier stamped in `attackStories.ts` `story()`. **Verified in a Hard session:** a benign AD 4625 event correctly carried `SubjectLogonId`/`LogonId`; free-run events carried none.

### C. Raw log tab (authentic vendor wire format)
The event detail's old "Raw JSON" toggle (which dumped the internal object) is replaced by an **Analysis | Raw log** segmented control. "Raw log" serialises the event into the format its source *actually* emits on the wire — the same bytes an analyst pivots on before parsing:
- **Windows Security + Sysmon** → Windows Event **XML** (`<Event><System>`/`<EventData><Data Name=…>`), correct Provider/Channel, Event ID inferred from event_type when absent (4625/4769/… ; Sysmon 1/3/11/13/22).
- **Firewall / VPN / proxy / IDS** → **syslog** `key=value` line with a syslog priority header (FortiGate-style), vendor-labelled.
- **EDR / cloud / identity / DLP** → **JSON** blob (these are JSON-ingested in reality).
It only serialises fields that already exist on the event, so it stays faithful to the vendor-accurate source data. **Verified in-browser:** AD→XML, Sysmon→XML, Palo Alto firewall→syslog, MDE→JSON, each rendering correctly with a format label + copy button.

`npx tsc --noEmit` clean; console clean on fresh mount; all changes confined to `scenarios.ts` (data), `useLiveEvents.ts` + `attackStories.ts` + `types.ts` (fidelity), and `EventFeed.tsx` + `rawLogFormat.ts` (Raw tab).

---

## Round 3 — student play-test: remaining tells fixed

Played a live Hard session end-to-end as a skeptical analyst and opened the raw log of every source. Nine remaining realism tells were found and fixed (2026-07-17). Notably, the biggest ones were **self-inflicted by the Round-2 Raw serializer** — an honest finding: the first serializer used one vendor's scaffolding for all appliances.

1. **Syslog serializer stamped FortiGate scaffolding (`devname=`, `vd=root`) on every appliance** — Palo Alto, GlobalProtect, WAF all showed FortiGate fields. Rewrote `rawLogFormat.ts` to be **vendor-aware**: FortiGate → key=value; **PAN-OS → CSV** in the real field order; Check Point → CP key=value (`src`/`dst`/`service`/`origin`); Cisco ASA → `%ASA-x-xxxxxx` message; else RFC5424.
2. **AWS/Cloudflare WAF rendered as syslog** — cloud WAFs ship **JSON** (Firehose/Logpush). `toRawLog` now routes cloud vendors (aws, cloudflare, azure, zscaler, akamai, …) to JSON even on appliance sources; only real boxes (F5/Imperva/FortiGate/PAN) get syslog.
3. **`devname` = the endpoint, not the firewall** — a Palo Alto traffic log named the finance workstation as the device. Now the emitting appliance (`PA-VM-01`, `FG-100F-01`, …), pulled from the event's own device field when present.
4. **Duplicated facts in syslog** (`srcip=… source.ip=…`) — added an ECS-duplicate skip-list so each fact appears once, in the vendor's own key.
5. **`rule.description` read like an answer key** — e.g. "Phishing email … **used for initial access**". Reworded 32/39 MITRE rules + O365/event-type maps to name the **observable trigger** ("Inbound email with archive/macro attachment from untrusted sender"), not the verdict or kill-chain phase. Deliberately **kept** Microsoft Defender's native verdict fields and verbatim Windows Event Viewer text (those genuinely are the product's own output).
6. **PAN IPS event mislabeled `source: proxy`, carrying WAF vocab** — retagged `source: ids` / `event_type: ids_blocked`, dropped `waf.attack_type`, PAN-native action.
7. **Benign Sysmon events missing `ProcessGuid`/`ProcessId`/`UtcTime`** — `enrichEvent` now fills these for any Sysmon event that lacks them (curated chains keep their shared GUID), so benign rows aren't visibly thinner than attack rows and the correlation key is always present.
8. **Kubernetes audit `sourceIPs[0]` flattened key + host = a laptop** — fixed to a real JSON array `sourceIPs: ["…"]` and `host.name: k8s-api-server` (the control plane emits the record), across all three k8s events.
9. **Sparse Windows XML `<System>`** — added the fields a real Windows event always has: real Provider `Guid`, `EventRecordID`, `Execution ProcessID/ThreadID`, `Keywords` (Audit Success/Failure), `Security UserID`, and Level 0 for Security-channel events (severity lives in the audit result, not the level).

Two **new** defects introduced by the Round-3 rewrite were caught in the same browser pass and fixed: a duplicated leading CSV field (`1,1,`), and a GlobalProtect VPN auth being rendered as a PAN **TRAFFIC** log (now a proper `Type=GLOBALPROTECT` log with no dst/ports). `tsc` clean; verified in-browser that Cloudflare WAF→JSON, Palo Alto→PAN-OS CSV (device `PA-VM-01`), Sysmon XML carries real GUID + Keywords.
