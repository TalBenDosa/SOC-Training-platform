# Mock EDR Console — fidelity research and design (Defender XDR + CrowdStrike Falcon)

**Status:** research and design only. Nothing implemented.
**Date:** August 2026
**Goal:** a simulated EDR investigation surface close enough to the real consoles that a graduate opening Defender or Falcon for the first time recognises it immediately.

---

## 0. The one thing to decide before building anything

**Do not clone the vendors' visual identity.** Recreating the Defender or Falcon UI pixel-for-pixel, with their logos, colour systems and product names presented as the real thing, is a trademark and trade-dress problem — and this platform is sold commercially to colleges, so it is a real exposure, not a theoretical one.

The good news is that **the part that carries the learning value is not protected**: field names, schema, query languages, event types, severity models and investigative workflow are technical facts. You can be 100% faithful to those.

Recommended posture, and the rest of this document assumes it:

| Replicate exactly | Approximate in our own visual identity | Do not do |
|---|---|---|
| Field names, schemas, value enums | Layout patterns (list → detail → tree) | Vendor logos / brand colours |
| Query languages (KQL, SPL-like) | Colour semantics (severity ramps) | Claiming to *be* Defender/Falcon |
| Event type taxonomies | Iconography | Screenshots of the real products |
| Investigative workflow + response actions | Typography | Vendor product names as our screen titles |

Framing: *"an investigation console modelled on Microsoft Defender for Endpoint"* — with a visible disclaimer that it is a training simulation and not affiliated with Microsoft/CrowdStrike. Same posture the platform already takes ("Inspired by CrowdStrike Falcon · Microsoft Sentinel · …" on the landing page).

---

## 1. What the real consoles actually contain

### 1.1 Microsoft Defender XDR (`security.microsoft.com`)

**Navigation surface**
- Incidents & alerts → *Incidents*, *Alerts*
- Hunting → *Advanced hunting*, *Custom detection rules*
- Actions & submissions → *Action center*, *Submissions*
- Threat intelligence → *Threat analytics*
- Assets → *Devices*, *Identities*, *Apps*
- Endpoints → *Device inventory*, *Vulnerability management*
- Reports, Settings

**Incident page** — the aggregation layer
- **Attack story / incident graph** — visual node graph of the whole incident
- Tabs: Alerts · Assets · Investigations · Evidence and Response · Summary
- Metadata: severity, status, **classification** (True positive / Informational, expected activity / False positive) and **determination** (Multistage attack, Malware, Phishing, Unwanted software, Compromised account, …)
- Assign to, tags, comments & history

**Alert page**
- **Alert story** — the process tree, expandable, with the flagged node highlighted
- Alert details, related events, impacted assets, recommended actions, MITRE technique badge

**Device page** — *the primary investigative surface*
- Overview: risk level, exposure level, OS, domain, tags, logged-on users
- **Timeline** — every event on the device in sequence, filterable by event type and time window. This is where a real MDE investigation is actually done
- Alerts · Security recommendations · Software inventory · Discovered vulnerabilities
- **Response actions**: Isolate device · Restrict app execution · Run antivirus scan · Collect investigation package · Initiate automated investigation · **Live Response** session

**Advanced Hunting (KQL)** — the tables that matter for us:
`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, `DeviceInfo`, `AlertInfo`, `AlertEvidence`, `EmailEvents`, `EmailUrlInfo`, `IdentityLogonEvents`, `CloudAppEvents`

**Verified `DeviceProcessEvents` columns** (from Microsoft Learn, doc updated 2026-08-07):

```
Timestamp, DeviceId, DeviceName, ActionType, FileName, FolderPath,
SHA1, SHA256, MD5, FileSize,
ProcessId, ProcessCommandLine, ProcessIntegrityLevel, ProcessTokenElevation,
ProcessCreationTime, ProcessUniqueId,
AccountDomain, AccountName, AccountSid, AccountUpn, AccountObjectId, LogonId,
InitiatingProcessAccountDomain, InitiatingProcessAccountName, InitiatingProcessAccountSid,
InitiatingProcessAccountUpn, InitiatingProcessLogonId,
InitiatingProcessIntegrityLevel, InitiatingProcessTokenElevation,
InitiatingProcessSHA1, InitiatingProcessSHA256, InitiatingProcessMD5,
InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId,
InitiatingProcessCommandLine, InitiatingProcessCreationTime,
InitiatingProcessParentId, InitiatingProcessParentFileName, InitiatingProcessParentCreationTime,
InitiatingProcessSignerType, InitiatingProcessSignatureStatus, InitiatingProcessUniqueId,
IsInitiatingProcessRemoteSession, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP,
IsProcessRemoteSession, ProcessRemoteSessionDeviceName, ProcessRemoteSessionIP,
ReportId, AdditionalFields, AppGuardContainerId
```

**Three fidelity details worth building content around** — most training gets these wrong:

1. **`SHA256` is usually EMPTY on `DeviceProcessEvents`.** Microsoft's own doc says: *"This field is usually not populated — use the SHA1 column when available."* Same for `InitiatingProcessSHA256`. Every tutorial that pivots on `SHA256` in this table is teaching a query that returns nothing. This is a superb teaching moment and an instant credibility signal.
2. **Three generations are visible in one row**: the created process (`FileName`), its parent (`InitiatingProcessFileName`), and its grandparent (`InitiatingProcessParentFileName`). Students routinely think they must join the table to itself.
3. **`ProcessTokenElevation`** has exactly three values — `TokenElevationTypeLimited`, `TokenElevationTypeDefault`, `TokenElevationTypeFull` — which is how you actually spot UAC elevation, and **`IsProcessRemoteSession` / `ProcessRemoteSessionIP`** are how you spot RDP-driven lateral movement without leaving the table.

**Live Response** commands: `connect`, `ls`, `cd`, `getfile`, `putfile`, `run`, `processes`, `services`, `registry`, `fileinfo`, `remediate`, `analyze`, `library`

### 1.2 CrowdStrike Falcon (`falcon.crowdstrike.com`)

**Navigation surface**
- Activity → *Detections*, *Incidents*, *Quarantined files*, *Real Time Response audit*
- Investigate → *Event Search*, *Host Search*, *Hash Search*, *User Search*, *IP Search*, *Process Timeline*
- Hosts → *Host management*, *Groups*, *Sensor update policies*
- Configuration → *Prevention policies*, *IOC management*, *Response policies*, *Containment policy*
- Modules: *Spotlight* (vuln), *Discover* (assets), *OverWatch* (managed hunting), *Identity Protection*, *Falcon Complete*, *Next-Gen SIEM*

**Detections page**
- Columns: Severity (Critical/High/Medium/Low/Informational) · Time · Host · **Tactic & Technique** · **Objective** · Filename · User · Status · Assigned to
- Status workflow: `New` → `In Progress` → `True Positive` / `False Positive` / `Ignored`
- Detection detail: **process tree ("execution details")**, full command line, hash, parent/grandparent, file path, triggering indicator, `PatternDispositionDescription` (e.g. *"Process blocked"*, *"Detection, standard detection"*), Falcon host link

**Process Timeline / Process Explorer** — *the primary investigative surface*, the Falcon analogue of MDE's device timeline. Expandable tree where each node carries process name, PID, command line, hash, start time, user — and hangs off it the DNS requests, network connections, file writes, registry operations and module loads attributable to that process.

**Event Search field vocabulary** (`event_simpleName` values):
`ProcessRollup2`, `SyntheticProcessRollup2`, `DnsRequest`, `NetworkConnectIP4`, `NetworkReceiveAcceptIP4`, `FileWritten`, `PeFileWritten`, `RegSystemConfigValueUpdate`, `ScheduledTaskRegistered`, `UserLogon`, `CriticalFileAccessed`

Key fields: `aid` (agent id), `aip`, `ComputerName`, `TargetProcessId_decimal`, `ContextProcessId_decimal`, `ParentProcessId_decimal`, `FileName`, `FilePath`, `CommandLine`, `SHA256HashData`, `MD5HashData`, `UserName`, `UserSid`, `RemoteAddressIP4`, `RemotePort`, `DomainName`, `ProcessStartTime_decimal`

**Real Time Response** — three permission tiers, which is itself a teachable access-control lesson:

| Tier | Can do |
|---|---|
| **Read-Only Analyst** | View/inspect only: `ls`, `cat`, `ps`, `netstat`, `ipconfig`, `reg query`, `filehash`, `getsid`, `eventlog`, `env`, `history`, `mount`, `users` |
| **Active Responder** | The above **+** act on the host: `get` (retrieve file), `kill`, `rm`, `cp`, `mv`, `mkdir`, `zip`, `encrypt`, `memdump`, `xmemdump`, `restart`, `shutdown`, `reg set`/`delete`, `runscript` (existing scripts) |
| **Administrator** | The above **+** `put` (upload to host), `run` (execute arbitrary binary), upload/manage custom scripts |

*(Tier membership above should be re-verified against current CrowdStrike documentation before it is taught as fact — it is behind customer auth and moves between releases.)*

**Network Containment** — isolates the host while preserving the Falcon sensor's own channel. The distinction "contained ≠ powered off ≠ disconnected" is a real Tier-1 misconception worth an exercise.

### 1.3 The two products side by side

| Concept | Defender XDR | Falcon |
|---|---|---|
| Unit of work | **Incident** (aggregates alerts) | **Detection**, plus **Incident** for grouped |
| Primary investigation view | Device **Timeline** | **Process Timeline / Explorer** |
| Process event | `DeviceProcessEvents` | `ProcessRollup2` |
| Parent field | `InitiatingProcessFileName` | `ParentBaseFileName` |
| Grandparent field | `InitiatingProcessParentFileName` | (walk the tree) |
| Command line | `ProcessCommandLine` | `CommandLine` |
| Reliable hash | **`SHA1`** (SHA256 usually empty!) | `SHA256HashData` |
| Host identity | `DeviceName` / `DeviceId` | `ComputerName` / `aid` |
| Hunting language | **KQL** | Falcon Event Search (SPL-like) / NG-SIEM |
| Remote shell | **Live Response** | **Real Time Response (RTR)** |
| Isolation | *Isolate device* | *Network contain* |
| Disposition vocabulary | classification + determination | status + `PatternDispositionDescription` |

**This table is the whole pedagogical thesis**: the reasoning is identical, the vocabulary is not. A student who learns to investigate in one, plus this mapping, can work in either. No competitor teaches the mapping explicitly.

---

## 2. What we can and cannot simulate

| Capability | Feasible? | Notes |
|---|---|---|
| Alert/detection list with real columns & sorting | ✅ Easy | Pure data |
| Detection detail + metadata | ✅ Easy | |
| **Process tree, expandable** | ✅ Medium | New component; core value |
| **Device/process timeline** | ✅ Medium | Filterable event list |
| **Pivot on hash/IP/user across fleet** | ✅ Medium | Pre-authored result sets |
| **Advanced Hunting (KQL) against sample data** | ⚠️ Hard | See §4 — needs a query engine |
| **RTR / Live Response console** | ✅ Medium | Scripted command→output pairs |
| Response actions (isolate, scan, collect) | ✅ Easy | State change + consequence |
| Automated investigation verdicts | ✅ Easy | Canned but realistic |
| Real agent telemetry / live endpoints | ❌ No | Nor should we — synthetic only |

---

## 3. Design — the `console_investigation` task type

### 3.1 Data model

One authored **investigation graph** per exercise:

```ts
interface EdrInvestigation {
  id: string;
  skin: "mde" | "falcon";          // same graph, two vocabularies
  detection: EdrDetection;          // where the student lands
  hosts: EdrHost[];
  nodes: EdrNode[];                 // processes, files, connections, users, reg keys
  edges: EdrEdge[];                 // spawned | wrote | connected_to | loaded | authenticated_as
  truth: {
    evidenceNodeIds: string[];      // the real attack chain
    noiseNodeIds: string[];         // legitimate activity that looks adjacent
    verdict: "true_positive" | "false_positive" | "escalate";
    containment: string[];          // acceptable response actions
  };
}

interface EdrNode {
  id: string;
  kind: "process" | "file" | "network" | "user" | "registry" | "scheduled_task";
  parentId?: string;
  hostId: string;
  ts: string;
  fields: Record<string, string>;   // VENDOR-ACCURATE, keyed by the active skin
  revealedBy?: "initial" | "expand" | "pivot" | "timeline" | "rtr";
}
```

**The skin is a field-name mapping, not a second dataset.** One authored intrusion renders as MDE or Falcon:

```ts
const FIELD_MAP = {
  mde:    { proc: "FileName", parent: "InitiatingProcessFileName",
            cmd: "ProcessCommandLine", hash: "SHA1", host: "DeviceName" },
  falcon: { proc: "FileName", parent: "ParentBaseFileName",
            cmd: "CommandLine", hash: "SHA256HashData", host: "ComputerName" },
};
```

This is the highest-leverage decision in the design: **author once, teach twice**, and the *contrast itself* becomes a lesson.

### 3.2 Screens

1. **Detection queue** — list with real columns, severity ramp, status workflow
2. **Detection detail** — summary + the process tree, flagged node highlighted
3. **Process tree** — expand ↑ parents / ↓ children; each node shows the skin's fields; click a node to see its full record
4. **Device timeline** — every event on the host, filterable by type and ±time window
5. **Pivot panel** — click any hash / IP / user → "where else does this appear?" (fleet-wide)
6. **Response actions** — isolate, scan, collect package, kill process; each with a consequence and a "was this proportionate?" check
7. **RTR / Live Response console** — a fake terminal accepting the real command set, returning authored output. Enforce the **permission tiers**: the student is given a role, and `put`/`run` are refused unless they are Administrator — which teaches least privilege by making them feel it
8. **Verdict + report** — reuse the existing incident-report grader

### 3.3 Scoring — deterministic, no LLM required

| Dimension | Measure |
|---|---|
| **Coverage** | fraction of `evidenceNodeIds` reached |
| **Precision** | noise nodes wrongly tagged as evidence |
| **Path efficiency** | pivots used vs minimum path (soft — exploration is fine, aimless clicking is not) |
| **Verdict** | correct disposition |
| **Proportionality** | containment action appropriate (isolating a domain controller over one adware hit is *wrong*) |
| **Report** | existing rubric grader |

This fits the platform's existing server-side grading model (`src/lib/rooms/grading.ts`) with no LLM in the scoring loop.

---

## 4. Advanced Hunting — the hard part, and a cheap way in

A real Advanced Hunting experience means executing student-written KQL against a dataset. Three options:

| Option | Effort | Fidelity |
|---|---|---|
| **A. `query_fill`** (exists today) | ~0 | Student completes a query; no execution. Already used for 19 KQL tasks |
| **B. Constrained query executor** | Medium | Parse a safe KQL subset (`where`, `project`, `summarize`, `join`, `count`, `top`) over in-memory JS arrays. Execute the student's real query, return real rows |
| **C. Full KQL engine** | Very high | Not worth it |

**Recommendation: B.** A subset covering `where` / `project` / `summarize by` / `count` / `top` / `join` handles the overwhelming majority of genuine hunting queries, runs entirely client-side over authored tables, and — critically — lets the **Rule-Writing Lab** exist: student writes a detection query, it executes against a labelled event set, and is scored on true positives caught vs false positives generated. That closes the loop between writing detection logic and living with its consequences, which nothing on the market teaches well.

---

## 5. Build phases

| Phase | Deliverable | Value |
|---|---|---|
| **1** | **Pivot mechanic on existing `log_analysis`** — clickable field values reveal linked pre-authored events | ~70% of the learning value; reuses `TaskPlayer.tsx` progressive-reveal machinery already built |
| **2** | **Process tree component** + `console_investigation` task type, MDE skin, one authored intrusion | The flagship interaction |
| **3** | **Falcon skin** over the same intrusion + the side-by-side mapping room ("same attack, two consoles") | Differentiator; near-zero extra authoring |
| **4** | **Device timeline** + response actions with proportionality scoring | Completes the workflow |
| **5** | **RTR/Live Response terminal** with permission tiers | High engagement, teaches least privilege experientially |
| **6** | **Constrained KQL executor** → Advanced Hunting + Rule-Writing Lab | Highest ceiling |

Phase 1 is small and independently shippable. Do not start at Phase 6.

---

## 6. Content authoring model

Each investigation is one authored file, matching how `scenario-packs/` already works:

```
src/lib/edr/investigations/
  officeMacroToRansomware.ts
  kerberoastToDcsync.ts
  aitmTokenTheftCloud.ts
  legitAdminToolFalsePositive.ts   ← FP cases are essential
```

Rules for authoring, enforced by extending the existing gate:
- Every field name must exist in the real vendor schema — extend `scripts/log-field-baseline.json` to cover `DeviceProcessEvents` / `ProcessRollup2` and fail the build on invented fields (the platform already caught fabricated fields this way twice)
- Every investigation ships **noise nodes**, not just evidence — an investigation where everything you click is malicious teaches nothing about discrimination
- At least 1 in 4 investigations must be a **false positive**
- The correct verdict must be reachable *only* by pivoting, never from the landing alert alone

---

## 7. Honest assessment of cost

This is the largest single feature in the platform's history — a new task type, 4–6 new React components, a graph data model, an authoring format, and (phase 6) a query interpreter. Phases 1–3 are where nearly all the pedagogical value sits; 4–6 are polish and ceiling.

The strongest argument for building it: the platform's core claim is *"you investigate, no hints."* Today that claim is fully delivered in the live dashboard feed but only *described* in the EDR rooms — students read about pivoting through a process tree without ever pivoting through one. Phase 1 alone closes that gap.

---

## Sources

- [DeviceProcessEvents table — Microsoft Defender XDR schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [Data tables in the Microsoft Defender XDR advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables)
- [DeviceNetworkEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [DeviceLogonEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table)
- [Get relevant info about an entity with go hunt](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-go-hunt)
- [Real Time Response — CrowdStrike Developer Center](https://developer.crowdstrike.com/api-reference/collections/real-time-response/)
- [The Power and Ease of Use of Real Time Response — CrowdStrike Tech Hub](https://www.crowdstrike.com/tech-hub/endpoint-security/the-power-of-real-time-response/)
- [FALCON 240: Investigating and Mitigating Threats (syllabus)](https://www.crowdstrike.com/wp-content/uploads/2024/03/FALCON-240-Syllabus.pdf)
- [Falcon Next-Gen SIEM](https://www.crowdstrike.com/en-us/platform/next-gen-siem/)
