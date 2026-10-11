# Content Expansion Research — Tier 1→3 curriculum, practice simulations, EDR console, Splunk & QRadar

**Status:** research only. Nothing in this document has been implemented.
**Date:** August 2026
**Grounding:** every "current state" number below was measured against the repo, not estimated. Commands used are noted so you can re-run them.

---

## 1. Where the platform actually stands

| Measure | Value | How measured |
|---|---|---|
| Rooms | 88 across 15 categories | `ROOMS.length` |
| Difficulty spread | 22 beginner / 49 intermediate / 19 advanced | `grep difficulty:` |
| Scenarios (full investigations) | 33 | `scenarios.ts` |
| Scenario packs (attack stories for the live feed) | 14 + spec | `src/lib/sim/scenario-packs/` |
| MITRE coverage | 93 of 111 practised techniques taught (84%) | `scripts/coverage-report.mjs` |
| Quizzes | 16 | content gate |

**Thinnest categories** (`rooms` per category):

| Category | Rooms | Tasks |
|---|---|---|
| Data Security | 1 | 16 |
| Vulnerability Management | 1 | 13 |
| Forensics | **2** | 24 |
| Application Security | 2 | 21 |
| …vs Network Security | 12 | 165 |

Forensics having 2 rooms against Network Security's 12 is the single most lopsided fact in the curriculum, and it sits directly on top of the "investigations" ambition.

---

## 2. The structural problem to fix first: there is no real tier model

The content *talks* about tiers constantly — "Tier 1" appears 41 times, "Tier 2" 56 times, "Tier 3" 14 times across room files — but **the data model has no tier field**. Rooms carry only `difficulty: beginner | intermediate | advanced` and a free-text `category`.

Consequences today:
- A student cannot see "am I Tier-1 complete?"
- A college cannot assign "the Tier 1 syllabus"
- `difficulty` is doing two unrelated jobs: *how hard is this room* and *where in a career does this sit*. Those are not the same axis — Network Forensics is `advanced` difficulty but squarely Tier 2 work, while shift handover is `beginner` difficulty and pure Tier 1.

**Recommendation (prerequisite for everything below):** add an explicit `tier: 1 | 2 | 3` (plus `tier: 0` for pre-SOC foundations) alongside the existing `difficulty`. Cheap change, unlocks: tier-scoped progress, tier certificates, "you are 6 rooms from Tier 2", and instructor assignment by tier. Without it, "content for every tier" cannot be *shown* to anyone even once it exists.

---

## 3. Chronological curriculum — Tier 0 → Tier 3

Ordered so each block only assumes what earlier blocks taught. ✅ = exists, 🟡 = exists but thin, 🆕 = does not exist.

### Tier 0 — Foundations (pre-SOC)
Largely complete (22 beginner rooms). Gaps worth closing:

| # | Room | Status | Why it belongs here |
|---|---|---|---|
| 0.1 | Threat / Vulnerability / Risk — the risk equation | 🆕 | The three words used most loosely by beginners; never formally tied together |
| 0.2 | Attack Surface as its own concept | 🆕 | Currently a one-line aside repeated across 8 rooms |
| 0.3 | How a log is born — from source to SIEM | 🆕 | Parsers, normalisation, field mapping. Analysts who never learn this treat SIEM fields as magic |

### Tier 1 — Alert Triage Analyst
The job: work the queue, triage, enrich, escalate, document.

| # | Room / asset | Status | Notes |
|---|---|---|---|
| 1.1 | SOC structure, shifts, escalation paths | ✅ | `soc-structure` |
| 1.2 | Log entry anatomy | ✅ | `log-entry-anatomy` |
| 1.3 | Alert triage workflow | ✅ | `alert-triage` |
| 1.4 | Windows / Linux / network log reading | ✅ | strong |
| 1.5 | Enrichment: TI lookup, geo, asset & user context | 🟡 | scattered; deserves one canonical room |
| 1.6 | **Ticketing & case discipline** | 🆕 | What goes in a ticket, why "closed — no action" is a failure, how a case is handed to Tier 2 |
| 1.7 | **Shift handover & SOC metrics** | 🆕 | MTTD/MTTR, queue age, what a handover note must contain. *This is the single clearest divider between "can investigate" and "can work in a SOC."* |
| 1.8 | **False-positive economics** | 🆕 | Why tuning is a Tier-1 responsibility, not someone else's job |
| **Quiz** | Tier 1 Readiness Check | 🆕 | Gate before Tier 2 |
| **Sim** | **Queue Rush** — 20 alerts, 25 min, prioritise + dispose | 🆕 | See §4 |

### Tier 2 — Incident Responder / Investigator
The job: take an escalation, scope it, prove it, contain it, write it up.

| # | Room / asset | Status | Notes |
|---|---|---|---|
| 2.1 | Investigation methodology | ✅ | `investigation-methodology` |
| 2.2 | EDR investigation deep-dive | ✅ | `edr-detection-investigation` — strong theory, no console practice (§5) |
| 2.3 | Memory & disk forensics | 🟡 | 1 room; extend: `$MFT`, USN Journal, Prefetch, Amcache, Shimcache |
| 2.4 | **Network forensics / PCAP** | 🆕 | **Biggest single content hole.** Wireshark, stream reassembly, Zeek logs, NetFlow. Nothing today |
| 2.5 | **Cloud forensics** | 🆕 | Which artefacts exist in AWS/Azure/GCP, container & serverless evidence, what is *not* recoverable |
| 2.6 | **Anti-forensics detection** | 🆕 | Timestomping, log clearing (4616/1102), USN gaps — how you notice someone cleaned up |
| 2.7 | **Evidence handling & chain of custody** | 🆕 | Only what an analyst needs; not a law course |
| 2.8 | **BEC investigation, end to end** | 🆕 | Exists as fragments across `phishing-analysis` / `email-security`; no single BEC case |
| 2.9 | **Ransomware, full lifecycle** | 🆕 | Intrusion → staging → encryption → recovery decisions. Scenarios exist; a *room* does not |
| 2.10 | **Insider threat investigation** | 🆕 | UEBA depth + the HR/legal coordination that makes it different |
| 2.11 | **Supply-chain compromise** | 🆕 | |
| **Quiz** | Tier 2 Readiness Check | 🆕 | |
| **Sims** | 4 new multi-source investigations | 🆕 | See §4 |

### Tier 3 — Threat Hunter / Detection Engineer
The job: find what alerting missed; build the alerting.

| # | Room / asset | Status | Notes |
|---|---|---|---|
| 3.1 | Threat hunting | 🟡 | 1 room. Extend with hypothesis-driven method (PEAK, TaHiTI) |
| 3.2 | Detection engineering | ✅ | `detection-engineering`, `use-case-development` |
| 3.3 | **Sigma rule authoring** | 🆕 | Detection-as-code; write a rule, not read one |
| 3.4 | **YARA rule authoring** | 🆕 | Pairs with malware artefacts |
| 3.5 | **Wazuh operational depth** | 🆕 | `ossec.conf`, `local_rules.xml`, `wazuh-logtest`, `if_sid`/`same_field`, REST API. Today's Wazuh room stops at "read an alert" |
| 3.6 | **Python for analysts** | 🆕 | IOC enrichment, log parsing, bulk lookups. Zero taught Python today (every hit is attacker code) |
| 3.7 | **APIs & automation** | 🆕 | Graph/REST from the *defender* side; today it appears only as attacker OAuth abuse |
| 3.8 | **Adversary emulation / purple teaming** | 🆕 | Atomic Red Team style: run technique → confirm detection fires → fix the gap |
| 3.9 | **Campaign & APT tracking** | 🆕 | Linking separate incidents into one campaign over time |
| 3.10 | **Detection tuning & rule lifecycle** | 🆕 | Versioning, deprecation, measuring rule efficacy |
| **Capstone** | "Final Shift" | 🆕 (already tracked as SEV-3.5) | Timed, multi-category, produces a certificate |

### Cross-tier: close the 18 MITRE gaps
Practised in scenarios, taught nowhere (`scripts/coverage-report.mjs`):

`T1033` `T1039` `T1056.001` `T1057` `T1133` `T1176` `T1219` `T1189` `T1485` `T1534` `T1539` `T1563` `T1565.001` `T1578.002` `T1580` `T1609` `T1619` `T1657`

Several map straight onto rooms proposed above — `T1189` (drive-by) into BEC/phishing depth, `T1539` (steal web session cookie) into the AiTM/token-theft material, `T1580`/`T1619`/`T1578.002` into Cloud Forensics, `T1485`/`T1565.001` into the Ransomware lifecycle room. Closing the gap is mostly a by-product of building §3, not separate work.

---

## 4. Practice simulations — the biggest gap relative to the ambition

Today practice comes in two shapes: the **live dashboard feed** (14 attack packs) and **33 scenarios**. Both are good. What is missing is *variety of exercise type*.

### 4.1 New simulation formats worth building

| Format | What it trains | Why it's different from what exists |
|---|---|---|
| **Queue Rush** (Tier 1) | Prioritisation under time pressure | Today a student sees alerts one at a time and has unlimited time. Real Tier 1 is *triage economics* — 20 alerts, 25 minutes, you cannot deep-dive them all. Scored on whether the *right* ones got depth |
| **Console Investigation** (Tier 2) | Pivoting inside an EDR | See §5 — the flagship |
| **Timeline Build** (Tier 2) | Reconstruction | Given 25 unordered events across 4 sources, place them on a timeline and mark the pivot points. Reuses the existing `ordering` task type at larger scale |
| **Hunt Sprint** (Tier 3) | Hypothesis-driven hunting | "Hypothesis: someone is using WMI for lateral movement. Find it or disprove it." Student writes queries; the platform returns result sets |
| **Rule-Writing Lab** (Tier 3) | Detection engineering | Student writes a Sigma/SPL/KQL rule; it is executed against a labelled event set and scored on true positives caught vs false positives generated. **This is the single most valuable new exercise type** — it closes the loop between detection and consequence |
| **Tabletop** (all tiers) | Team decision-making | Multi-role incident: student plays analyst, platform plays IR lead/legal/comms. Text-based, LLM-driven, graded on decision quality |
| **Report Clinic** (Tier 2/3) | Writing | Student is given a *badly written* real-shaped report and must fix it. Inverts the existing exercise and is much faster to grade deterministically |

### 4.2 Scenario-pack expansion
14 packs is thin for the live feed — students recognise repeats. Target ~30, prioritising: BEC, insider exfiltration, supply chain, ESXi/hypervisor, OAuth consent abuse, Kerberoasting→DCSync chain, cloud IAM escalation, container escape, DNS tunnelling, MFA-fatigue→token theft.

---

## 5. Flagship: simulating an investigation in Defender / CrowdStrike

### 5.1 What exists today
Four relevant rooms — `defender-xdr`, `crowdstrike-falcon`, `sentinelone`, `edr-detection-investigation` — and the last one is genuinely strong: it teaches the real Falcon/MDE field names (`event_simpleName`, `ParentBaseFileName`, `SHA256HashData`, `PatternDispositionDescription`, `ContextProcessName`, `CallStackModuleNames`), how to read a process tree for parent-child anomalies, and the pivot→scope→contain workflow.

**But it teaches all of it as prose and static log blocks.** Verified: `src/components/rooms/` contains only `MermaidDiagram.tsx`, `RoomCard.tsx`, `TaskPlayer.tsx`. There is **no interactive process-tree or console component anywhere**, and no `process_tree` structure in the event model. Process trees are drawn as Mermaid diagrams — a *picture* of a tree, not a tree you can expand.

So the student reads *about* pivoting without ever pivoting. That is exactly the gap you identified.

### 5.2 Proposed: a `console_investigation` task type

**The idea:** a small, faithful re-creation of the *investigation surface* of an EDR console — not the whole product. The student lands on one detection and must navigate outward to reach a verdict.

**Data model** — a graph, authored per exercise:

```
nodes:  process | file | network_connection | user | host | registry_key | scheduled_task
edges:  spawned | wrote | connected_to | authenticated_as | modified | loaded

Each node carries VENDOR-ACCURATE fields and a `revealed: boolean`.
Each node may carry `is_evidence: true` (part of the real attack chain)
or `is_noise: true` (legitimate activity that looks adjacent).
```

**Interactions the student gets:**
1. **Expand process tree** — walk parent ↑ and children ↓ from the flagged process
2. **Pivot on a value** — click a SHA256 / IP / user and ask "where else does this appear?" (fleet-wide)
3. **Show full command line** — often truncated in the alert row, as in the real product
4. **Check the host timeline** — what else happened on this device ±15 minutes
5. **Tag as IOC** — reuse the existing IOC-notebook mechanic
6. **Reach a verdict** + name the containment action

**Scoring (deterministic, no LLM needed):**
- Coverage: what fraction of `is_evidence` nodes did they reach?
- Precision: did they tag noise as evidence?
- Efficiency: pivots used vs the minimum path (soft — exploration is not punished, aimless clicking is)
- Verdict + containment correctness

**Two skins over one engine** — this is the important design point. The *investigative logic is identical*; only the field names and UI chrome differ:

| | Microsoft Defender (MDE) | CrowdStrike Falcon |
|---|---|---|
| Process event | `DeviceProcessEvents` | `ProcessRollup2` |
| Process name | `FileName` | `FileName` |
| Parent | `InitiatingProcessFileName` | `ParentBaseFileName` |
| Command line | `ProcessCommandLine` | `CommandLine` |
| Hash | `SHA256` | `SHA256HashData` |
| Host | `DeviceName` | `ComputerName` |
| Agent/host id | `DeviceId` | `aid` |
| Network event | `DeviceNetworkEvents` | `NetworkConnectIP4` |
| Hunting language | KQL (Advanced Hunting) | Falcon Query Language / Event Search |

Running the *same* intrusion through both skins is a genuinely rare teaching asset: it proves to the student that the skill is transferable and the console is incidental. No competitor does this well.

### 5.3 Cheaper v1, if the full component is too much
Extend the existing `log_analysis` player with a **pivot mechanic**: make specific field values clickable; clicking reveals a linked, pre-authored event set. ~70% of the learning value, a fraction of the build, and it reuses the progressive-reveal machinery already in `TaskPlayer.tsx`. Ship v1, learn, then decide on the full graph console.

---

## 6. Splunk and QRadar

### 6.1 Splunk — the mechanism already exists and is almost unused
`query_fill` already declares `language: "kql" | "spl"`. Measured usage: **19 KQL tasks, 1 SPL task.** So Splunk practice is *supported and unbuilt* — the cheapest high-value content in this entire document.

**Proposed:**

| Asset | Content |
|---|---|
| Room: **Splunk for SOC Analysts** (Tier 1→2) | Search pipeline, `index=`/`sourcetype=`, `stats`/`table`/`where`/`eval`/`rex`, time modifiers, `transaction` vs `stats` grouping. Heavy `query_fill` |
| Room: **Splunk Detection & ES** (Tier 3) | Correlation searches, notable events, the CIM data model, `tstats` acceleration, risk-based alerting (RBA) |
| Quiz | SPL fundamentals |
| Field work | Add `index` / `sourcetype` / `host` / `source` to sample events so SPL queries have realistic targets |
| Sim | Hunt Sprint run entirely in SPL |

Concepts that must be taught because they have no KQL analogue: **sourcetype vs index**, **notable events vs raw alerts**, **CIM normalisation**, **RBA risk scores accumulating on an entity**.

### 6.2 QRadar — essentially absent
Measured: QRadar appears in 6 files (17 mentions total), **AQL in 2 files (5 mentions)**. There is no QRadar teaching content — only name-drops.

QRadar is worth adding *specifically because its model is different*, and that difference is pedagogically valuable:

| Concept | Why it matters |
|---|---|
| **Offense** (not "alert" or "incident") | QRadar aggregates events into an offense keyed on an index field — a genuinely different mental model from Sentinel incidents or Splunk notables |
| **Magnitude = Relevance × Credibility × Severity** | An explicit, teachable scoring model. Nothing else in the curriculum makes prioritisation math this concrete |
| **Log Sources & DSMs** | The clearest real-world example of the parsing/normalisation layer (Tier-0 room 0.3 above) |
| **Building Blocks vs Rules** | Composable detection logic |
| **Reference Sets** | Watchlists — how a SOC operationalises threat intel |
| **AQL** | `SELECT … FROM events WHERE … GROUP BY … LAST 24 HOURS` — SQL-shaped, a useful third syntax |

**Implementation cost is low:** add `"aql"` to the `query_fill` language union — a one-line change to a union type that already precedent-exists (the renderer just prints the language label and matches blanks case-insensitively; it is language-agnostic by design).

**Proposed:** one Tier-2 room **"QRadar for SOC Analysts"** (offenses, magnitude, log sources/DSMs, building blocks, reference sets, AQL) plus a quiz. A second Tier-3 room only if there is demand.

### 6.3 The idea worth building regardless: **"One Attack, Three SIEMs"**
A single room that takes *one* intrusion and shows it as:
- a **Microsoft Sentinel** incident (KQL, entities, analytics rule)
- a **Splunk ES** notable (SPL, correlation search, risk score)
- a **QRadar** offense (AQL, magnitude, building blocks)

Same attack, three consoles, three query languages, one investigative conclusion. This directly teaches the thing employers actually need — *the tool is incidental, the reasoning transfers* — and it is a strong differentiator. It also amortises: one authored intrusion, three lessons.

---

## 7. Suggested order of work

| Priority | Item | Rationale |
|---|---|---|
| **1** | `tier` field + tier-scoped progress | Everything else is invisible without it. Small change |
| **2** | Splunk content (room + quiz + SPL `query_fill`) | Mechanism already exists and is unused — highest value per hour |
| **3** | Console Investigation **v1** (pivot mechanic on `log_analysis`) | Directly answers the Defender/CrowdStrike ask; reuses existing player |
| **4** | Network Forensics / PCAP room | Largest single content hole; anchors the Forensics category (2 rooms today) |
| **5** | Tier 1 operational rooms (handover, metrics, ticketing) | Cheap to write, and they are what makes a graduate *employable* rather than merely *technical* |
| **6** | QRadar room + `"aql"` language | Low cost, real differentiation |
| **7** | Rule-Writing Lab (Sigma/SPL/KQL scored against a labelled set) | Highest-value new exercise type, highest build cost |
| **8** | "One Attack, Three SIEMs" | Best marketing asset in the list; needs 2 and 6 done first |
| **9** | Console Investigation **v2** (full graph console, MDE + Falcon skins) | The flagship, once v1 has proven the interaction |
| **10** | Tier 2/3 investigation rooms + scenario-pack expansion to ~30 | Steady content build |

---

## 8. Two risks worth naming

1. **Content volume is already the constraint on quality, not quantity.** The recent gate work surfaced 453 questions answerable by picking the longest option. Adding 25 rooms without fixing the authoring standard multiplies that debt. Recommend: land the distractor-quality work and the `CONTENT-SPEC` rules *before* the big build.

2. **Vendor accuracy is the platform's core claim.** Splunk, QRadar, MDE and Falcon content must use real field names, real query syntax and real product behaviour. The existing `scripts/log-field-baseline.json` gate and the vendor field-reference memories are the right mechanism — extend them to cover SPL/AQL/MDE-Advanced-Hunting schemas *as the content is written*, not after.
