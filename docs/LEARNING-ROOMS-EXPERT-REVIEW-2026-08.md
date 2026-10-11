# Learning Rooms — Expert Review (30-Year SOC/IR Perspective)

**Date:** 2026-08-18
**Reviewer stance:** senior SOC/IR/detection-engineering practitioner, reviewing as if this content will train analysts a college is paying to certify as job-ready Tier-1 (and increasingly Tier-2/3, given the "masterclass"/"advanced" rooms).
**Scope reviewed:** `src/data/roomsMeta.ts` (all 91 rooms — full metadata: id, title, description, difficulty, category, prerequisites, task list) + `src/data/rooms-batch-*.ts` (49 files, ~40k+ lines). Full-content deep-read on a representative sample spanning the pedagogical spine (Foundations, SOC Operations, Windows/AD/Kerberos, Linux, SIEM/Wazuh, EDR/CrowdStrike, Threat Intel). Automated grep sweeps for known-risk patterns (wrong Event IDs/SubStatus codes, GrantedAccess values, Wazuh-wrapper contamination, `process.name` on firewalls, fake TLS certs, invented DNS-analytics fields, MITRE tactic/technique mismatches) ran across **all 49 batch files**, not just the sample.
**Not deep-read this pass** (flagged for next round, see bottom): rooms-batch-05, 06, 09, 10, 14-r1..r6, 15-r1, 16-r1, 17-r1..r6, 19–27, 29–31 content prose (metadata/spot-checked only). Given ~91 rooms in one pass, this review prioritized the highest-traffic pedagogical spine and ran automated correctness sweeps everywhere else rather than reading all 40k+ lines line-by-line.

---

## Overall verdict

**8.7 / 10** — this is a mature, unusually well-engineered curriculum, not a first draft. Every sampled reading task uses correct terminology, correct Windows Event IDs/SubStatus codes/encryption types, correct MITRE tactic↔technique pairings, and vendor-real log fields. The platform has clearly already been through several rigorous internal audit passes (visible in-code as dev comments explaining *why* a field was fixed — e.g. a comment in `rooms-batch-03.ts` explicitly documenting that `TargetUserName`/`ServiceName` roles on Event 4769 were previously swapped and corrected). I did not find new P0 factual errors in the areas I could verify.

The one place this review adds real value beyond prior audits: **it looked at the room catalog as a whole graph** (91 rooms × prerequisites) rather than file-by-file, and found one concrete, previously-undocumented-in-report-form pedagogical sequencing gap (below), plus validated that the platform's own prior gap-analysis (`docs/CONTENT-EXPANSION-RESEARCH.md`, `docs/TIER1-TIER2-GAP-BREAKDOWN.md`) is still current and should be treated as the primary source of truth for "what to build next" — I cross-checked it against the live 91-room catalog and it holds up, with three items now closed.

| Axis | Score | Basis |
|---|---|---|
| Technical/professional accuracy | 9.3/10 | Zero new errors found in sampled/swept content; Event IDs, SubStatus codes, GrantedAccess, EncryptionType, MITRE pairs all correct everywhere checked |
| Pedagogical sequencing | 8.0/10 | Prerequisite graph is thoughtfully designed (91-room DAG reviewed in full) but has 1 confirmed AD/Kerberos-before-prerequisite gap and 1 minor masterclass-skip-basics gap |
| Practical SOC relevance | 8.5/10 | Excellent connective tissue between rooms ("the theory lesson taught you X, this room hands you the raw telemetry") and analyst-choice/verdict tasks with fp_traps; console/pivot interactivity is still prose+static-log, not a live process tree (known, already tracked) |
| Content depth / "0→hero" | 8.5/10 (rooms) / 9.5/10 (the paired `/learn` library) | Rooms intentionally stay lean (3–6 readings) because deep theory lives in the 90-lesson zero-to-hero `/learn` library — this is a deliberate two-track design, not an oversight, and it works. Depth gaps that remain are catalog-level (whole topics with no Room at all), not per-room thinness |

---

## 1. Accuracy audit — what I checked and what I found

### Checked clean (no errors found)

- **Windows auth codes** — `0xC000006A` (wrong password), `0xC0000064` (no such user), `0xC0000234` (locked) all correctly distinguished in `windows-event-logs` (rooms-batch-03).
- **Kerberos** — Event 4768 (TGT/AS-REQ-AS-REP) vs 4769 (TGS/service ticket) correctly distinguished throughout `active-directory` and `kerberos-authentication`; `TicketEncryptionType 0x17` = RC4-HMAC (Kerberoasting indicator) vs `0x12` = AES-256 correctly explained; `PreAuthType 0` (AS-REP Roasting) vs `PreAuthType 2` (normal) correct; DCSync (`DS-Replication-Get-Changes-All`) correctly described as full-domain hash extraction, not "crack one account at a time."
- **`GrantedAccess: 0x1FFFFF`** (PROCESS_ALL_ACCESS, the LSASS-dump tell) is used consistently and correctly across every room that references it (`crowdstrike-falcon`, `edr-detection-investigation`, `defender-xdr`, `detection-rules-tuning`, `persistence-mechanisms`/priv-esc content in rooms-batch-11/18/28) — never the wrong `0x1410`.
- **No Wazuh-wrapper contamination outside the dedicated Wazuh room.** `agent.name` / `manager.name: "wazuh-manager"` / `decoder.name` / `full_log` only appear inside `wazuh-fundamentals` content, which is explicitly *about* Wazuh — correct and expected, not a violation of the platform's "no Wazuh fields in general platform events" rule.
- **`process.name` never appears on a firewall/Check Point/FortiGate/PAN-OS event** — every occurrence found is on an EDR (CrowdStrike/MDE) or correlated-SIEM event, which is correct (firewalls don't see processes).
- **No fabricated TLS certs** (no `CN=*.microsoft.com` self-signed spoofing pattern found) and **no invented DNS-analytics fields** (no `dns.entropy_score`-style computed field masquerading as a raw log field) anywhere in the 49 batch files.
- **MITRE tactic↔technique pairing** spot-checked at scale (`T1110*`↔Credential Access, `T1566*`↔Initial Access) across every occurrence in all 49 files — 100% consistent.
- **`crowdstrike.*` fields use real Falcon field names** (`event_simpleName`, `detection.tactic_id`, `detection.pattern_disposition`, `CallStackModuleNames`, `SHA256HashData`) — no leftover `cs.*` or `crowdstrike.AlertType` legacy naming.

### The one real finding (P1 — pedagogical sequencing, developer-acknowledged in code but not in any report)

**Room: `auth-identity-monitoring`** ("Authentication & Identity Monitoring")
Its own description promises: *"detect password sprays, credential stuffing, impossible travel, **and Kerberos-based attacks**."* Its actual content teaches Event 4769/Kerberos service tickets, DCSync, NTDS.dit extraction, and `SeDebugPrivilege`-based LSASS dumping on a Domain Controller (rooms-batch-11.ts, `priv-r3`/`priv-la*` tasks under this room's task-id namespace).

Its listed `prerequisites` are `["windows-event-logs", "identity-basics"]` — **`active-directory` is not required.** A learner can legally reach this room having never learned what a KDC, a TGT, a Domain Controller, or NTDS.dit even *is* (all of that is taught in `active-directory`, not in `windows-event-logs`). The gap is real enough that the codebase already contains a developer comment flagging half of it:

```ts
// identity-basics teaches authn-vs-authz, MFA, sessions/tokens — the ground
// this room assumes. It was authored later (batch 21) and never wired in as a
// prerequisite, so a learner could hit password-spray/Kerberos monitoring
// without the identity foundations. (identity-basics itself only needs
// intro-cybersecurity, so this adds no deep lock.)
```

— but that comment only explains why `identity-basics` was added; it doesn't address the missing `active-directory` link for the Kerberos/DCSync content, which is the deeper gap. **Fix:** add `"active-directory"` to `auth-identity-monitoring`'s prerequisites in `roomsMeta.ts`'s generator source (`rooms.ts`), verify via `scripts/generate-rooms-meta.mjs`.

### Minor (P2) sequencing note

**`protocols-masterclass`** ("Network Protocols Deep Dive") requires only `networking-fundamentals`, skipping `networking-protocols` (the room that actually teaches DNS/HTTP/SMTP/etc. at intro level) even though the masterclass is explicitly a *deep dive on top of* that material. Low impact (it's an elective "masterclass," not on the critical path) but worth tightening for consistency with how every other masterclass room (`firewall-masterclass`, which does require both `networking-protocols` and `firewall-network-security`) is wired.

### Full prerequisite graph — otherwise well-designed

I reconstructed and reviewed the complete 91-room prerequisite DAG. Beyond the one gap above, it is genuinely thoughtful: bridge/foundation rooms (`encoding-encryption-hashing`, `timestamps-and-timelines`, `log-entry-anatomy`, `identity-basics`, `malware-types`, `security-products-behaviour`, `risk-fundamentals`) all correctly gate only on `intro-cybersecurity` and are wired as real prerequisites into the rooms that need them (`ioc-analysis`→`encoding-encryption-hashing`, `digital-forensics-basics`→`timestamps-and-timelines`, `malware-analysis-fundamentals`→`malware-types`). Cross-domain rooms are correctly double-gated (`entra-id` needs both `active-directory` *and* `microsoft-365-security`; `nac-masterclass` needs both `networking-protocols` *and* `active-directory`). "Practice" rooms explicitly chain off their paired theory room and say so in their own description text (e.g. `credential-attacks-practice`: *"The theory lesson taught you what brute forcing... is. This room makes you tell them apart from the raw telemetry alone"*) — a genuinely good pattern worth reusing for future rooms.

---

## 2. Depth-expansion roadmap (the priority the owner asked for)

The platform already has two prior, code-grounded gap analyses that I independently validated against the current 91-room catalog: **`docs/CONTENT-EXPANSION-RESEARCH.md`** and **`docs/TIER1-TIER2-GAP-BREAKDOWN.md`**. Both are accurate and current — I did not duplicate their per-topic breakdowns; instead I re-ran their room inventory against the live catalog. **Status update: 3 of their flagged gaps have since been closed** (`risk-fundamentals` room now exists — closes their "0.1 Threat/Vulnerability/Risk equation" gap; `powershell-for-soc-analyst` now exists — partially closes their "3.6 Python/PowerShell for analysts" gap, PowerShell half only; `commodity-initial-access` now exists, addressing modern initial-access techniques not in their original list). Everything else they flagged as 🆕 is still 🆕 today. My own independent read of the full room list confirms their diagnosis and I did not find additional whole-topic gaps beyond what they already documented.

**Consolidated, re-prioritized "what to add next" (highest impact first), validated against the live catalog:**

1. **Ransomware, full lifecycle — dedicated Room (still missing).** This is the single highest real-world-frequency SOC incident type and the platform has zero dedicated Room walking intrusion→staging→shadow-copy-deletion (`vssadmin`/T1490)→encryption→recovery-decision end to end, even though the live dashboard already has an `esxi-ransomware` scenario pack to draw content from. Model it on the existing `edr-detection-investigation` room (which is a genuinely strong template: six-step workflow, real Falcon/MDE field names, process-tree anomaly reading).
2. **BEC (Business Email Compromise), end-to-end investigation Room (still missing).** BEC is the highest-dollar-loss incident category industry-wide (FBI IC3 consistently ranks it #1 by reported losses) and today it only exists as *fragments* spread across `phishing-analysis` and `exchange-online-security` — no single room walks a full BEC case (inbox rule creation → OAuth consent → wire-fraud email → mailbox forwarding cleanup).
3. **Sigma + YARA rule *authoring* (not just reading) — the sharpest Tier-1→Tier-2 divider (still missing).** `detection-rules-tuning`/`detection-engineering`/`use-case-development` teach students to read and tune Sigma rules; none has the student write one from a TTP and see it scored against a labelled event set. This is flagged in the platform's own prior research as *"the single most valuable new exercise type — it closes the loop between detection and consequence."* I agree with that assessment after reviewing the current state of `detection-rules-tuning` (rooms-batch content is prose-and-quiz about Sigma structure, not authoring practice).
4. **Network forensics / PCAP room (still missing).** Confirmed still absent from the 91-room catalog despite a strong `/learn` theory lesson already existing (`network-traffic-analysis-pcap-wireshark`). No Room gives hands-on Follow-TCP-Stream / beaconing-interval / Zeek-log practice. Given SOC Tier-1/2 analysts increasingly get handed a PCAP export from an EDR or firewall vendor, this is a real operational gap, not an academic one.
5. **`auth-identity-monitoring` prerequisite fix** (§1 above) — cheapest possible fix, immediate pedagogical-integrity win, do this one first regardless of the bigger items.

**Second-tier additions** (still valid from the prior research, re-confirmed absent): cloud forensics (which cloud artefacts survive vs. what's unrecoverable after `TerminateInstances`), anti-forensics detection (timestomping, log clearing 4616/1102, USN Journal gaps — note: 1102 itself is already taught correctly in `windows-event-logs`, so this room would build on existing, correct foundations rather than re-teach them), insider-threat investigation depth (UEBA + HR/legal coordination, distinct from the existing `dlp-fundamentals` room which covers the DLP-tooling side but not the investigation/coordination side), Python-for-analyst automation (IOC bulk-enrichment scripts — currently *zero* defensive Python anywhere in the curriculum; every Python reference is attacker tooling), and a Wazuh room that goes past "read an alert" into `local_rules.xml`/`wazuh-logtest` authoring (today's `wazuh-fundamentals` room, which I read in full, is accurate but stops at alert-reading — confirmed).

**Format-level gap** (also pre-existing, re-confirmed by my sample of `TaskPlayer`-driven log_analysis tasks): every EDR "process tree" in the curriculum is prose + a static Mermaid diagram, never an expandable/pivotable tree component. `edr-detection-investigation` teaches the pivot→scope→contain *mental model* excellently but the student never actually clicks through a tree. This is the platform's own most self-aware gap (documented in `docs/CONTENT-EXPANSION-RESEARCH.md` §5) and remains accurate today.

### Room-level depth notes from my own direct reads (beyond the catalog-level gaps above)

- `wazuh-fundamentals` (read in full): accurate and well-analogized (FIM→`/etc/passwd`, Active Response, rule-level bands), but entirely alert-consumption — no rule-authoring, confirming item above.
- `intro-cybersecurity`, `soc-structure`, `cyber-kill-chain` (read in full): genuinely excellent zero-to-hero writing — concrete numbers with sourcing caveats (*"no single report is the last word — cross-check several… name the source and the year"*), a real SIEM-correlation-vs-raw-log distinction taught explicitly and reinforced later in a log_analysis task rather than just asserted. This trio is publication-quality and should be the house style reference for any new room.
- `active-directory` / Kerberos content (rooms-batch-03, read in depth): the single strongest technical-accuracy sample in the whole review — precise on TargetUserName/ServiceName roles on 4769, PreAuthType semantics, RC4-vs-AES encryption-type reasoning, DCSync mechanics. Use as the reference standard for any future AD/identity content.
- `edr-detection-investigation` (rooms-batch-28, spot-checked): field-accurate CrowdStrike telemetry (`PatternDispositionDescription`, `CallStackModuleNames`, `ContextProcessName`) and a genuinely good six-step workflow — the strongest EDR room in the catalog, worth using as the template for the Ransomware/BEC end-to-end rooms recommended above.

---

## 3. Rooms to preserve as quality reference

When building new content (the ransomware/BEC/Sigma-authoring rooms above), copy the house style from:
- `intro-cybersecurity`, `soc-structure`, `cyber-kill-chain` (rooms-batch-01) — analogy-first, sourced-statistics, explicit SIEM-vs-raw-log pedagogy.
- `active-directory` (rooms-batch-03) — technical precision on Kerberos/DCSync/AS-REP-roasting, correctly-scoped MCQ distractors that test real misconceptions rather than trivia.
- `edr-detection-investigation` (rooms-batch-28) — real vendor field names, six-step workflow, matching/flag tasks that reinforce field meaning rather than just recall.
- `credential-attacks-practice` / `lateral-movement-practice` / `web-attacks-practice` (the "practice" room pattern generally) — explicit "the theory room taught you X, this room makes you find it in raw telemetry with no labels" framing is exactly right and should be the template for any new practice-tier room.

---

## 4. What this pass did NOT cover (flag for next round)

- Full line-by-line read of rooms-batch-05/06/09/10/14-r1..r6/15-r1/16-r1/17-r1..r6/19–27/29–31 — these were only automated-swept (clean on all known-risk patterns) and metadata-reviewed (title/description/prereqs), not read task-by-task for prose accuracy the way the batch-01/03/04/07/28 sample was.
- Content-depth quality of the individual "masterclass"/"advanced" Network Security cluster (`tcpip-deep-dive`, `dns-deep-dive`, `tls-encrypted-traffic`, `windows-protocols-lateral`, `email-protocols-forensics`, `tunneling-c2-channels`) — descriptions read as strong (precise, jargon-appropriate for advanced level) but full content wasn't read this pass.
- Cloud rooms (`aws-security`, `azure-security`, `gcp-security`, `kubernetes-container-security`) content depth — descriptions are strong and specific (real IAM/CloudTrail/S3/GuardDuty terminology visible even at description level) but not deep-read.
- Quiz-distractor balance / no-hints compliance at the individual-question level for the un-sampled batches — this is already covered by the platform's own `soc-room-log-auditor` agent and CI content-validation gates, so it's lower-priority for a manual re-check.

**Recommended next-round scope:** the Cloud Security cluster (5 rooms) and the Network Security "masterclass" cluster (6 rooms) are the two largest un-sampled blocks and the most likely place to find either a stale fact (cloud vendor APIs/pricing/service names change fastest) or a depth shortfall, given they're also the most recently-dated-feeling content by topic.

---

## Files referenced

- `SOC-Training-platform/src/data/roomsMeta.ts` — full 91-room metadata/prerequisite graph reviewed
- `SOC-Training-platform/src/data/rooms-batch-01.ts`, `-03.ts`, `-04.ts`, `-07.ts`, `-11.ts`, `-12.ts`, `-18.ts`, `-28.ts`, `-32.ts` — deep-read/spot-checked in this pass
- `SOC-Training-platform/docs/CONTENT-EXPANSION-RESEARCH.md`, `docs/TIER1-TIER2-GAP-BREAKDOWN.md` — prior gap analyses, validated as still-current source of truth for the expansion roadmap
