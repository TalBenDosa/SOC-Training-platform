# Expert Content Review — HACK THE SOC
**Date:** 2026-07-19
**Method:** 5 independent senior-practitioner reviews (rooms 01–06, 07–12, 13–17, scenarios, lessons+quizzes), read-only, plus hands-on play and direct code verification by the lead reviewer.
**Corpus:** 61 rooms, 23 scenario builders, 17 lessons, 8 quizzes, ~1,070 raw log blocks.

---

## 0. Headline

**The pedagogy is genuinely good. The technical substrate is not yet shippable.**

Every reviewer independently reached the same split verdict. The writing, sequencing, analogies, and — above all — the false-positive / analyst-judgement exercises are better than most commercial courseware. Three findings recurred verbatim across reviewers who never saw each other's work:

- `analyst_choice` tasks with the `fp_trap` field are the strongest pedagogical artefact on the platform.
- The `raw` log blocks are the weakest layer, and they fail in one repeating way.
- Content currency is anchored around 2021–2023 while presenting itself as 2026.

Five reviewers converging on the same defect *classes* means these are not 150 unrelated bugs. They are **five systemic causes**, each fixable at the source.

---

## 1. Verified directly by the lead reviewer (highest confidence)

These four were checked against the code, not inferred.

### V1 — `LESSON_PATHS` is empty. The five learning paths do not exist at runtime. **[BLOCKER]**
`src/lib/lessons/paths.ts` — the entire catalog (lines ~40–238) is inside a `/* */` block. `LESSON_PATHS` evaluates to `[]`.

Four live consumers depend on it:
- `src/app/(app)/learn/[slug]/page.tsx:26`
- `src/app/(app)/learn/[slug]/[lesson]/page.tsx:222`
- `src/app/(app)/admin/AdminContentManager.tsx:71`
- `src/app/api/lessons/[slug]/route.ts:175`

SOC Analyst, Threat Hunter, Incident Responder, Detection Engineer and Purple Team are advertised and render nothing. The only shipping curriculum is the flat 17-item `BUILTIN_LESSONS`. Note the commented catalog and the live array are **two different syllabi with zero slug overlap** — uncommenting as-is produces two competing curricula.

### V2 — Five MITRE techniques are unmapped; `mitre_tactic` emits `undefined`
`src/lib/sim/scenarios.ts` — `T1204.002` (used 11×), `T1219`, `T1176`, `T1566.002`, `T1556.009` have no entry in `tacticForTechnique`. Confirmed by grep: present in the file, absent from the mapping function. This silently breaks tactic display on the affected scenarios.

### V3 — `T1078.002` mapped to the wrong tactic
`scenarios.ts:224` — `T1078.002` (Valid Accounts: Domain Accounts) returns `TA0008` (Lateral Movement). Per ATT&CK it is `TA0001` (Initial Access), consistent with how `T1078` and `T1078.004` are already mapped two lines above at 197 and 204. Internal inconsistency, not just an external one.

### V4 — Debrief timeline rendered backwards **[FIXED THIS SESSION]**
Observed live: `18:51:10, 18:51:14, 18:48:57, 18:49:01`. Root cause — `live.events` is newest-first (batches prepend), so `.filter(...).slice(0,6)` kept the *last* six events and rendered them in reverse, dropping the initial-access steps students most need to see. Fixed in `dashboard/page.tsx` with a chronological sort + earliest-six slice. `tsc` clean.

---

## 2. The five systemic causes

Fixing these at the source resolves the large majority of the ~150 individual defects.

### S1 — Analytics fields injected into vendor `raw` blocks
Reported independently by **all three** room reviewers.

Examples: `FailureCount`, `TimeWindow`, `FailuresPerMinute`, `AlertThreshold`, `PreviousFailures` inside a Windows 4625. `beacon_interval_seconds`, `beacon_jitter_percent`, `domain_age_days` inside a Palo Alto THREAT log. `PasswordAttempted` inside an Entra sign-in — a field that, if it existed, would itself be a critical finding. `spray.attempt_count` aggregates on a 4625.

**Two harms.** These fields do not exist in the named product — a Palo Alto firewall does not compute beacon jitter. And, more damaging pedagogically: deriving *"47 failures across 12 accounts in 2 minutes"* by pivoting **is the skill**. Pre-computing it into the event deletes the exercise.

**Fix at source:** `raw` holds vendor-native fields only. Derived values move to a separate `enrichment` / `siem_context` object.

### S2 — Fields invented to make an exercise solvable
The same pattern with a different motive: a field is fabricated because the question needs it.

- `s1.extensionAdded`, `s1.fileCount_renamed` — do not exist in SentinelOne; **the flag answer depends on one of them**
- `crowdstrike.Confidence` (0–100 ML score) — Falcon has no such field; an entire graded question rests on it
- `RequestorName` on Event 4769 — no such field; **found by two reviewers in two different files**
- `it_verify_result`, `changeTicket` — literal answer keys sitting inside `raw`, making `analyst_choice` solvable by field-lookup rather than reasoning
- `PassRole` as a CloudTrail `eventName` — it is an IAM permission, never an event

**Fix at source:** you already maintain 14 vendor field-reference memory files. Add a CI check that fails any `raw` field not present in the reference for the declared vendor. This alone closes most of S1 and S2.

### S3 — The same fact taught two different ways in two rooms
The most corrosive class, because an attentive student concludes the material is unreliable.

| Contradiction | Right | Wrong |
|---|---|---|
| AES etypes | `0x11`=AES128, `0x12`=AES256 (`ad-r2`) | `0x12`=AES128, `0x18`=AES256 (`ad-q3`) |
| AS-REP roasting | `PreAuthType=0` (pathLessons-c) | `TicketOptions 0x40810010` (builtinLessons L3) |
| Kerberoasting event | 4769 (three places) | 4768 (quiz `la_05`) |
| LogonType 3 | excludes RDP (batch 03) | includes RDP (batch 04) |
| Sysmon `QueryStatus` | numeric `9003` (17-r2) | string `"NXDOMAIN"` (13-r1, 10-r4) |
| XMAS scan | FIN+PSH+URG (17-r1) | all flags (13-r1) |
| Entra `RiskDetail` | remediation state (batch 01) | detection type (batch 05) |
| MDE time column | `Timestamp` (4 examples) | `TimeGenerated` (the template above them) |
| Password spray | 1 attempt/account | 4.4/account, 118/22, 7 lockouts |
| FP-rate target | >98% precision | "below 50% is typical" |
| Tier-1 authority | cannot isolate | had already isolated 12 hosts |
| Lazarus codename | CHOLLIMA (batch 08) | "LAZARUS GROUP" as CS name (batch 07) |

### S4 — Content is 2021–2023 wearing a 2026 date
- **Ransomware roster is dead.** Maze (ceased Nov 2020) used as a live threat. LockBit (Operation Cronos, Feb 2024) and ALPHV (exit-scam, Mar 2024) are the anchor examples. Emotet (defunct 2023) is the loader exemplar. Current: Akira, Qilin, Play, INC, Lynx, SafePay; Latrodectus/DarkGate/Pikabot.
- **Phishing tradecraft predates the macro block.** Both phishing rooms centre on `.docm` "Enable Content" — blocked by default since July 2022. Absent entirely: **AiTM/reverse-proxy** (Evilginx, Tycoon2FA — the dominant credential-phishing technique, and the reason "SPF pass = legitimate" is wrong), HTML smuggling, quishing, ClickFix, OAuth consent phishing.
- **TLS room is a 2020 room.** JA3/JARM as state of the art with no mention of JA4+ (2023, and what sensors actually emit today). No acknowledgement that **TLS 1.3 encrypts the Certificate message** — which invalidates the room's entire issuer/subject detection checklist for the majority of 2026 traffic.
- **VPN room misses the actual VPN threat.** Teaches brute force and impossible travel; omits pre-auth appliance exploitation — Ivanti, Citrix Bleed 1 & 2 (**token replay that bypasses MFA outright**), CVE-2024-3400, FortiOS.
- **Firewall room never says firewalls are now an initial-access vector.** Ten readings on PAN/Fortinet/Check Point with no CVE-2024-3400, no CVE-2024-24919, no FortiOS SSL-VPN series.
- **EDR timeline stops before the two things that matter.** No July 2024 CrowdStrike outage (in a room whose flagship event is a CrowdStrike alert), no EDR-killers/BYOVD.
- **NTLM relay stops a decade early.** SMB signing taught as *the* mitigation; no cross-protocol relay (SMB→LDAP, ESC8/PetitPotam), which signing does not stop. A student concludes a signed environment is relay-safe.
- **Stale statistics graded as fact.** "Attack every 39 seconds" (2007 study of 4 honeypots). Dwell time 197/200+ days — Mandiant median has been **10–11 days** since 2023, and `threat-hunt-q1` grades students on the wrong number. "90% of attacks begin with phishing" attributed to Verizon DBIR — DBIR has never said this; it traces to 2016 vendor marketing. IBM figures are 2023-edition. Retired: TLP:WHITE (2022), `DeviceAlertEvents`, `sigmac`, Chronicle→Google SecOps, NSG Flow Logs.

### S5 — The assessment layer cannot certify anything
- **Answer-length tell is near-universal.** In batch 17 *without exception*, and across most of 01–12, the correct option is the longest and most hedged; distractors are short and absolute ("always", "never", "proves conclusively"). A student can score 100% by picking the longest option. Roughly a third of lesson-embedded items are solvable by elimination alone.
- **Implausible distractors:** "Kerberos is inherently malicious", "whichever alert has the shortest title".
- **Broken or unanswerable items:** `aws-f1` references an event never attached to any task. `dns-q1` keys a restatement of its own premise. `dns-qf1` accepts thresholds (`>80`, `>90`) against a 0–1 ratio — always zero rows. `tunnel-qf1` uses `prev()` inside `summarize` — invalid KQL. Two flag tasks reject the answer their own hint suggests.
- **Genuinely disputable keys:** `cloud-la1` Q2 marks the *correct* statement wrong (IAM is global and always logs `us-east-1` — the explanation concedes it). `ti_01` has two true answers. `tunnel-q2` has two correct answers because Cobalt Strike jitter is one-sided and the room never names the model.
- **Quiz bank is unwired.** No reference between `QUIZZES` and any lesson slug. Five lessons have no quiz; meanwhile a full 12-question Advanced "Cloud & Identity" quiz assesses material **taught nowhere in the 17-lesson track**.

---

## 3. Top defects that would mis-train an analyst

Ranked by how wrong the analyst ends up.

| # | Defect | Where | Why it matters |
|---|---|---|---|
| 1 | `LESSON_PATHS = []` | `paths.ts` | Five advertised paths render nothing |
| 2 | **4769 requester/target inverted** | batch 03 `ad-la1`, 17-r4 | Found twice independently. A student who knows real 4769 answers correctly and is **marked wrong** |
| 3 | AS-REP UAC bit `8388608` | 17-r4, stated twice | That is `PASSWORD_EXPIRED`. Correct is `4194304`. Published filter returns the wrong accounts |
| 4 | `explorer.exe` "in System32, single instance" | batch 02 | Inverts the signal: flags healthy servers, **trusts** explorer.exe running from System32 |
| 5 | ShimCache "proves execution" | batch 09 `dfir-r3` | The #1 forensic misconception. It is *presence* evidence. Gets findings thrown out in real IR review |
| 6 | RAM capture before containing active ransomware | batch 08 `ir-method-q1` | Keys a 15–30 min acquisition while a file share encrypts. Correct: EDR isolate (preserves memory), then acquire |
| 7 | Windows PPID = 1 | batch 09, LA + both Qs + flag | PID 1 is Linux. Windows System is PID 4. Also misattributes PPID anomaly to hollowing (it is spoofing, T1134.004) |
| 8 | Golden Ticket producing Event 4768 | scenarios | A Golden Ticket is forged offline — it **cannot** generate an AS-REQ. That absence is the detection |
| 9 | Password spray defined backwards | batch 08 `alert-triage` | 347 failures against *one* account keyed as T1110.003. "Spraying-style single-account brute force" is a contradiction in terms |
| 10 | Kerberoast LDAP filter self-refuting | 17-r4 | `objectClass=user` matches computer objects — returns exactly what the caveat says it excludes |
| 11 | BEC with no link keyed T1566.002 | `local-lesson-2` | Requires a malicious link; the lesson body itself says BEC has none. Correct: T1656 |
| 12 | Broken queries throughout | lessons 1/2/3 | `!=` against CIDR excludes nothing; `stats ... by _time span=1h` is invalid SPL; `let`+`$token$` is a KQL/SPL hybrid that will not parse; a GUID joined against a UPN returns zero rows forever |
| 13 | Blanket `svchost.exe` exclusion in LSASS detection | lesson 3 | Creates the exact blind spot the detection exists to close |
| 14 | Key Vault data-plane op in the Activity Log | 16-r1 | The room teaches the control/data-plane split, then its flagship event violates it |
| 15 | Attribution taught on shared infrastructure | batch 07 `ioc-r3` | Pivots from a **Tor exit with 3,847 abuse reports** to co-resolving domains and concludes one actor. This is how bad blocklists get made |
| 16 | Empty-string SHA-256 as a malware IOC | lesson 2, batch 12 ×2 | `e3b0c442…b855` is the hash of nothing — the most recognisable hash in security. Also MD5 labelled `sha256`, a 63-char SHA-256, a 24-char MD5 |
| 17 | One IP plays five contradictory roles | platform-wide | `185.220.101.x` is a Tor exit, APT29 C2, spray source, BEC relay, Cobalt Strike C2, and an AWS API source — geolocated to NL, RU and DE. `203.0.113.45` (TEST-NET-3) geolocated to Moscow |
| 18 | Explanations cite evidence not in the log | several | "known Tor-adjacent VPS used in previous attacks" with no such field present. Trains the exact habit that gets Tier-1 tickets kicked back |

---

## 4. Scores

| Area | Accuracy | Pedagogy | Relevance | Depth |
|---|---|---|---|---|
| Rooms 01–06 | 6.0 | 8.1 | 6.8 | 6.5 |
| Rooms 07–12 | 6.1 | 8.2 | 7.8 | 7.0 |
| Rooms 13–17 | 6.2 | 7.2 | 7.8 | 7.0 |
| Lessons | 7.7 | 9.0 | 9.0 | 8.2 |
| Quizzes | 6.0 | — | 7.0 | 6.0 |

**Pedagogy ~8.2 / Accuracy ~6.4.** That gap is the entire finding.

**Strongest:** `windows-event-logs` (most trustworthy reference material on the platform), `auth-identity-monitoring`, `privileged-access-monitoring` (the `xp_cmdshell` reading is senior-level and deliberately calls back to earlier rooms), `firewall-log-analysis` (ship as-is), `microsoft-365-security`, `sharepoint-teams-monitoring`, `customer-communication`, and lessons 8–9 (SIEM/EDR).

**Weakest:** `endpoint-security-fundamentals` (graded on a CrowdStrike feature that doesn't exist), `sentinelone` (flag depends on a fabricated field), `digital-forensics-basics` (assessment built on an impossible PPID), `threat-intelligence` (its only hands-on artefact sources an IP from a CVE catalogue), `wazuh-fundamentals` (the two memorisable facts are both wrong), `entra-id` (capstone event Entra cannot emit), `kubernetes-container-security` (labelled advanced, thinnest room reviewed, omits every preventive control).

---

## 5. What is genuinely excellent — protect it

Do not let a correctness sweep flatten this.

- **`analyst_choice` with `fp_trap`** — the best format on the platform. `phishing-ac1` (auth-pass ≠ legitimate), `fw-ac1` (clean reputation ≠ benign), `dns-ac1` (random subdomains ≠ DGA), `priv-ac1` (trusted insider ≠ authorised), `winproto-ac1` (IPC$+svcctl+7045 is mechanism, not verdict). Batches 07–09 have none — extend it backwards.
- **`spt-teams-la1` Q2** — forces Collection vs Exfiltration and teaches that a download log *does not prove data left*. The single best question in the corpus.
- **Judgement over vocabulary in the lessons** — the five-question framework, benign-true-positive, "quarantined addresses the artifact, not the incident", the pre-isolation authority checklist, timeline-as-investigative-tool. These are things normally taught in person because no course covers them.
- **Deliberate sequencing.** The comment at `builtinLessons.ts:471` explaining why protocols moved *after* SIEM is exactly the right reasoning. Do not reorder.
- **`customer-communication`** DON'T SAY / DO SAY pairs — normally learned only by getting it wrong in front of a client.
- **`pathLessons-f.ts` flagging domain fronting as post-2018 obsolete** — proof the currency instinct exists in the codebase. It just needs applying everywhere.

---

## 6. Recommended order

1. **Restore or delete `LESSON_PATHS`.** Shipping `[]` behind four live consumers is a defect independent of content quality.
2. **Fix V2/V3** (unmapped tactics, `T1078.002`). Minutes of work.
3. **Re-key the wrong answers** — items 2, 3, 6, 9, 11 above plus `cloud-la1` Q2, `la_05`, `threat-hunt-q1`. These are the only defects that make a student *confidently wrong* in an interview or a real ticket.
4. **Build the schema CI gate**, then regenerate every `raw` block against the 14 field-reference files. Split `raw` from `enrichment`. Closes S1 + S2 permanently.
5. **Reconcile the S3 contradiction table.** One canonical answer per fact.
6. **Validate every SPL/KQL snippet** against a real instance. A student who pastes a lesson query and gets a parse error stops trusting the course.
7. **Currency sweep (S4).** Highest return: ransomware roster, then AiTM/HTML smuggling/quishing/ClickFix into both phishing rooms, then appliance-CVE + token replay into VPN, JA4 + TLS 1.3 into TLS.
8. **Normalise MCQ option lengths.** The single largest source of unearned scores.
9. **Wire the quiz bank to lesson slugs** so assessment can only test what was taught. Then write the missing cloud/identity module — in 2026 a Tier-1 spends more time in identity logs than Windows Security logs, and the quiz bank already assumes it.

---

## 7. Bottom line

I would put a new analyst through `firewall-log-analysis`, `auth-identity-monitoring`, `privileged-access-monitoring`, `windows-event-logs`, `microsoft-365-security`, `sharepoint-teams-monitoring` and lessons 8–9 today, unchanged.

I would not ship batches 07, 09, 10 or 17, or lessons 5, 10 and 12, without the corrections above.

The distance between those two lists is smaller than it looks, because the defects cluster: five systemic causes, and the two largest (S1, S2) are closed by one CI gate you already have the reference data to build.
