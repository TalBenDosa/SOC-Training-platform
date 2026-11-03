# Review: Operation Cold Vault (room `ransomware-full-lifecycle`)

Reviewed 2026-11-03. Scope: `src/data/rooms-batch-33.ts` (room content and answer keys), `src/lib/rooms/experience/ransomwareLifecycle.ts` (stations, briefing, labs, persona), `src/lib/rooms/experience/types.ts`, `src/lib/rooms/grading.ts`, `src/lib/rooms/flagLog.ts`, and the operation components under `src/components/operation/`. Technical claims checked against CISA #StopRansomware (the Ransomware and Data Extortion Response Checklist, AA24-109A Akira, AA23-325A Citrix Bleed/LockBit, AA23-136A BianLian), MITRE ATT&CK v19, and Microsoft documentation. Findings below were FIXED in the same pass unless marked "left open".

## 1. Summary verdict

**Accuracy: strong to begin with; a handful of real gaps closed.** The room was already well above typical training material: the RaaS/IAB/affiliate economy, the exfiltration-first shift, the hybrid-crypto explanation and the LOLBin/scheduled-task precursor reasoning were all sound. The defects were (a) assessment resting on telemetry the readings never named (how a scheduled-task creation, a DCSync, a PsExec service install, or an RDP brute force actually appears in Windows logs), (b) a containment instruction at the LSASS stage ("start domain-wide rotation now") that contradicted the correct eviction order the room itself teaches later, and (c) missing the back half of a real ransomware response entirely: scoping the deployment push, the contain/protect-backups/eradicate/rotate/recover order, krbtgt, evidence preservation, reporting and breach notification.

**Pedagogy: good difficulty curve, one over-assessed idea, several taught-but-not-practised steps.** The reading-then-retrieve rhythm is right, labs never leaked a graded answer, and the log-analysis tasks are genuinely hard in the right way. But the room assessed recognition far more than action: the student never wrote a hunt, never ordered a recovery, and the "what do I do now" questions all lived in multiple choice.

**Mission realism: a well-built lesson that stopped at the ransom note.** The graded chain ran detection to impact and then ended on a flag. A real incident's hardest, most teachable work (scoping the blast radius by the push mechanism, then evicting in an order that does not re-expose the environment) was absent. Two new graded tasks and one moved flag turn the Final Gate into an actual response.

## 2. Accuracy findings

Severity: **High** = wrong, or contradicts a graded answer; **Medium** = outdated/misleading/unrealistic; **Low** = polish.

### High

**A1. LSASS-stage remediation contradicted the room's own eviction order (fixed).**
`rw-la1` Q4 answer and explanation originally said the immediate action was to "start domain-wide rotation" of credentials. That is wrong at this point in the incident and contradicts Reading 8's playbook: resetting passwords while the affiliate still holds a foothold just gets them dumped again (Microsoft DART / compromise-recovery guidance; the krbtgt double-reset FAQ makes the same point). The correct immediate action is to **disable the specific exposed privileged accounts** and scope their use; the full rotation comes after eradication.
**Fix:** reworded `rw-la1` Q4 option 1 and its explanation to "disable the exposed privileged accounts, scope, escalate; full coordinated rotation comes later, after persistence is removed (Reading 8)". This now agrees with the new eviction `ordering` task (`rw-o2`).

**A2. Assessed-but-untaught: Windows event IDs behind the lateral-movement question (fixed).**
`rw-q2` tests the "4624 type 3 then 7045 PSEXESVC repeating across hosts" signature, and Reading 5 named only 4624/7045. Reading 5 now also states that a PsExec service install lands as **System Event 7045 and Security Event 4697** (audit-policy dependent), so the graded pattern is fully taught, and `rw-q2`'s stem was made log-source precise.

**A3. Assessed-but-untaught: the new scope hunt needs a taught query shape (fixed).**
The new `rw-qf1` query_fill asks the student to write a Sentinel `SecurityEvent` hunt. Reading 5 now teaches the exact shape it needs (the `SecurityEvent` table, `EventID`, `EventData has`, `dcount()`/`make_set()` grouped by `SubjectAccount`) with a worked `codeExample`, so nothing in `rw-qf1` is untaught.

### Medium

**A4. RDP brute force: wrong logon-type expectation for NLA (fixed).**
Reading 2's table implied the failure burst would be visible as type 10. With Network Level Authentication enabled (the default on modern Windows), the credential is checked before a session exists, so failures land as **Event 4625 logon type 3**, not type 10 (community-confirmed; Microsoft 4625 field docs). A brute-force rule counting only type 10 misses the burst. Added to Reading 2 text, the table, and the `rw-r2` labs. `rw-q1`'s stem now notes "no failed logons precede the success", which is what actually distinguishes the edge-exploit case from brute force.

**A5. Edge-device examples were vague; real advisories are more teachable (fixed).**
Reading 2 mentioned "Citrix Bleed" and "Ivanti" in passing with a broken sentence. Replaced with the concrete mechanism from the CISA advisories: LockBit 3.0 via **Citrix Bleed (CVE-2023-4966)** stealing NetScaler **session tokens** (login/MFA bypass), and Akira via **SonicWall SSL-VPN (CVE-2024-40766)** often using credentials stolen before the fix. Added the operational lesson that patching closes the hole but does not invalidate what was already taken, which also sets up A1's credential-reset logic.

**A6. Scheduled-task and DCSync detections named no event IDs (fixed).**
Reading 3 cited Event 4698 for scheduled tasks; it now also names the `Microsoft-Windows-TaskScheduler/Operational` Event 106 fallback for when the audit policy is off, and tags the technique T1053.005 / Run key T1547.001. Reading 4 now names the DC's **Security Event 4662** replication-rights access as the DCSync detection point, which the DCSync checkpoint and matching task both rely on.

**A7. "Exfiltrate a small proof sample" overstated the old model (fixed).**
Reading 7's description of the 2019-2021 model as "exfiltrate a small sample as proof" was tidier than reality; early double extortion stole opportunistically. Softened, and added the documented **BianLian** move to exfiltration-only extortion (CISA/ACSC AA23-136A) as the real-world anchor for the "encryption-optional" trend.

**A8. The response stopped at the ransom note; no recovery doctrine (fixed, and see new tasks).**
Reading 8 ended on the pay-decision governance line without the CISA checklist's actual response order. Added: contain-first (isolate via EDR or disconnect; power down only if you cannot disconnect, to preserve volatile memory evidence); scope by the deployment push, not the alerts; then the five-step evict/recover order (contain → protect backups off-domain with pre-intrusion restore points → eradicate persistence and close entry → rotate all privileged/service accounts and **reset krbtgt twice** → restore critical-first), plus law-enforcement reporting and breach notification as leadership/legal obligations. The playbook table's actions were updated to match, and shadow-copy deletion was re-filed to the Impact row (ATT&CK T1490), where it belongs.

### Low

**A9. ATT&CK v19 IDs are correct (verified, no change needed).** The room already uses `T1685` and `T1685.005` under Defense Impairment (TA0112), matching ATT&CK v19 (released 2026-04-28, which split Defense Evasion into Stealth TA0005 and Defense Impairment TA0112, merging the old T1562 into T1685). `attack.ts` carries these IDs. Technique tags for the new/edited readings (T1053.005, T1547.001, T1567.002) were added explicitly.

**A10. Broken-sentence artifacts from an earlier em-dash removal (fixed).** Several readings had full stops mid-clause ("...process-tree signature: ... email. Is exactly..."). Repaired in Readings 1, 2, 5, 6, 8. No em dashes were introduced.

**A11. Exfiltration volume consistency (fixed).** `rw-q3` said "roughly 85 GB" while the `rw-la2` event's `bytes_out` is 91,483,200,000 (~85 GiB / ~91 GB). Changed q3 to "roughly 91 GB" to match the decimal reading of the field.

## 3. Pedagogy findings

**P1. One idea over-assessed, the response under-practised (addressed).** The "detect a masqueraded process + LOLBin" skill was tested well across la1 and la3. But "what do I do now" was only ever multiple choice (`rw-q3`), and the single highest-value SOC skills in a ransomware case (hunt the blast radius, order the recovery) were taught and never performed. Added `rw-qf1` (write the scope hunt) and `rw-o2` (order the eviction/recovery), both using existing task types.

**P2. Difficulty curve (sound, kept).** Readings + labs (Understand) → questions (Apply) → log analyses (Apply/Analyse) → verdict (Evaluate) → new query/ordering (Create/Analyse) at the boss. The boss gate now requires synthesis (a correct hunt and a correct recovery order), not just a recalled flag value.

**P3. Flag placement (fixed).** `rw-f1` sat after `rw-q3`, so the flag about the first user-reported encrypted file came after the whole-incident containment question. Moved `rw-f1` to directly follow the impact log (`rw-la3`) and added `logTask: "rw-la3"` so `resolveFlagLog` pins the correct event rather than guessing the nearest log (this is the exact bug the room-flag-log memory warns about).

**P4. Labs never leak (verified).** All briefing labs run on a separate fictional case (Meridian Freight, hosts WKS-FIN-0912/SRV-LOG-07/DC-MER-01, account m.pratt, extension `.locked77`, tool MEGAcmd) that shares no value with any graded task. Each lab was written against the current reading text.

## 4. Mission realism

**G1. The gates now trace a real response, not task types.** Intel Gate (get in) → Breach Gate (foothold + first dump) → Spread Gate (lateral + tear-down) → Exfil Gate (the highest-value window) → Final Gate (impact, scope, contain, hand off). The Final Gate is where the new tasks land, so the student ends by doing the back half of a real incident: scope the push fleet-wide, then evict and recover in a safe order, then hand facts (not the pay decision) to IR.

**G2. Comparison with a real ransomware response.**

| Real step (CISA checklist) | Before | Now |
|---|---|---|
| Detection & analysis of precursors | Strong (la1, la3, readings) | Strong |
| Scope the blast radius | Taught in passing | `rw-qf1` writes the SecurityEvent hunt |
| Contain (isolate; power down only if you cannot disconnect; preserve memory) | Partly in q3 | Reading 8 + q3 + `rw-o2` |
| Protect backups / clean restore points | Absent | `rw-o2` step 2 + Reading 8 |
| Eradicate persistence, close entry | Absent | `rw-o2` step 3 + Reading 8 |
| Rotate credentials incl. krbtgt twice | Absent (and la1 said rotate too early) | Reading 8 + `rw-o2` step 4; la1 corrected |
| Recover critical-first, watch for reinfection | Absent | `rw-o2` step 5 + Reading 8 |
| Report to law enforcement / notify breach | Absent | Reading 8 governance paragraph |

## 5. New graded tasks

| id | type | XP | what it adds |
|---|---|---|---|
| `rw-qf1` | query_fill (KQL) | 30 | Write the Sentinel `SecurityEvent` hunt that counts every host where the deployment scheduled task was created, grouped by account: scoping by the push, not the alerts. |
| `rw-o2` | ordering | 35 | Order the five eviction/recovery steps so the plan does not undo itself (contain → protect backups → eradicate → rotate incl. krbtgt twice → restore). |

`rw-f1` (flag, 25 XP) was moved to follow `rw-la3` and pinned with `logTask`. Room XP updated 620 → **685** (equals the task-XP sum), `estimatedMinutes` 105 → **115**. No new log events were added (both new tasks reuse the existing case), so the log-field gate is unaffected.

## 6. Checks

- `npx tsc --noEmit -p .` ... clean.
- `npx eslint` on both edited files: clean.
- `npx vitest run src/lib/rooms` ... 59 passed.
- Temporary `gradeTask` test for `rw-qf1`, `rw-o2`, `rw-f1` (all-correct, partial, wrong-order, flag) ... 5 passed, then deleted.
- `npx tsx scripts/validate-content.mjs` ... only "roomsMeta stale" errors (this room and the two others other agents are editing); no content defect for this room; XP sum matches.
- `node scripts/validate-log-fields.mjs` ... PASS, no new field violations.

## 7. Left open

- **roomsMeta.ts regeneration** is Tal's to run (`npx tsx scripts/generate-rooms-meta.mjs`); the two added tasks will not render in Operation Mode until it is regenerated, because `getRoomExperience` compares station task ids against the room task list and `validate-content` flags the 18-vs-20 mismatch until then.
- **Room narration** (`roomNarration.ts`) still maps `rw-r1`..`rw-r8`; the reading edits change the narrated text, so those readings' audio hashes are now stale and the audio would need re-generation if narration is expected to match the new wording.

## Sources

- CISA #StopRansomware: Ransomware and Data Extortion Response Checklist (cisa.gov/stopransomware/ransomware-guide); AA24-109A (Akira, Cisco/SonicWall VPN initial access); AA23-325A (LockBit 3.0 / Citrix Bleed CVE-2023-4966, session-token theft); AA23-136A (BianLian, shift to exfiltration-only extortion).
- MITRE ATT&CK v19: TA0112 Defense Impairment; T1685 Disable or Modify Tools and T1685.005 Clear Windows Event Logs; T1490 Inhibit System Recovery (Impact); T1053.005, T1547.001, T1567.002, T1003.001, T1003.006, T1021.002, T1047.
- Microsoft: Windows Security Event 4698 (scheduled task created), 4697 (service installed), 4662 (directory-service access), 4624/4625 logon types and the NLA type-3 behaviour; krbtgt double-reset guidance (password history of 2); Sentinel `SecurityEvent` advanced-hunting schema.
