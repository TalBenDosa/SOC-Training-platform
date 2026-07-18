# HACK THE SOC — End-to-End Platform Review (PM)

*Commissioned as a comprehensive, cross-functional pass: content correctness, pedagogy, learner experience, UX/UI, gaps, and further-development. Five specialist agents reviewed the whole platform; this document synthesizes their findings into one prioritized plan.*

---

## Executive verdict

**The platform is fundamentally strong and does not need a rewrite.** The 62-room prerequisite graph, the 17-lesson zero→analyst Learning Path, the Dashboard's SLA/pacing/Easy-mode design, the no-hints discipline, and the incident-report loop are all thoughtfully built — and technical accuracy across ~28,000 lines of content is unusually high.

**The damage that exists is mostly self-inflicted and narrowly scoped:** onboarding copy and leftover scaffolding that no longer match good product decisions already made, plus two failure mechanics that can make a beginner feel punished. Three independent reviewers (pedagogy, engagement, UX) converged on the *same two* issues — a strong signal they are the real priorities.

---

## Already fixed this session (correctness — done + tsc-clean)

Before this review, two content-correctness rounds and this review's own sweeps auto-corrected:
- **Log realism** across all scenarios + the Raw-log serializer (vendor-accurate syslog/XML/JSON per source).
- **~30 veteran content fixes** across lessons + rooms (invalid Kerberos etype `0x13`; `0x18`≠AES; T1055.001→.002; T1566.002→.001; T1528↔T1550.001 swap; T1046 rename; epoch/timeline errors; Azure AD→Entra ID & Defender XDR currency; 6 no-hints "self-incriminating value" leaks).
- **Event ID ↔ description consistency sweep:** 3 mismatches fixed — `b_edr_08` (4698 "created" → 201 "task ran"), `b_sysmon_pipe_01` (Sysmon 17 pipe mis-typed `net_connection` → `process_create`), `gl_c2` (robocopy Sysmon-1 mis-typed `registry_set` → `process_create`). `scenarios.ts` was fully audited: **zero** Event-ID mismatches.
- **Fairness fix (MITRE consistency):** the malicious email-forwarding-rule behavior was tagged `T1137.005` in `scenarios.ts` but `T1114.003` in rooms + the correlation engine — a student tested on a label they were never taught. Standardized both scenario events on **T1114.003** (+ added the Collection tactic mapping).
- **No-hints rule** hardened into `soc-content-writer` and `soc-room-log-auditor` so the "self-incriminating value" pattern can't be re-authored.

---

## 🔴 The two headline issues (flagged independently by 3 reviewers)

### 1. Room failure is punitive: 65% gate → full redo + global XP clawback
`src/app/(app)/rooms/[id]/RoomClient.tsx` (lines 18, 143–178)
- Below **65%**, the room deletes *all* progress (including completed readings) and forces a redo **from task 0** — no "retry just the missed questions".
- XP is added to the **global** `soc_total_xp` live, then on failure `addXpToTotal(-newXp)` silently subtracts it back — a visible give-then-take-away, and the failure screen never says "your total just dropped by X".
- Most task types (`question`, `analyst_choice`, each `log_analysis` sub-question) are **one-shot**: confirm → answer locked, 0 XP on a wrong first guess, no retry. Only `flag` retries; `matching`/`ordering` give partial credit.
- **Worst where it matters most:** Room 1 (`intro-cybersecurity`) has ~6 gradeable items, all first-exposure. Two wrong first guesses already drops a total beginner below 65% — on their very first room, before they've learned the one-shot format.
- **The platform already contains the healthier pattern:** the Learning-Path quiz gate (`learn/[slug]/[lesson]/page.tsx`, 70%) resets only the quiz, keeps the readings, and never claws back XP. Rooms should adopt it.

**Recommended fix (P0):** don't debit already-earned XP on failure (withhold the completion *bonus/badge* until a pass instead); allow re-answering a missed question after its explanation; replay only the missed tasks, not the whole room; a "practice pass" grace on a student's first 2–3 rooms. Reframe copy: *"You've got most of it — review these 3 and you're through,"* not *"Room not passed, start over."*

### 2. The Dashboard "missed attack" penalty is silent and teaches nothing
`src/app/(app)/dashboard/useLiveEvents.ts` (lines ~1219, 1290–1339); state unused in `dashboard/page.tsx`
- When the 8-minute SLA expires uncaught: `setMissedAttack(true); fnCount++; sessionXp -= 5`.
- **`missedAttack` / `clearMissedAttack` / `activeIncident` are exported by the hook and consumed *nowhere*** (grep-confirmed). A stale comment references a "you missed it" UI that doesn't exist. The student's XP just silently drops by 5 with no toast, no explanation, no debrief → reads as *"my XP randomly went down,"* eroding trust in the whole XP system.
- Pacing itself is **healthy** (verified first-hand): 8-min detection window, report-writing untimed, attacks arrive 2–3 min in with 2–4 min between phases. The problem is purely the missing feedback loop.

**Recommended fix (P0, near-zero effort):** wire the already-computed `activeIncident.title` + `eventIds` into a "You missed one — here's what it looked like" debrief banner, turning the miss into a worked example. Drop the −5 XP in favor of a neutral "missed" counter, or at least explain it.

---

## Findings by lens (prioritized)

### Pedagogy & sequencing (`soc-pedagogy-architect`)
- 🔴 **Both headline issues above.**
- 🔴 **Learning-Path lesson 8 is out of order** (`builtinLessons.ts` lines 11–153): it teaches JA3 TLS fingerprints, DGA entropy, and full **Splunk SPL** queries *before* lessons 9–10 ever explain what a SIEM or query language is — and is a 5-topic density spike among 1–2-concept neighbors. Move later (after SIEM/EDR) or split into 2–3 lighter lessons.
- 🟡 **"Analyst mindset" arrives too late in both tracks.** The `analyst-mindset` room (`rooms-batch-14-r2.ts`) is `beginner` and gated only on `soc-structure`, but it's defined ~48 rooms deep; the "Continue" recommender in `rooms/page.tsx` walks **file order, not prerequisite depth**, so a linear learner won't see it until after dozens of advanced rooms. Reorder the recommender by prereq depth, or move the room earlier. Content about handling ambiguity/being wrong is most valuable *before* a student hits the failure mechanics.
- 🟡 No hard mastery gate ties the Dashboard to Rooms/Path progress (mitigated by the Welcome modal + Easy default).
- ✅ Rooms DAG, Learning-Path arc, SLA/pacing, and the incident-report loop are sound and well-scaffolded.

### Engagement & motivation (`soc-engagement-designer`)
- 🔴 Both headline issues (framed as "give-then-take-away" and "silent penalty").
- 🟡 **Inconsistent forgiveness confuses beginners:** `FlagPlayer` retries infinitely; `QuestionPlayer`/`LogAnalysisPlayer`/`AnalystChoicePlayer` lock on first try; `matching`/`ordering` give partial credit — with no signal telling the student which is which.
- 🟡 **Streak has no grace/warning:** a multi-day streak vanishes silently with no "ends today" nudge and no streak-freeze.
- 🟡 **False-positive stat** is skinned as a red "failure" even though over-caution is the safer SOC error — reframe as a neutral "caution rate, aim < 20%".
- ✅ Genuinely excellent: `EarnMoment` level-up toast, `IncidentReportModal` (draft auto-save + unlimited resubmit, no clawback), `CompanyClearedModal`, honest rank ladder (no fake leaderboard), partial credit in matching/ordering.

### UX / UI (`soc-ux-ui-reviewer`)
- 🔴 **Onboarding teaches a UI that was removed.** `SOCWelcomeModal` tells new users to *"press the amber ⚠ Suspicious button"* — the row-verdict UI was deliberately removed (it would reveal ground truth). First thing every user reads sends them hunting for a nonexistent button. Rewrite step 2 to the real flow (read log → conclude silently → state it in the Incident Report), and delete the dead `classify`/`fpCount`/`avgCatchMs` plumbing so it isn't re-wired against the wrong model.
- 🟡 **Decorative-but-dead controls erode trust:** Topbar search has no `onChange` (and duplicates the *working* feed search right below it on Dashboard); notification bell shows a hardcoded "7"; several dashboard panels imported but never rendered.
- 🟡 **"Admin Panel" sits in the learner nav** with a fake "✓ Admin" badge — move it out / de-emphasize.
- 🟡 **Accessibility:** hover-only tooltips (`LogSourceCard`, `HeaderTip`) have no click/touch fallback (the `Term.tsx` component already does this right — copy that); the live event table lacks `overflow-x-auto` for tablet widths.
- 🟡 Pass thresholds differ (Rooms 65 / Report 60 / Quiz 70) and difficulty-badge colors diverge on the Learn page — unify or explain.
- ✅ "Start here / Continue" banner, resumable room progress with clear "Task X of Y", honest Progress page, guided incident report, "Verify with IT" affordance.

### Gaps, alignment & development (`soc-alignment-auditor`)
- ✅ **Coverage is strong** — prior gap-fill rounds (batches 14/15/16) closed the big holes (K8s, AWS/GCP/Azure IAM, OAuth consent, MFA fatigue, DNS tunneling, LOLBins, NTLM relay, Kerberos family). No "tested-but-never-taught" technique gap remained except the T1137/T1114 label (now fixed).
- 🟡 **No query-writing practice.** KQL/SPL is taught in prose and read in multiple-choice, but no task type makes the student *write* a query — the single biggest NICE-competency gap. Spec: a `query_fill` fill-in-the-blank task graded by string/AST match.
- 🟡 **Foundation-tier attack pool is thin** — only 2 stories (`phishing-malware`, `usb-malware`) for the entire Easy difficulty vs 14+ advanced. A beginner sees the same 2 attacks repeatedly. Grow to 5–6.
- 🟢 `nac-masterclass` and `soar-automation` rooms are self-contained but never reinforced by a dashboard scenario (low priority).

---

## Further-development backlog (build list)

| Priority | Item | Impact |
|---|---|---|
| **P0** | Soften Room-failure mechanic (no XP clawback, retry only missed tasks, reframe copy) | Removes the biggest "afraid to fail" moment, at the point beginners hit it first |
| **P0** | Wire `missedAttack` → a "you missed one" debrief banner; drop/normalize the −5 XP | Turns a silent trust-eroding penalty into a teaching moment (near-zero effort) |
| **P0** | Rewrite `SOCWelcomeModal` step 2 to the real (no row-verdict) flow; remove dead `classify` plumbing | Fixes the first thing every user reads |
| **P1** | Resequence/split Learning-Path lesson 8 (SPL/JA3 after the SIEM lesson) | Removes a real difficulty cliff |
| **P1** | Reorder the room "Continue" recommender by prerequisite depth; surface `analyst-mindset` early | Puts foundational mindset content where it helps |
| **P1** | Give MCQ-type tasks a one-retry-after-nudge or partial credit (match `FlagPlayer`/matching) | Consistent, fairer scoring |
| **P1** | Grow the foundation-tier attack pool to 5–6 stories | Variety for beginners on Easy |
| **P2** | Add a `query_fill` (KQL/SPL) task type; retrofit 2–3 SIEM rooms | Closes the largest competency gap |
| **P2** | Remove decorative-dead controls (Topbar search, notif badge, orphaned panels); move Admin out of learner nav | Restores UI trust |
| **P2** | Accessibility: click/touch tooltip fallback; table `overflow-x`; streak-at-risk nudge + freeze; reframe FP stat | Polish + reach |

---

## Patterns & rules established (to keep the platform consistent)

1. **No-hints, two forms:** raw log fields must never (a) contain conclusion/analysis fields (`data.anomaly`, `data.recommendation`), nor (b) carry a **self-incriminating value** in a legitimate field (`SubjectUserName: "backdoor-admin"`). *A raw field value must never be more informative than what a real attacker would leave.* — now encoded in `soc-content-writer` + `soc-room-log-auditor`.
2. **Each source reports only its own layer** — EDR ≠ Windows Event Viewer ≠ firewall ≠ Sysmon; the Raw serializer renders each vendor's true wire format.
3. **Event ID must match the described action** (4624 success / 4625 fail / 4698 created vs 201 ran, etc.).
4. **One MITRE ID per behavior across all surfaces** (the T1137/T1114 lesson).
5. **Failure should coach, not punish** — withhold bonuses, don't claw back earned progress; every miss gets a debrief.
6. **Currency:** carry both the current and legacy vendor names (Microsoft Entra ID (formerly Azure AD); Defender XDR (formerly M365 Defender)).

---

## Overall

A genuinely well-built platform whose remaining risks are concentrated in a handful of scoped, high-leverage fixes — three of them (P0) are near-zero-effort because the good design already exists elsewhere in the same codebase and just needs to be applied consistently. Closing P0 + P1 moves the experience decisively from *"a test you're afraid to fail"* to *"a game you want one more round of,"* without adding a single new feature.

---

## P2 — implemented (2026-07-17)

- **query_fill task type** (`data/rooms.ts`, `components/rooms/TaskPlayer.tsx`) — a new fill-in-the-blank KQL/SPL task with per-blank proportional partial credit, retrofitted into `sentinel-fundamentals` (KQL — failed logons) and `detection-engineering` (SPL — compiles the room's own Sigma rule). Closes the "never writes a query" competency gap.
- **Decorative-dead controls removed** — Topbar's non-functional search/notification-badge/threat-icon deleted; 9 orphaned dashboard components (never imported anywhere) deleted; "Admin Panel" moved out of the primary learner nav into a small de-emphasized footer link, and the misleading "✓ Admin" role badge removed.
- **Accessibility** — `LogSourceCard`/`HeaderTip` tooltips got a click/touch fallback (matching the existing `Term.tsx` pattern); the live event table got `overflow-x-auto` + a `min-w` for narrow viewports.
- **Streak-at-risk nudge + freeze** (`progress/page.tsx`) — a same-day banner when a streak is alive only via yesterday's grace period, plus up to 2 streak freezes/month that retroactively cover a missed day (verified live: correctly triggered on a synthetic 1-day streak).
- **False-positive stat reframed** — "False Positive / Negative" (red, `XCircle`) → "Caution Rate / Missed Attacks" (neutral amber, `Scale`) with coaching copy ("a little over-escalation beats a miss — aim under 20%").
`tsc` clean; query_fill grading, streak banner, and Caution Rate tile all verified live in-browser.

---

## classify() cleanup — follow-up (2026-07-17)

Tracing every consumer of the dead `classify()`/`fpCount`/`perSourceAccuracy`/`perTechniqueAccuracy` state (deferred in P2) surfaced something more serious than dead telemetry: **`markCaught()` — the function that stops the SLA timer and registers a catch — was never called from anywhere in the app.** A student who correctly identified and reported an attack got no credit for it: the SLA timer kept running in the background, and the miss-timer would still fire later and silently log it as a **missed** attack (`fnCount++`) — which would also have made the P0.2 "you missed one" debrief fire on attacks the student actually caught. This wasn't cosmetic; it undermined this session's own P0 fix.

**Fixed:**
- `dashboard/page.tsx`: `IncidentReportModal`'s `onPassed` now calls `live.markCaught()` with the active incident's event id — a passing report **is** the catch, registered for real.
- `useLiveEvents.ts`: deleted `classify()`, `groundTruth()`, `TECHNIQUE_EXPLANATION`, `ClassificationResult`, and the state only `classify()` fed (`correctCount`, `totalClassified`, `fpCount`, `perSourceAccuracy`, `perTechniqueAccuracy`) — all unreachable without the deliberately-removed per-event verdict UI. Added a real `attacksPresentedCount` (incremented once per non-FP incident opened) so `detectRate = caught/presented` is now honest. `attacksCaughtCount` moved into `markCaught()` itself, guarded once-per-incident.
- `SiemStats.tsx` / dashboard `page.tsx`: removed the now-truly-dead "FP Rate" chip and its props.
- `progress/page.tsx`: recalibrated the Incident-Response catch-speed scoring to the real 8-minute SLA window (was hardcoded to a stale 180s/30s pair that predates this session's SLA increase — now genuinely exercised since `avgCatchMs` populates for real). Rebuilt "Log Analysis" and "MITRE Knowledge" skills to derive from real Learning-Room task performance (`perTaskXp` × `ROOMS`) instead of the dead Dashboard per-event accuracy — the only honest signal available now that the per-event verdict UI is gone. Dropped "Threat Intel" (no honest substitute) rather than show a fake number. Redid the "Caution Rate" tile from P2 into a real "Catch Rate / Missed Attacks" once `attacksCaughtCount`/`attacksPresentedCount` were wired for real. Fixed the "Sharp Eye" badge, which was unreachable (required `fpRate <= 10`, always false).
- Flagged, not actioned: two orphaned API routes (`/api/dashboard/review-notes`, `/api/scenarios/[slug]/review-report`) from the same removed-verdict-UI lineage — zero callers found, left for a dedicated cleanup pass.

`tsc` clean. Verified live: report-modal opens safely with no active incident (no-op path); injecting a synthetic session end-to-end produced real, correct values — Log Analysis 20%, MITRE Knowledge 20%, Threat Hunting 100%, Incident Response 100%, Catch Rate/Missed Attacks "100% / 0", and the previously-unreachable "Sharp Eye" badge unlocked.
