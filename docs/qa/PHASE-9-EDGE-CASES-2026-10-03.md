# QA Phase 9 — Edge Cases

**Date:** 2026-10-03 · **Scope:** `src/lib/team/**`, `src/app/api/team/**`, `src/app/(app)/team/[id]/**`, migrations 0071–0089, with focus on the new graded "good catch" report model.
**Method:** code review + synthetic probes (`computeReport` run against ~25-event logs; two regexes timed). Every finding verified in source. CONFIRMED = read/probed; POTENTIAL = needs a runtime/DB check.

## Status summary

Several findings were in **code shipped earlier this session** (the graded report model) or are serious robustness bugs in the report route — those are **FIXED now** and verified. The rest are reported for approval.

| ID | Sev | Finding | Status |
|---|---|---|---|
| P9-01 | HIGH | Quadratic regexes in `computeReport` → one player's 16 KB finding makes the debrief take 164 s > 60 s route cap; report 500, no cache, no XP | **FIXED** |
| P9-02 | MEDIUM | Detection time used the escalation even when an earlier TP/suspicious mark existed → inflated dwell/SLA (T1 marks before escalating) | **FIXED** |
| P9-04 | MEDIUM | One event with `payload = null` throws → report permanently 500 | **FIXED** |
| P9-05 | MEDIUM | SLA judged by max severity but dwell measured from the first (low-sev recon) log → kill-chains almost always "past SLA" | **FIXED** |
| P9-F | MEDIUM | MTTD counted escalations only while "detected" counted marks → "1/1 detected" shown next to "MTTD —" | **FIXED** |
| P9-cov | LOW | `hostCoverage`/`techCoverage` computed but never used; comment claimed logs+hosts+techniques | **FIXED** |
| P9-03 | MEDIUM | Reassigning a member re-scores their whole shift by the final role; reassign → observer drops them from the report & gives 0 XP | fix on approval |
| P9-06 | MEDIUM | `escalation.bounced`/`resolved` check only that an escalation exists — no latest-state/ownership check; two T2s can both resolve & bounce | fix on approval (migration) |
| P9-07 | MEDIUM | `reassign` / `members` routes ignore the `appendSystemEvent` result → on append failure the role change/removal lands but no `member.*` event; other clients never refresh | fix on approval |
| P9-08…P9-16 | LOW | see below | fix on approval |

---

## Fixed this session (verified)

| ID | File : line | Fix applied |
|---|---|---|
| P9-01 | `computeReport.ts:164` `IOC_LIKE`, `:259` report-IOC regex, `huntQualityScore`/`reportQualityScore` | Bounded every quantifier (RFC label ≤63, TLD ≤24, hash ≤128) so no catastrophic backtracking; added `clip(text, 2000)` on all free-text before regex/`wordCount`. A 16 KB finding was ~110 ms/run → now negligible. |
| P9-02 | `computeReport.ts:514` | `detTs = earliest of (escalation, TP/suspicious mark)` instead of "escalation if any, else mark" — the T1 flow marks before escalating, so the old code charged report-writing time to the SLA. |
| P9-04 | `computeReport.ts:371` | Normalize at entry: `events = rawEvents.map(e => e.payload == null ? {…, payload:{}} : e)` — one bad row can no longer 500 the whole report. |
| P9-05 | `computeReport.ts` grade block | `slaMet`/timeliness now measured from `slaAnchor` = the first log at the incident's MAX severity (not the first recon log). `dwellS` (MTTD) still from the first log. |
| P9-F | `computeReport.ts` `firstDetect` | Now `min(firstEscalation, firstTP/suspiciousMark)` so MTTD and "detected" use the same basis. |
| P9-cov | grade block + `TeamReport.tsx` | Grade `coverage` now blends log + host + technique coverage (the axes the incident has); UI shows `hosts %` and `tech %` too. |

New tests: 3 added (earliest-action detection, SLA anchor on a mixed-severity incident, null-payload no-throw); one existing MTTD test updated to the corrected behavior. 77 report tests pass; snapshot updated.

---

## 1. Boundary / empty input — remaining (fix on approval)

| ID | Sev | File : line | Repro | Impact | Fix |
|---|---|---|---|---|---|
| P9-08 | LOW | `computeReport.ts` `label.slice(0,140)`; `pause/route.ts` `detail.slice(0,200)` | A description with an emoji at the slice boundary leaves a lone surrogate | Postgres jsonb rejects it → report cache upsert fails (logged) and rebuilds each view; for pause it would 500 `team_transition` | `Array.from(s).slice(0,n).join("")` |
| P9-09 | LOW | `computeReport.ts` `triageMin` uses `feedSev.get(eid)` un-lowercased while `sevOf` lowercases | A feed severity `"Critical"` | Time-to-triage cell silently `null` (feed severities are lowercase today, so latent) | Use `sevOf(eid)` |
| P9-10 | LOW | `format.ts:7` `hostKey` splits on `.` → `hostKey("10.0.0.5")` = `"10"` | An IP as hostname | Every IP collapses to its first octet; isolation validation would mis-judge (no story uses an IP hostname today) | Skip the split when the host is an IP |

**Probed OK (no bug):** empty events/roster, no `occurred_at`, never-started session, zero attack logs, a log with no severity/hostname/technique (coverage → `null`, no divide-by-zero), escalation of an unknown id, duplicate feed ids, a `"constructor"` severity. The 20 000-event player cap prevents `Math.min(...spread)` stack overflow.

## 2. Empty states (fix on approval)

| ID | Sev | File : line | Fix |
|---|---|---|---|
| P9-11 | LOW | `SituationBoard.tsx:37` — `players` filters only instructor/observer, keeps `left` in "Online x/N" + load map | Add `status !== "left"` |
| P9-12 | LOW | `computeReport.ts` — `incidents.slice(0,12)` with no "showing 12 of N"; later missed incidents hidden | Show the remainder or sort misses first |

## 3. Concurrency

**Verified OK:** `apply_session_action` takes `team_lock_session` first (claim/release/pause/seq serialized); claim conflict → `claim_held`; second ack → `case_owned`; 2 s idempotency key; pause/resume via atomic `team_transition` (repeat = noop); single-seat unique index + roster-cap trigger.

| ID | Sev | File : line | Repro | Impact | Fix |
|---|---|---|---|---|---|
| P9-06 | MEDIUM | `0088_team_qa_fixes.sql:106-122` `team_validate_action` | `escalation.bounced`/`resolved` require only that an escalation exists | Two T2s can both resolve & bounce the same case; action after a terminal state accepted; any T2 resolves another's case | Reject when the latest lifecycle event is bounced/resolved; require ownership for resolve (migration) |
| P9-07 | MEDIUM | `reassign/route.ts`, `members/route.ts` POST+DELETE | `appendSystemEvent(...)` result ignored, route returns `ok:true` | On append failure the DB change lands but no `member.*` broadcast → other clients & the removed user never refresh | Check `.ok`, retry or return a warning |

**POTENTIAL:** members DELETE doesn't release the member's claims/case ownership (blocks others up to the 5-min claim TTL); `start` seeds the timeline before `team_transition`, so a `not_ready` race leaves a feed sized for the old roster and the retry skips seeding (`count>0`).

## 4. Time / clock / SLA

Midnight & timezones safe (epoch ms throughout); `pausedSpans` agree with SQL `team_active_ms`; negative dwell clamped. **P9-02 / P9-05 / P9-F fixed above.**

| ID | Sev | File : line | Impact | Fix |
|---|---|---|---|---|
| P9-13 | LOW | `slaSecFor` (1/3/10/30 min triage) vs `slaForSev` (5/15/30/60 min incident) | Two SLA tables read as contradictory ("within SLA" in one, "past" in the other) | Name them distinctly in the UI, or unify |
| P9-14 | LOW | `SituationBoard.tsx:40-49` `oldestUnacked`/`mtta` use raw `now - occurred_at` (not pause-aware) | After a 30-min pause the Manager sees "oldest unacked 35 min" | Use `activeMs` with `pausedSpans` |
| P9-15 | LOW | `TeamReport.tsx:46-50` HotWash `dwellS` = first escalation − first attack log | Disagrees with graded per-incident dwell; a benign false-alarm escalation counts | Drive from `team.incidents` |

## 5. Unicode / RTL

| ID | Sev | File : line | Impact | Fix |
|---|---|---|---|---|
| P9-16 | LOW | `TeamReport.tsx:399-406` `exportCsv` — Blob has no UTF-8 BOM | Excel on Windows shows Hebrew names as mojibake (formula-injection guard itself is correct) | Prepend `"﻿"` to the CSV |

**Verified OK:** tenant name validation strict ASCII; Hebrew/bidi/emoji labels pass through `computeReport` without throwing; display-name fallbacks safe.

## 6. Mid-action session expiry / membership

**Verified OK:** `apply_session_action` re-checks membership + org affiliation under the lock every call (removed/expired → `not_a_member`, friendly UI); JWT-expired → `auth_required`.

| ID | Sev | File : line | Impact | Fix |
|---|---|---|---|---|
| P9-03 | MEDIUM | `computeReport.ts` (final roster role only), `reassign/route.ts` (allows `observer`), `teamXp.ts:27` | A member who did real work then reassigned is judged by the final role; reassign → `observer` drops them from the report and gives 0 XP | Replay `member.role_changed` and score per role-at-time; or forbid reassigning to observer once the member has acted |

---

## Recommended next (on approval)
1. **P9-03** (role-at-time scoring) + **P9-06** (escalation ownership/state, migration) + **P9-07** (append result) — the MEDIUMs with real behavioural impact.
2. Batch the LOWs (P9-08…P9-16) — all small, low-risk (surrogate-safe slice, `sevOf`, CSV BOM, pause-aware SituationBoard, left-member filters, incident list remainder).
