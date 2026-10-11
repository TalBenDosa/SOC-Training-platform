# Content Feedback & Implementation — HACK THE SOC

_Four-dimension content audit of the platform's learning material, and the full record of what was implemented in response._

**Date:** 2026-08-06
**Scope:** learning content only (rooms, lessons, scenarios, live-dashboard authoring) — "what the student learns."
**Method:** four specialist agents each swept the whole curriculum from one angle, then findings were synthesized and executed.

---

## 1. Verdict

**Overall: ~7.5 / 10** — a strong professional foundation; the one structural weakness was *how* the content was delivered (too much passive reading; parallel content systems competing for attention), not its correctness.

| Dimension | Score | One-line |
|---|---|---|
| Technical accuracy & currency | 8.3 | Event IDs, MITRE, raw fields nearly flawless |
| Theory ↔ practice alignment | 8.0 | Most mechanisms covered; only narrow gaps |
| Pedagogical progression | 7.0 | Rooms spine excellent; parallel paths weaker |
| Engagement | 6.5 | Strong mechanics, but passive/repetitive reading template |

---

## 2. What the audit found

### Strengths (kept)
- **Rare accuracy:** Kerberos (4768/4769, `0x17=RC4` vs `0x12=AES256`), `GrantedAccess: 0x1FFFFF` on lsass consistent across dozens of rooms, deliberate TLS "FP trap."
- **Capstone rooms** (`investigate-alert-workflow`, `incident-report-writing`): 7-step investigation, "5 Whys," a `query_fill` that forces writing KQL.
- **Enforced mastery gate:** `ROOM_PASS_THRESHOLD = 0.65` in code; a failed room doesn't unlock dependents.
- **Motivation mechanics:** XP / ranks / streak+freeze / data-derived skills radar / certificates.
- **Live dashboard:** SLA timer, threat-actor + victim rotation.

### The three cross-cutting problems (flagged by multiple agents)
1. **Too much passive reading.** Fixed template of 3 long readings in a row (0 XP, no gate) before the first interaction; `batch-13-r1` had 10 consecutive readings; "Mark as Read" clickable without reading a word.
2. **Three parallel content systems.** Sidebar gave "Learning Rooms," "Dashboard," "Learning Path" equal weight, but only Rooms has a mastery gate — a beginner could learn a shallower version via the reading library without realizing Rooms is the graded spine.
3. **No explicit theory→practice transfer moment.** The capstone teaches exactly what the dashboard demands, but room completion only ever pointed at "the next room."

### Narrower findings
- IBM-2023 breach stats presented as fixed-year facts (and as an MCQ answer) — would age into being wrong.
- `crowdstrike.event.*` vs `crowdstrike.*` inconsistency between rooms.
- Theory gaps: vCenter/ESXi + T1489, "permitted ≠ authorised," setgid crontab, "Tier" ambiguity (SOC Tier 1/2/3 vs AD Tier 0/1/2), two Kerberos rooms with no explanation.

---

## 3. What was implemented

All committed and verified (`tsc` / `validate:logs` / `build` green on each).
Commits: `18caaef` → `086e07e` → `0bbd332` → `8b0c6f4`.

### Engine / UX
- **Active reading (P0.1/P0.2).** `ReadingTask` gained an optional **ungraded `checkpoint`** (inline recall question) + symbolic `xp`. `ReadingPlayer` now gates "Mark as Read" behind a scroll-to-end sentinel **or** a length-scaled dwell (5–18 s), renders the checkpoint (must answer correctly to continue), and shows the `+XP` reward. `RoomClient` awards that XP to the **global/rank total only** — never the room score — so the 65 % mastery gate is untouched (`taskMaxXp` for reading stays 0).
- **Progressive log reveal (P2.9).** Large raw events in `log_analysis` reveal fields in batches of 8 instead of one wall; every revealed field stays IOC-taggable.
- **Source-of-truth signpost (P0.3).** `/learn` shows a banner: this is a reference library; the graded, prerequisite-gated curriculum is **Learning Rooms**, with a direct link.
- **Transfer CTA (P0.4).** The two capstone rooms show a "Now practise this live" button into the SOC Dashboard on completion.

### Content
- **~230 reading checkpoints** across **~40 room files** (50 in the first wave on the reading-heaviest rooms; ~180 in a second wave via four parallel agents covering batch-03/04/06/07/10/11/12, 13-r3/r4, 14-r1..r6, 15-r1, 16-r1, 17-r1..r6, 18, 19, 20..29). Each tests a concrete fact from the passage above it, with a real-confusion distractor and a one-line explanation. Capstone rooms got the richest checks.
- **4 `analyst_choice` tasks (P1.6)** with FP traps added to early rooms (`active-directory`, `sentinel-fundamentals`, `defender-xdr`, `crowdstrike-falcon`) — the platform's strongest "think, don't memorise" mechanic, no longer locked to the late rooms.
- **5 theory gaps closed (P1.8)** with readings + checkpoints: vCenter/ESXi + T1489 Service Stop (`batch-23`), "permitted ≠ authorised" (`batch-11`), setgid crontab persistence (`batch-18` persist-r2), AD-Tier vs SOC-Tier disambiguation (`attackTypeLessons`), "why two Kerberos rooms" (`batch-18`).
- **Accuracy (P0.5 / P2.11):** IBM-2023 stats reworded as recent-years ranges + Verizon DBIR / Mandiant M-Trends added and a source-citation habit taught (`batch-01`); `crowdstrike.event.*` → `crowdstrike.*` normalized (69 refs across `batch-13-r3/14-r2/14-r3`); an agent-written Sentinel event with invented field names rewritten to a real `SecurityAlert` (aggregates under `ExtendedProperties.*`).

### Class leaderboard (P1.7) — LIVE
- Migration **`0018_org_leaderboard.sql`**: a `SECURITY DEFINER` function `public.org_leaderboard()` returning safe columns only, hard-filtered to the caller's own org via `current_org()`. Deliberately **not** the view that caused the C1 cross-tenant leak (dropped in 0016).
- `src/app/api/leaderboard/route.ts` runs it as the caller (user-context client); a cohort card on `/progress` appears only for enrolled classes (hidden for solo learners).
- **Applied to production 2026-08-06** via the Supabase SQL editor. Verified: function present, `prosecdef = true`, granted to `authenticated` only (`anon`/`public` absent). **The leaderboard is live, not pending.**
- **Confirmed live end-to-end:** viewed on the deployed app as a `Student` in the "Internal / Default" org — the card renders with both cohort members ranked (rank 1 highlighted as "you"), "Ranked by XP within your organisation."

### XP-source alignment (follow-up, found during the leaderboard prod check)
Verifying the leaderboard surfaced a mismatch: the `/progress` header showed **0 XP** while the leaderboard showed **85** for the same user. Root cause was a **hydrate race**, not two data sources — `remoteBackend.hydrate()` loads the server-authoritative `profiles.xp` into the local `soc_total_xp` cache but writes it directly (the `xp` column is client-revoked since migration 0008) and fired no event, so the header — which read `getTotalXp()` once on mount, before the async hydrate landed — stayed on the fresh-device `0`, while the leaderboard reads the server directly.
- `progress.ts`: new `broadcastXpChanged()` re-announces the current total without changing it.
- `ProgressProvider`: calls it right after `hydrate()` + `setStorageBackend`, so the synced server total reaches listeners.
- `/progress`: the header now listens for `XP_CHANGED_EVENT` and re-reads (the Topbar rank badge already listened, so it aligns too).
- **Verified live:** after the deploy landed, the header updated from `0` to **85 XP**, matching the leaderboard — same server-authoritative `profiles.xp` everywhere.

---

## 4. Intentionally NOT done

- **P2.10 — blanket "scenario-first" room reorder.** Reordering many rooms to open with a scenario before reading would risk the careful scaffolding the pedagogy audit specifically praised. The new `analyst_choice` tasks already inject early interactivity without disturbing the sequence. Left as a deliberate non-change.

---

## 5. Verification notes

- Every commit passed `tsc --noEmit`, `node scripts/validate-log-fields.mjs`, and `next build` (135 pages). The final build took ~116 s (OneDrive filesystem), but clean.
- `batch-04` and `batch-07` keep **local** copies of the task interfaces; `checkpoint?` was added to those local `ReadingTask` definitions so the new field typechecks there too.
- The class leaderboard **and** the XP-alignment fix were both driven live in the deployed app (screenshots): the leaderboard card renders for a student in a 2-member cohort, and the header XP converged from `0` to the server total `85`. The only flow not exercised live is the incident-report **passed** state (needs a full graded submission); its render path is verified statically.
