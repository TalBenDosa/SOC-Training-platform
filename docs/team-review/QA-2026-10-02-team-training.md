# QA — Team training (Team-SOC multiplayer) — 2026-10-02

Scope: code review + local checks + pure-function probes (real `buildTeamTimeline` / `computeReport`) on
`feat/stack-selection` (== prod main 7bbade6). No browser / staging / prod run. Produced by the QA agent;
saved here by the main session. Status column = what the main session did about it the same day.

Local checks: `tsc` 0 errors · vitest team/native 56 files / 477 tests pass · eslint 0 errors, 3 warnings
(`[id]/page.tsx:59` unused `IMPACTS`, `team/page.tsx:25` unused `Info`, `team/page.tsx:55` unused `claimLoading`).

No authz bypass, cross-org read or service-only RPC exposure found.

| Sev | Id | Finding | Where | Status |
|---|---|---|---|---|
| High | H1 | Public feed payload carries attack-correlated SHAPE: `mitre_*` on 80 % of attack rows vs 4 % benign (MITRE badge in the opened row, technique-specific rule name/id), empty `user`/`registry`/`cloud` objects mostly on attack rows, `is_detection` ~99.5 % precise | `buildTimeline.ts` `toPublicEntry`; `EventFeed.tsx` MITRE badge; `liveEventEnrich.ts` rule desc/id | **Fixed**: technique only where a product tags it (`mitreVisible`: detections/IDS/WAF/SIEM/UEBA/DLP) — badge, rule name/id, and team payload (technique moved to the answer key, report joins it back); empty structures dropped. `is_detection` kept: it only says what the rendered record type already shows (an EDR alert); the real gap is content — almost no benign EDR alerts (see recommendations). Guard: `publicPayloadTells.test.ts` |
| High | H2 | XP farmable without analysis (8 one-char notes → 75; flip one verdict 20× → 127; mark all benign → 156) | `teamXp.ts`, `computeReport.ts:715`, `ROLE_ACTION_TYPES` incl. `note.added` | **Fixed** (new sessions; awarded XP untouched): activity counts distinct work (re-verdicts, repeated acks/decisions/actions once; notes don't count), rubric pays only after ≥3 distinct pieces of work, −3 accuracy per wrong final verdict. Tests in `teamXp.test.ts` |
| Med | M1 | Removed/left member keeps GET `[id]` read (roster, names); no UI to remove a no-show; lapsed-affiliation invitee blocks Start forever | `api/team/sessions/[id]/route.ts:29-32`, `members/route.ts` (DELETE has no UI caller) | Open |
| Med | M2 | Click telemetry client-asserted & unthrottled (`event.opened` returns before rate-limit/validation; forged dwell); ≥60k click rows make `pageAll` throw → report 500 forever | `0073:273-279`, `0071`, `0080:440-457`, `serverReport.ts:69-87` | Open |
| Med | M3 | Pauses count against SLA, claim TTL, MTTD/ack latency → rubric timeliness & XP | `computeReport.ts:50`, `alertQueue.ts:58-60`, `projections.ts` | Open |
| Med | M4 | `ioc-truth` endpoint is a whole-feed oracle (verdict for every IOC of every fired log; digest fn in client bundle; unthrottled) | `api/team/sessions/[id]/ioc-truth/route.ts:21-50` | Open |
| Med | M5 | End-of-session thundering herd: every client GETs `/report`, no single-flight; XP awarded inside the request, no `maxDuration` | `end/route.ts:40-49`, `awardTeamXp.ts` | Open |
| Med | M6 | Scoring rewards volume (raw counts) | `computeReport.ts:715` | **Fixed** with H2 |
| Med | M7 | Pinned-storyline validation uses raw story events; forced stories never re-checked at /start (1 disagreement found, no broken build) | `api/team/sessions/route.ts:47-51`, `storylines/route.ts:35-36` vs `buildTimeline.ts` | Open |
| Low | L1 | Roster cap / single-seat check-then-insert; loser gets generic 500 | `members/route.ts:61-77` | Open |
| Low | L2 | Staff invited as a player can read seed / scenario_id / `expected_action` | GET `[id]`, RLS `team_staff_sessions` | Open (design) |
| Low | L3 | Builder: stack carries over on company change; pinned storyline silently cleared; Google→M365 leaves Proofpoint; lobby never shows the stack (`SessionMeta` lacks `stack`) | `team/page.tsx:71,105-119`, `StackPicker.tsx`, `types.ts:3` | Open |
| Low | L4 | A second org instructor has `me.role === null` → only Pause/End | `[id]/page.tsx:1016-1019,1122` | Open |
| Low | L5 | XP sweep: newest 200 only, 20/night; zero-player sessions re-enter daily; REPORT_VERSION bump doesn't re-award | `awardTeamXp.ts:40-48` | Open |
| Low | L6 | `is_team_member(p_session, p_user)` SECURITY DEFINER granted to authenticated — membership oracle | `0071:118-128` | Open |
| Low | L7 | `/start`: no try/catch around `buildTeamTimeline`; retry keeps first pace; zero-player start self-pauses | `start/route.ts:55-66` | Open |
| Low | L8 | Stale copy ("Ask them to refresh"), reassign list omits observer, 3 eslint warnings | `InstructorPanel.tsx:35`, `AddMemberPanel` | Open |
| Low | L9 | `key={w.name}` collides for equal display names | `MgrConsole.tsx:191` | Open |
| Low | L10 | Org licence not enforced for in-flight sessions (unconfirmed impact) | `apply_session_action`, end, pause | Open |
| Low | L11 | Native modules lazy-load at `running` → first rows flip legacy→native | `[id]/page.tsx:790-796` | Open |
| Low | L12 | POST `/sessions` duplicate invitees → generic 500 (API only) | `sessions/route.ts:55-90` | Open |
| Low | L13 | Recycled noise repeats identical logs in the shift tail (weak tell) | 0084 | Open |
| Low | L14 | `backfill-team-xp.ts` has no target-project confirmation | `scripts/backfill-team-xp.ts` | Open |

## Verified OK (selection)
Grants: all service-only RPCs revoked from anon/authenticated; client writes on `team_sessions`/`team_session_members`
revoked; `seed`/`scenario_id` column-revoked from players; `session_injects` staff-only; `session_events` RLS excludes
left/lapsed members. Answer key: none of `TEAM_ANSWER_FIELDS` in 20,381 public bodies; opaque ids; uniform tier;
`/report` 409 until ended, own card only unless staff/Manager. Action gating deny-by-default, validation under the session
lock, idempotency key + unique index, no lock cycle, atomic idempotent transitions, concurrent starts seed once. XP
deterministic & idempotent, no double award. Stack: `sanitizeStack` server-side everywhere; every company × difficulty
keeps ≥3 fitting stories across all 1600 vendor combinations; 41,829 rows under 6 stacks with no foreign-vendor leakage.

## Not confirmed
Browser behaviour; Vercel timeout for end/report (M5); reachability of 60k clicks in honest play (M2); licence-expiry
effect on live sessions (L10); whether the MITRE badge was a deliberate teaching feature (H1 — now shown on detections only).
