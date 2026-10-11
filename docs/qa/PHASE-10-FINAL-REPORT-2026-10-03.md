# QA Phase 10 — Final Report & Regression Plan

**Date:** 2026-10-03 · **Platform:** HACK THE SOC (Next.js 15 + Supabase) · **Audit owner:** Senior QA + security
**Program:** a 10-phase pre-production audit (architecture → authz → API → DB → frontend → security → error handling → performance → edge cases → this report). Audit first, fix after approval, one table per finding.

## 0. Verdict

**The platform is production-grade.** Phases 1–7 found and fixed a large backlog (security, DB integrity, frontend crashes, error handling) — **all deployed**. Phases 8–9 (this session) found **no architectural defects**: performance is already aggressively tuned, and the edge-case pass surfaced a cluster of report-engine bugs that are **now fixed**. The remaining open items are medium/low and scoped.

The one thing no static audit can replace: **a live multi-user pilot** (the standing P0). Everything below is green in code and tests; the team room's O(N²) client cost (P8-01) and the graded-report behaviour should be watched during that pilot.

## 1. Phase-by-phase status

| Phase | Area | Findings | Status | Deployed |
|---|---|---|---|---|
| 1–3 | Architecture / authz / API | (foundational) | Fixed | ✅ main 871f6e9 |
| 4 | Database | 24 (P4-01…24) | Fixed (1 deferred: statement-level XP trigger) | ✅ 0080+0081, main 15de0b1 |
| 5 | Frontend | 25 (P5-01…25) | Fixed | ✅ main 9c87aaf |
| 6 | Security | SEC-01…22 + P-01…06 | Fixed | ✅ 0083, main 6d83b1f |
| 7 | Error handling | E-01…23 + internal monitoring | Fixed | ✅ 0085+0086, main 124e223 |
| **8** | **Performance** | 6 (P8-01…07) | **Audited** — 1 HIGH-at-scale, rest LOW; fix recommended during pilot | — (see PHASE-8 doc) |
| **9** | **Edge cases** | 16 (P9-01…16) | **6 FIXED this session**, 10 on approval | pending |
| **10** | **This report** | — | — | — |

Detail: [PHASE-8-PERFORMANCE](PHASE-8-PERFORMANCE-2026-10-03.md), [PHASE-9-EDGE-CASES](PHASE-9-EDGE-CASES-2026-10-03.md).

## 2. Fixed in this session (Phase 9 critical + fresh-code)

All in the report engine (`src/lib/team/report/computeReport.ts`) and verified (tsc + 77 report tests + snapshot):
- **P9-01 (HIGH)** — quadratic regex DoS: a 16 KB finding could push the debrief past the 60 s route cap (report 500, no XP). Bounded all quantifiers + clip free-text to 2 KB.
- **P9-02 (MED)** — detection time now the earliest of (escalation, TP/suspicious mark); the T1 flow marks before escalating, so the old code charged report-writing time to the SLA.
- **P9-04 (MED)** — a single `payload:null` event no longer 500s the whole report.
- **P9-05 (MED)** — SLA judged from the first MAX-severity log, not the first recon log (kill-chains could grade fairly again).
- **P9-F (MED)** — MTTD and "detected" now use the same basis.
- **P9-cov (LOW)** — host/technique coverage now feed the grade (blended) and show in the UI.

## 3. Open items (consolidated, by severity)

### HIGH (watch / fix during the pilot)
| Ref | Item | Note |
|---|---|---|
| P8-01/02 | Team room re-derives the whole growing event log per broadcast (O(N²)); `events` unbounded + full re-sort | Only bites long, high-volume multi-user sessions — **measure with React Profiler during the pilot**, then fix incrementally |

### MEDIUM (fix on approval)
| Ref | Item |
|---|---|
| P9-03 | Role-at-time scoring: a reassigned member is judged by the final role; reassign → observer zeroes their XP |
| P9-06 | `escalation.bounced/resolved` lack an ownership/latest-state check (migration) |
| P9-07 | `reassign`/`members` routes ignore the `appendSystemEvent` result (clients don't refresh on failure) |
| P8-03 | `fetchPublished*`/`fetchOrgCompanies` select the full `content` JSON with no limit (scales badly for a content-heavy college) |
| Carry-fwd | Phase 2–3 DB items flagged needing a migration (AUTH-002 room_progress writable, AUTH-007/009 answer-key exposure, P3-02/08/10 races) — **re-verify against current prod** (several overlap Phase 4/6 fixes); scenario-review fixes #3–#7 |

### LOW (batch on approval)
P8-04/05/06 (superadmin whole-table read, dual 1 s dashboard intervals, `select("*")`); P9-08…P9-16 (surrogate-safe slice, `sevOf` triage severity, `hostKey` IP, SituationBoard `left` members + pause-aware clocks, incident-list remainder, lobby counts include left/observer, dropped-invite reporting, SLA-table naming, HotWash dwell source, CSV UTF-8 BOM).

### Resolved since earlier phases (re-verified this session)
- Auth round-trips → `getValidatedAuth` wraps `getUser()` in `cache()` (one per render).
- Sidebar `/api/feedback` poll removed (now superadmin-only).

## 4. Regression test plan

### Automated gate (run before every deploy)
```bash
npx tsc --noEmit
npx vitest run                     # 1456 tests (176 files)
npm run validate:content           # PASS
npm run validate:feed              # PASS
npm run validate:logs              # PASS (exit 0)
npm run validate:scenarios:integrity   # PASS
npm run check:client-answers       # no answer-key leak in client chunks
npm run build                      # next build compiles
```
Plus the PGlite DB suites (phase4 / phase6 / phase7 / edr / team-review) and the `computeReport` characterization snapshot — any scoring drift shows as a snapshot diff.

### Targeted regression per phase
- **P4 (DB):** `node scripts/test-phase4-db.mjs` (PGlite, 48 checks).
- **P6 (security):** nonce CSP present; API writes need Origin/Sec-Fetch; licence gate; `revoke_user_sessions` on removal; no answer keys in `.next/static/chunks` (`grep -rl --include=*.js -F "<explanation text>" .next/static/chunks`).
- **P7 (errors):** `/api/health?deep=1` → db ok; `/api/access-codes/%25` → 200 `{valid:false}`; non-UUID segment → no 500.
- **P9 (report engine, NEW):** the 3 added tests (earliest-action detection, SLA anchor on a mixed-severity incident, null-payload no-throw) + the grade-band tests (caught_well/partial/noticed/missed).

### Manual regression (the standing P0 — needs real users)
A guided live pilot with ≥4 participants in prod, end-to-end (lobby → staggered attacks + MSEL + bonus → End → AAR), capturing: React Profiler commit durations as the event log grows (P8-01); the graded report on a real session (do catch grades match a human reviewer's judgement?); and the full T1→T2→T3→Manager relay under real concurrency.

## 5. Recommendation

Ship-ready for a **guided pilot now**. Before selling as a team-measurement product: run the pilot, fix the Phase-9 MEDIUMs (P9-03/06/07) and the team-room scaling (P8-01) if the Profiler confirms it, and re-verify the carried-forward Phase 2–3 DB items against current prod. The LOW backlog can be worked down continuously; none blocks use.
