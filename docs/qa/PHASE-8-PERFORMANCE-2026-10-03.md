# QA Phase 8 — Performance Audit

**Date:** 2026-10-03 · **Scope:** HACK THE SOC (Next.js 15 + Supabase) · **Mode:** audit only (fix after approval)
**Method:** static code review (Grep/Read) + verification of each finding in source. CONFIRMED = read the code, definitely real. POTENTIAL = needs a runtime measurement.

## Verdict

The codebase is already **aggressively perf-tuned**; there is no low-hanging fruit. Verified-good patterns (NOT flagged): heavy sim data lazy-loaded via `simData.ts` `import()` only on "Start Training"; scenario list uses a meta-only module so the ~2 MB sim pack never enters the initial bundle; server reads use `fetchAll(range)` pagination + chunked `.in()`; all polling hooks are visibility-gated with backoff; feed rows enrich-cached (`toLiveCached`). **No true N+1** (query-in-loop) exists — the loops are intentional paginated chunking.

The one finding that matters at scale is **team-room client derivation cost (P8-01/02)** — O(N²) over a long multi-user session.

**Already resolved since Phase 1** (re-verified): `getValidatedAuth` wraps `getUser()` in `cache()` → one auth round-trip per render (was 2–3); the Sidebar no longer polls `/api/feedback` (now superadmin-only).

## Top findings by impact

| # | Sev | Area | One-liner |
|---|---|---|---|
| **P8-01** | HIGH¹ | render | Team room re-derives the whole growing event log on every broadcast (~32 memos + 12 consoles on uncapped `events`) → O(N²)/session |
| **P8-02** | MEDIUM | realtime | `mergeEvents` full-sorts + the `events` array is unbounded; gap-fill can pull 60×1000 rows into it |
| **P8-03** | MEDIUM | DB/API | `fetchPublished*` / `fetchOrgCompanies` / `fetchOrgRoomMetas` select the full `content` JSON with no `.limit()` |
| **P8-04** | MEDIUM | DB/API | `superadmin/students` reads whole tables across ALL orgs (paginated but unbounded working set) |
| **P8-05** | LOW | render | Two concurrent 1 s `setInterval`s re-render the dashboard subtree every second during an incident |
| **P8-06** | LOW | DB/API | `remoteBackend` `select("*")` pulls large `telemetry`/JSON columns when fewer fields are used |

¹ HIGH only for long, high-volume multi-user sessions; MEDIUM for typical ones.

---

## Area 1 — Database / API query cost

### CONFIRMED

| ID | Sev | File : function | Repro | Impact | Fix |
|---|---|---|---|---|---|
| P8-03 | MEDIUM | `src/lib/content/publicContent.ts` — `fetchPublished` (:41/46 `select("content")`), `fetchOrgCompanies` (:134), `fetchOrgRoomMetas` (:148) | Dashboard mount / scenarios-list / rooms-list for an org | No `.limit()`/pagination; selects the **entire `content` JSON** (whole scenario/company/room payloads incl. event packs) for every published row → payload grows linearly with an org's authored content; large blobs to the browser on page load | Select meta columns only (the scenarios *list* already does this via `scenariosMeta`); lazy-load full `content` on open; add `.limit()`+pagination |
| P8-04 | MEDIUM | `src/app/api/superadmin/students/route.ts:63-69` | Super-admin opens Students | `fetchAll` over `org_members`, `room_progress`, `scenario_history`, `dashboard_sessions`, `task_attempts`, `organizations` across **all orgs**; paginated (safe from the PostgREST cap) but the whole working set lands in server memory per request and grows with total platform usage | Super-admin-only → low urgency; move to a server-side rollup/`count` view instead of pulling raw rows |
| P8-06 | LOW | `src/lib/storage/remoteBackend.ts:323-324` | Progress sync | `select("*")` on `user_progress`/`room_progress` pulls large JSON columns when fewer fields are used downstream (user-scoped → bounded) | Select only needed columns |

No true N+1 found. `lib/plans/server.ts` and `lib/team/report/serverReport.ts` loops are intentional paginated/chunked reads.

## Area 2 — Client polling & realtime

### CONFIRMED

| ID | Sev | File : function | Repro | Impact | Fix |
|---|---|---|---|---|---|
| P8-02 | MEDIUM | `src/app/(app)/team/[id]/page.tsx:166-172` (`mergeEvents`) + `:89` (`events` state) | Every incoming realtime broadcast during a running session | `setEvents(prev => [...prev, ...fresh].sort((a,b)=>a.seq-b.seq))` re-allocates and **re-sorts the entire growing log** on each event → O(n log n)/event, O(N² log N)/session; `events` is never capped and the gap-fill pull (`:237-253`) paginates up to 60×1000 rows into that same array | Events arrive seq-ordered and append at the tail — merge-append in place instead of a full sort; cap/window the retained array (feed render already caps at `-120`) |

**Non-issues verified:** `useLiveEvents` benign tick = `intervalMs` (~40 s); notifications poll 60 s (visible-gated, debounced); heartbeat 15 s (visible-gated); isolation 10 s (filtered to EDR isolation types only — tiny); OpsHealth 120 s. The team reconcile loop pulls from the DB **only** when realtime is unhealthy/silent, with exponential backoff + jitter — well designed.

## Area 3 — Client bundle & payload

No new CONFIRMED issue — bundle splitting is already correct (see Verdict).

### POTENTIAL

| ID | Sev | Note |
|---|---|---|
| P8-07 | LOW | The on-demand `simData` chunk (`benignEvents` ~433 KB + `companyProfiles` ~260 KB + `attackStories` pulling 24 packs) is correctly deferred to "Start Training", but it's one large chunk fetched/parsed at once — on a slow device the parse cost could stutter the first incident. Confirm with a bundle analyzer / Lighthouse TTI; consider splitting per-company |

## Area 4 — React render cost

### CONFIRMED

| ID | Sev | File : function | Repro | Impact | Fix |
|---|---|---|---|---|---|
| P8-01 | MEDIUM→HIGH (long sessions) | `src/app/(app)/team/[id]/page.tsx` — ~32 `useMemo`s keyed on `[events]` + the full `events` array passed to `SharedCase`, `SituationBoard`, `WarRoom`, `T1/T2/Hunt/Lead/DE/TI/Mgr` consoles, `InstructorPanel`, `TeamIntel`, `InjectFeed`, `TeamReport` (lines ~1086–1187) | Every realtime broadcast creates a new `events` ref | All ~32 memos recompute (each a full O(n) scan rebuilding Sets/Maps: `escalationStates`, `activeClaims`, `incidentLabels`, `dispositions`, `reportByEid`…) **and** all 12 consoles re-render and re-derive over the full log. The visible feed IS capped (`feed.slice(-120)`) — the derivations are not. For a multi-user session producing thousands of events this is the dominant client cost: O(n)/broadcast, ~O(N²) cumulative | Maintain derived indices **incrementally** (one `reduce` over only the `fresh` batch, updating Maps held in a ref) instead of re-scanning all `events`; window the derivation input; `memo()` consoles on narrowed slices rather than the whole array |
| P8-05 | LOW | `src/app/(app)/dashboard/page.tsx:974` (session clock) + `useLiveEvents.ts:547`/`:695` (SLA clock) | During an active incident | Both 1 s intervals `setState` every second → the dashboard subtree re-renders 1×/s for the whole incident (`EventFeed` is `memo`'d so its own cost is bounded, but parent churn is avoidable) | Drive both clocks off one shared 1 s tick, or compute elapsed from a timestamp on render-demand instead of a per-second state write |

**Non-issues verified:** `EventFeed` caps at 100 visible, filter `useMemo`'d, component `memo`'d; `reportEvidence`'s `JSON.stringify` is `useMemo`'d behind the modal flag and bounded to 100 events.

---

## Recommended fix order (on approval)

1. **P8-01 + P8-02 together** (same root — team-room scaling): incremental derivation over the `fresh` batch + merge-append instead of full-sort + cap the retained `events`. This is the single highest-value perf fix and should be measured with the React Profiler during the live pilot.
2. **P8-03** — meta-only selects for published content + lazy full-`content` load.
3. **P8-05**, **P8-04**, **P8-06** — low urgency.

## To confirm live (during the P0 pilot)
- P8-01/02 magnitude: React Profiler commit durations per broadcast as `events` grows in a long multi-user session — **the single most important thing to measure**.
- P8-03: per-org published-row counts and payload sizes in prod.
- P8-07: bundle analyzer / Lighthouse TTI on the deferred `simData` chunk.
