# Team-SOC multiplayer — infrastructure / health review

Reviewer: infra-health (side observer, staging-only, uncommitted). Scope: the
Team-SOC multiplayer exercise (lobby → running → after-action report), with a
focus on the recent **log-anchored escalation** change (🚩 on a log → modal
report → T2 opens "the flagged log").

**Verdict: HEALTHY WITH ISSUES** — every automated gate is green and the build
is clean, but static tracing surfaced one reachable UI↔DB-gate mismatch
(`staff.inject`), a confirmed (if narrow) DOM-nesting defect, and a real
test-coverage gap: none of the 157 passing unit tests touch this feature at
all, so "tests pass" says nothing about the team console specifically.

## Gate results

| Layer | Command | Result |
|---|---|---|
| Types | `node node_modules/typescript/bin/tsc --noEmit` | exit 0, no output |
| Unit tests | `npx vitest run` | 157 passed / 157, 14 files, exit 0 — **none of these files touch `team/[id]/page.tsx`, `team/page.tsx`, or `EventFeed.tsx`/`DetailPanel`** (verified: `find src scripts -iname "*.test.*"` lists 14 files, all in `lib/sim`, `lib/edr`, `lib/rooms`, `lib/scenarios`, `lib/storage`, `lib/dashboard` — zero in `app/(app)/team` or `app/(app)/dashboard/EventFeed*`) |
| Build | `npm run build` (after confirming no dev server was listening on any port, then `rm -rf .next`) | exit 0. 180 static pages generated, `/team` and `/team/[id]` both compile and are listed in the route manifest (`/team` 9.31 kB, `/team/[id]` 27.1 kB). Only pre-existing ESLint *warnings* (unused `sensorId`/etc. in unrelated scenario-pack files), no errors |
| Content | `npm run validate:content` | 0 errors, 53 warnings (pre-existing, unrelated to team feature) |
| Runtime feed | `npm run validate:feed` | PASS — timestamp coherence, asset inventory, tenant purity all hold. Relevant because `buildTeamTimeline` (`src/lib/team/buildTimeline.ts`) reuses the exact same `COMPANY_EVENTS`/`attackStories` pool this gate checks |
| Feed integrity | `npm run validate:feed:integrity` | PASS — 1406 events materialised, D-01/02/03/06/11 all clean |
| Log fields | `npm run validate:logs` | PASS — 20,877 fields checked across 202 files, 0 new violations (92 unresolvable-vendor blocks reported but pre-existing, unrelated to this feature) |
| RLS | `npm run validate:rls` | PASS — 23 public tables, 5 deny-all, 0 gaps |
| Scenarios | `npm run validate:scenarios` | not run — no scenario-content changes in this diff; team timeline draws on existing, already-validated scenario packs |

Before building I checked for a live dev server (`Get-NetTCPConnection -State
Listen` via PowerShell, plus `tasklist`) — nothing was listening on 3000/3001,
so the OneDrive `.next`-collision trap described in the brief did not apply
here; I still `rm -rf .next` before `npm run build` as a precaution.

## Findings, ranked

### 1. MEDIUM — `staff.inject` UI/gate mismatch for a "staff-as-player" session
**Where:** `src/app/(app)/team/[id]/page.tsx:490` (render condition) vs.
`supabase/migrations/0060_team_t1_claim.sql:38` (gate: `p_type = 'staff.inject' then p_role = 'instructor'`).

The Instructor panel (with the "Send inject" button) renders on
`me.is_staff || me.role === "instructor"`. `me.is_staff` is a **global**
org-role check (`org_admin`/`instructor`/platform-admin — see
`src/app/api/team/sessions/[id]/route.ts:29-30`), independent of what role
this specific user was **invited as** in `team_session_members`
(`src/app/api/team/sessions/route.ts:60-64`). The session builder
(`src/app/(app)/team/page.tsx:65-70`) loads *all* active org members —
including other org_admins/instructors — into the invite roster with no role
restriction, so a second staff member can legitimately be invited as `t1`.

When that happens, `apply_session_action` resolves `v_role` from
`team_session_members` (server-side, not client-supplied —
`0051_team_session_rpc.sql:54-56` — so this isn't a spoofing risk, but it does
mean the UI's staff-detection and the RPC's role-detection diverge). A
staff member playing `t1` sees the InstructorPanel *and* their T1Console
simultaneously; clicking "Send inject" always fails with
`action_not_allowed: staff.inject for role t1 in status running`, surfaced as
a red error banner (`setError(e.message)` at `page.tsx:258`) — not a crash,
but a dead button for a legitimate, reachable scenario (any org with ≥2
instructors/org_admins running team exercises together).

A milder version of the same gap: a platform-admin who is `is_staff` but
**not a member of the session at all** (viewing another org's/another
instructor's session for oversight) gets the same InstructorPanel with every
action failing `not_a_member` instead.

**Fix:** render the InstructorPanel (and gate the inject button specifically)
on `me.role === "instructor"`, not `me.is_staff`. `is_staff` should still
control the Start/End buttons (those go through `requireOrgAdmin`-gated REST
routes, not the RPC role gate, so they're correctly org-scoped and unaffected
by this issue).

### 2. LOW-MEDIUM — confirmed DOM-nesting defect: `<td>` inside `<div>`, T2's "Open the flagged log"
**Where:** `src/app/(app)/team/[id]/page.tsx:948-951` nests `<DetailPanel>`
(`src/app/(app)/dashboard/EventFeed.tsx:490`, root element `<td colSpan={7}>`)
directly inside a plain `<div>`:
```
<div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40">
  <DetailPanel event={snap} onThreatQuery={() => {}} onPivot={onPivot} />
</div>
```
Grepping the whole codebase (`DetailPanel` usages), this is the **only**
place outside the real feed `<table>` that renders it — the normal usage
(`EventFeed.tsx:1052`) is correctly inside a `<motion.tr>` inside a `<tbody>`.

**Is it a hydration mismatch?** No — `openLog` starts at `useState<number |
null>(null)` (`page.tsx:911`), so the `<td>` never exists in the
server-rendered HTML for the initial paint; it only appears after a client
click, entirely post-hydration. So this is *not* the classic SSR/CSR text
mismatch. It **is**, confirmed by code reading:
- A React DEV-only `validateDOMNesting` console warning every time a T2/T3
  analyst opens a flagged log ("`<td>` cannot appear as a child of `<div>`") —
  harmless in production (React strips this check in prod builds), but noisy
  and a real signal something's structurally wrong.
- A genuine (if minor) **CSS risk**: Tailwind's preflight (`@tailwind base` in
  `src/app/globals.css:1`) does not reset table-cell display types (verified:
  no `table-cell`/`display:\s*table` override anywhere in `globals.css`), so
  the orphan `<td>` keeps the UA-default `display: table-cell`. Per the CSS
  anonymous-table-object rules, the browser wraps it in an anonymous
  table/row box, which can make width/box-sizing behave differently than a
  normal block (e.g. shrink-to-fit instead of stretching to the parent's
  100%). I did not empirically screenshot this (no dev/build server was
  driven with a real browser in this review — see "not tested" below), so
  I can't say how bad it looks in practice, only that the CSS reset that
  would normally neutralise it isn't present.

**Fix:** split `DetailPanel`'s body out of its `<td>` wrapper into an
unwrapped inner component (e.g. `DetailPanelBody`), then have two 1-line
wrappers: `DetailPanel` (`<td colSpan={7}>` for the real feed table) and a
`DetailPanelCard`/`div`-rooted variant for standalone use (T2Console here,
and any future non-table placement). Low effort, removes both the warning
and the CSS risk.

### 3. INFORMATIONAL — dead/unwired actions referenced by the rubric but never dispatched
`evidence.pinned` and `rule.tuned` are both defined in
`session_action_allowed` (0060) and counted in the after-action rubric
(`ROLE_ACTION_TYPES` at `page.tsx:1397`, `team.evidencePinned` at
`page.tsx:1641`, `roleRubric`'s DE branch), and the T1 role guide literally
instructs "📌 Pin the key logs to the Shared Case" (`page.tsx:50`) — but
grepping the whole `src/` tree, no button anywhere calls `act("evidence.pinned", …)`
or `act("rule.tuned", …)`. This isn't a crash risk (the metrics just always
read 0/n-a), but it means the rubric silently under-scores every session and
the guide promises a feature that doesn't exist yet in this build. Worth a
product decision, not a code fix — flagging per "report, don't fix" for
UX/spec gaps.

### 4. LOW (theoretical) — countdown overlay doesn't block the underlying "I'm ready" button
`page.tsx:241-247`: on receiving the `session.started` broadcast, the client
updates `session.status` and starts a 3-2-1 countdown, but does not flip local
`phase` to `"running"` until the countdown reaches 0. For those ~3 seconds the
lobby's "I'm ready" button is still mounted underneath the full-screen
countdown overlay (`z-50`, `position: fixed`, `inset-0`). The overlay has no
interactive children, so a mouse click can't reach the button underneath (the
overlay occludes it), but the overlay doesn't set `inert`/`aria-hidden` on the
background, so a keyboard user tabbing through could theoretically still
reach and activate it. If they did, the server would already be `running`
and `session_action_allowed` would reject `member.ready` (`p_status =
'lobby'` required) — so the *worst case* is a rejected RPC call and an error
banner, not a crash or a state-corruption bug. Very low likelihood, very low
impact; flagging for completeness since it's a real (if narrow) UI/gate edge
case, same family as finding #1.

### 5. Everything else I specifically traced was defensively coded and did not crash on inspection
- **`pull()` 1000-row pagination** (`page.tsx:202-213`): correctly cursors on
  `seq`, guards with `guard < 30` (covers up to 30,000 events), breaks on
  empty page or `data.length < 1000`. No unbounded loop risk.
- **`onEscalate` handler** (`page.tsx:460-473`): guards `if (!raw) return;`
  before touching the payload.
- **T1Console's `escalate()`** (`page.tsx:757-775`): uses `?.` and `asStr()`
  throughout; the escalation quality gate (`canEscalate`) hard-blocks the
  submit button until summary + ≥12-word observations + ≥1 IOC + severity are
  all present, matching `MIN_RATIONALE_WORDS` — no way to fire a malformed
  `escalation.requested` from the UI.
- **`enrichSnapshot`** (`page.tsx:651-663`): explicit `typeof snap !==
  "object"` guard before touching fields, and the `enrichEvent(...)` call
  itself is wrapped in `try { … } catch { … }` with a safe fallback object —
  matches the same defensive pattern the live feed's own `liveFeed` memo uses
  (`page.tsx:317-329`). A malformed `snapshot` payload cannot crash the T2
  console.
- **`DetailPanel`'s own rendering** (`EventFeed.tsx:439-487`): every raw
  field access goes through `?.` chains or `Object.entries(event.raw ?? {})`;
  `basicInfo`/`ecsCore`/`rawFields` all guard against missing sub-objects.
- **`onRowOpened` signature widen** (`(eventId?, dwellMs?) => void`,
  `EventFeed.tsx:1085`): the dashboard's own handler,
  `useLiveEvents.ts:886` (`recordEventOpened: () => void`), silently ignores
  the extra arguments — JS/TS both allow calling a `()=>void`-typed callback
  with extra arguments, and `tsc --noEmit` confirms this compiles clean. No
  regression.

## Migration consistency (`session_action_allowed` vs. every `act("...")` in the UI)

I extracted every action type the client can fire (`grep -o 'act\(\s*["\x27][a-zA-Z_.]+' page.tsx`) and cross-checked each against the **latest** cumulative gate definition, `supabase/migrations/0060_team_t1_claim.sql` (the function is `create or replace`d across 0051/0053/0054/0055/0057/0058/0059/0060; 0060 is the final, complete body — `apply_session_action` itself is defined once, in 0051, and never redefined, and it resolves the caller's role **server-side** from `team_session_members`, never trusting a client-supplied role).

| Action (fired from) | Gate requirement | UI's actual restriction | Match? |
|---|---|---|---|
| `member.ready`/`unready` (lobby) | any role, `status='lobby'` | button only shown in lobby phase | ✓ |
| `disposition.set`, `escalation.requested`, `alert.claimed`/`released` (T1Console) | `t1`, running | T1Console only rendered for `role==='t1'` | ✓ |
| `escalation.acknowledged`, `escalation.bounced`, `containment.requested`, `containment.executed` (T2Console) | `t2`/`t3`, running | T2Console only rendered for `role in (t2,t3)` | ✓ |
| `escalation.resolved` | `t2,t3,lead,mgr` | fired only from T2Console (t2/t3) | ✓ (gate is a superset — fine) |
| `containment.approved`/`denied` (LeadConsole) | `lead,mgr` | LeadConsole rendered for `role in (lead,mgr)` | ✓ |
| `sitrep.sent`, `decision.logged` (Sitrep/DecisionLog, nested in LeadConsole) | `lead,mgr` | only reachable via LeadConsole | ✓ |
| `hunt.logged`, `scope.confirmed` (HuntConsole) | `t3` | HuntConsole only for `role==='t3'` | ✓ |
| `scope.set` (ScopeConsole "Set"/"Amend", used by both T2 `mode="set"` and T3 `mode="confirm"`) | `t2,t3` | fired from T2Console (t2) and HuntConsole (t3) | ✓ |
| `rule.published` (DEConsole) | `de` | DEConsole only for `role==='de'` | ✓ |
| `intel.published` (TIConsole) | `ti` | TIConsole only for `role==='ti'` | ✓ |
| `handover.noted` (MgrConsole) | `lead,mgr` | MgrConsole only rendered for `role==='mgr'` (narrower than the gate — fine, no lead path exists in the UI for this action, not a bug) | ✓ |
| `ticket.answered` (InjectFeed) | `t1` | button gated on `isT1` locally | ✓ |
| `staff.inject` (InstructorPanel) | `instructor` | rendered on `is_staff \|\| role==='instructor'` | **✗ — see Finding #1** |
| `case.status_set` (SharedCase) | `t2,t3,lead,mgr` | buttons `disabled={!canStatus}`, `canStatus` = same set | ✓ |
| `case.assigned` (SharedCase) | `lead,mgr` | `canAssign` = same set | ✓ |
| `note.added`, `event.opened` | any role, running | no role restriction in UI | ✓ |
| `message.sent` (WarRoom) | always `true` | `canPost` requires non-null, non-`observer` role (UI is *stricter* than the gate — fine) | ✓ |

Net: **one mismatch** (`staff.inject`, Finding #1), everything else lines up.
`session.started`/`session.ended`/`feed.event`/`inject.fired`/`grade.assigned`
are correctly blocked from client origination in both the 0051 and 0060
versions of the gate (`then false`) and are never called via `act(...)` in
the UI — they're only ever inserted server-side (start/end routes,
`promote_due_injects`).

## The OneDrive `.next`/stale-SWC artifact — how to tell it apart from a real error

I did not encounter this artifact in this session (I confirmed no dev server
was listening before running `npm run build`, and `rm -rf .next` first — the
build was clean, single-shot, no stale cache). For the record, since the
brief calls it out explicitly: the tell is that the **reported line/column in
the syntax error does not correspond to the actual code at that position** in
the file open in the editor — e.g. a "Unexpected token" at a line that,
when you `Read` the file, is a comment or blank line. Real TypeScript/ESLint
errors always point at the actual offending token. If you see a
syntax error whose cited line doesn't match reality, `rm -rf .next` and
re-run before concluding there's a real bug — but *first* verify no dev
server is running (a build against a live dev server's `.next` produces a
different symptom: 500s on every route, not mismatched line numbers).

## No-regression check — single-player dashboard

- `EventFeed`'s three new props (`onPivot`, `onAddIoc`, `onEscalate`) are all
  optional (`?:`) and the dashboard's own call site
  (`src/app/(app)/dashboard/page.tsx:1530-1541`) does not pass any of them —
  confirmed by grep, only `onRowOpened` is passed. Inside `DetailPanel`, all
  three are consumed behind `onX && (...)`/`!!onX` guards
  (`EventFeed.tsx:496`, `625`, `628`), so omitting them renders nothing extra.
- `onRowOpened`'s signature widened from implicit `()=>void` usage to
  `(eventId?, dwellMs?) => void`; the dashboard's `recordEventOpened` is
  still typed `() => void` and JS permits calling it with extra args — `tsc
  --noEmit` confirms this compiles without error, and `npm run build`
  succeeded end-to-end including the `/dashboard` route.
- `git diff --stat` on `EventFeed.tsx` shows +101/-16 across the file — I
  read the diff region (all of `DetailPanel`'s new escalate CTA and the
  IOC/pivot chips) and every addition is behind an `onX &&` guard; nothing
  in the always-on rendering path (the base row, the Analysis/Raw toggle,
  the IT-verify widget, MITRE badge, etc.) was touched in a way that changes
  single-player behaviour.
- **Not verified empirically**: I did not load `/dashboard` in a real browser
  to visually confirm nothing shifted. This is a static/compile-time
  confirmation only (see below).

## What was NOT tested (be honest about the gap)

- **No browser/visual verification at all.** Every finding above (including
  the `<td>`-in-`<div>` nesting) is from reading the code, not from opening
  `/team/[id]` in a browser and clicking through the lobby → running → T2
  "open the flagged log" → after-action-report flow. I did not have a
  browser-automation tool available in this session; I did not start `next
  start`/`next dev` and drive it. This is the single biggest gap: a genuine
  live run-through (multiple browser sessions/roles, real Supabase Realtime
  presence + broadcast, pg_cron actually promoting injects on schedule)
  could surface timing/race issues that static analysis cannot — most
  notably the presence/broadcast reconnect path (`page.tsx:220-251`) and
  whether pg_cron is actually enabled and firing on the staging project.
- **No staging-DB verification.** I did not query the staging Supabase
  project to confirm all 12 migrations (0049–0060) are actually applied
  there, or that `pg_cron` is scheduled and running `promote_due_injects`.
  I only confirmed the `.sql` files exist on disk and read their bodies. Per
  the standing instruction, I did not run any migration or touch the DB.
- **`npm run validate:scenarios`, `npm run validate:hashes`,
  `npm run validate:diagrams`, `npm run validate:svg`** were not run — none
  of them touch code changed in this diff (no scenario/content files were
  modified; `buildTeamTimeline` only *reads* already-validated scenario
  packs). `validate:feed:adaptation` / `validate:feed:paths` (L03/E01-specific
  single-player checks) were likewise skipped as out-of-scope for the team
  feature.
- **No load/concurrency test.** The multi-analyst "soft-claim" logic
  (`alert.claimed`/`released`, T1-3) and the optimistic-concurrency
  `p_expected_seq` path in `apply_session_action` were read, not exercised
  under real concurrent writers.
- Vitest's 157 passing tests give **zero** coverage of this feature (see gate
  table above) — "tests pass" here is not evidence the team console works,
  only that it doesn't fail to compile. Treat the HEALTHY verdict as
  "no crash found by static tracing + clean build," not "verified working."
