# Changelog — Team-SOC hardening & server authority (2026-09-26)

Closes every item in [`AUDIT-2026-09-26-team-infra-ux-security.md`](AUDIT-2026-09-26-team-infra-ux-security.md)
(Phase 0, 1 and 2). Per-item status is in §7 of the audit.

> **Scope & safety:** **staging only.** Migrations `0069`, `0071` and `0072` are applied to the staging DB;
> nothing was deployed to prod / `main`. New behavior is **version-gated** by
> `team_sessions.schema_version`: sessions started from now on are v2; sessions already open stay v1
> with their old behavior, so applying the DB before the client breaks nothing.

---

## 1. Security
- **0069:** execute on every team system function revoked from `public/anon/authenticated`; the
  old `seed_session_timeline`/`start_team_session` dropped; realtime write = presence only (no forged
  broadcasts); `promote_due_injects` uses `FOR UPDATE SKIP LOCKED`.
- **Answer key off the wire (v2):** the public feed body no longer carries `expected_verdict`,
  `fp_explanation`, `incident_id`, `edr_scope` or `is_baseline`; `tier` is uniform; ids are opaque
  and seed-stable. Answers live in `session_injects.expected_action` (staff-only). Inject kinds
  twist / false lead / pressure show to players as "update"; staff see the real kind.
- **Server-authoritative AAR:** `GET /api/team/sessions/[id]/report` computes once on the server,
  caches in `team_session_reports`, and returns only the caller's own card (staff and the Manager see
  all). CSV export is staff-only and formula-safe.
- **Access:** client write policies on sessions/members dropped; `is_team_member` excludes removed
  members and requires active org membership; `DELETE /members` removes a member; generic error
  bodies everywhere; rate limit (~60/min, burst 30) + 20K-event cap for player actions.
- **Lifecycle control:** in v2 only staff / the active Manager can pause or end; coverage and
  instructor-left pauses are decided by the server alone.

## 2. Connectivity
- Contiguous-watermark **gap-fill**: pulls on seq gaps, on `SUBSCRIBED`, on tab visibility and in
  every phase (lobby included), with backoff + jitter; the RPC's returned row is merged immediately.
- **Server clock** (`lib/team/clock`): offset from the `Date` header + a 15 s ticker drives claim TTL,
  SLA, load and oldest-unacked, so a skewed laptop no longer misreads teammates' claims.
- Roster/role changes emit `member.*` events → every client refreshes roster and `me`.
- **Live / Reconnecting** pill; friendly, auto-clearing action errors; idempotency key =
  type + payload hash + 2 s bucket (double-click = one event).

## 3. Infrastructure (migration 0071)
- One lock rule: every writer takes the per-session advisory lock first; background jobs try-lock
  and skip busy sessions (≤50 sessions/tick, one exception block each).
- Single seq allocator; `occurred_at = clock_timestamp()` (time order matches seq order).
- `team_transition` RPC: atomic, validated status changes with DB-clock `paused_ms`,
  `pause_reason`, pending injects → `skipped` on end, ready-check re-verified on start.
- **Server presence:** `team_heartbeat` (every 15 s from the room and from `/edr`) +
  `team_lifecycle_tick` every 10 s — core tier unseen >120 s (two stale ticks) → coverage pause;
  instructor >180 s → pause (not end); resume after 30 s of steady presence; 60 s grace after
  start/resume; manual pauses never auto-resume. One spoiler-free `hint.nudge` 3–6 min after the
  first attack if nobody escalated.
- `replenish_feed` subtracts `paused_ms` and only recycles `channel='feed'` rows; the reaper judges
  idleness by actor activity + heartbeats; v2 clicks go to `session_clicks` (no seq, no broadcast).
- Ops: `team_ops_events`, `team_ops_health` view (service-only), daily `cron.job_run_details` purge.

## 4. Architecture
- `team/[id]/page.tsx` split into `_components/*`; `computeReport` extracted, isomorphic, with a
  characterization snapshot on a real ended staging session.
- `lib/team/projections`: **one** claims/open-load rule used by the feed badges, T1 console,
  Situation Board **and** the AAR replay (at event time) — the AAR no longer scores a Manager on
  overload the board had stopped showing.
- 39 team tests (report characterization + fixtures, projections, buildTimeline, serverReport).

## 5. UX/UI
- AAR: 4 headline metrics with a legend + grouped "Show all metrics"; title "Shift review".
- Rebalance banner names the queue, not the person (no-fault); Tier-2-missing warning on create;
  closed session rows are whole-row links to the Shift review; guide/confirm copy matches the UI.
- Take-next confirmation; Manager with staff rights still commands from the Situation Board;
  aria-labels, focus-visible rings and contrast fixes; escalation snapshots truncated above 8K.

## 6. Fixes from the independent review (migration 0072)
- **Critical — sessions auto-paused ~80 s after start:** lobby clients kept the v1 meta, so they
  never sent heartbeats and the server tick paused the room as "instructor left". Sessions are now
  v2 from creation, and every client re-reads the session meta on `session.started`.
- **Fairness:** promote / replenish / tick visited only the 50 oldest live sessions; now they pick
  only sessions that need work, in random order (verified with 55 older sessions ahead of a new one).
- **Timestamp tell:** authored dates (benign ≈ May, attacks ≈ June) marked the attack logs. Public
  feed bodies now sit on one synthetic time base (raw fields shifted too); the room and the EDR
  pivot re-time every log to when it streamed in; recycled logs keep their base time.
- A removed (left) member no longer blocks Start; seeding runs under the session lock
  (`team_seed_timeline`), so two Start clicks can't double the feed; the double-click guard no longer
  swallows ready → unready → ready or claim → release → claim; a Manager whose org affiliation
  lapsed can no longer end/pause through the API.

## Verification
- 0072 harness on staging: 14 checks (privileges, seed-once, left member vs Start, fairness,
  replenish ts, tick) — all passed; cron jobs succeeding, 0 ops errors.
- 0071 apply harness on staging: ~40 SQL checks (privileges, seq under concurrency, transitions,
  tick pause/resume/hysteresis v2-only, nudge-once, replenish filter, answer-free payloads) — all
  passed; cron healthy, no ops errors.
- `tsc` clean · vitest **197/197** · `next build` OK · validate content / feed / logs /
  feed-integrity / scenario-integrity all PASS · rooms-meta unchanged.
- Independent code review of the full diff — 7 confirmed findings, all fixed (section 6).
- **Manual, still open:** live two-user run — see Part D of
  [`TEST-SCRIPT-2026-09-23-two-analyst.md`](TEST-SCRIPT-2026-09-23-two-analyst.md).

## Not in prod
Team-SOC has never been deployed to production. Separate and still awaiting approval: the quiz-XP fix
(`fix/quiz-xp-award`, migration 0070).
