# Team-SOC — Infrastructure & Scalability Review (2026-09-18)

Goal: the combined (team) training runs **smoothly under a very large number of concurrent
users and many simultaneous sessions**. This reviews the architecture end-to-end, fixes the
code/DB bottlenecks, and states the operational (Supabase plan) levers that set the real
ceiling. Method: code + migration audit and an independent scalability audit; hot-path
`EXPLAIN` on staging; gates green (`tsc`, `next build`, `vitest` 157). A true multi-thousand
websocket load test isn't runnable from the dev sandbox — the ceilings below are derived from
the mechanism + Supabase quota math and validated by query plans.

## Architecture at a glance

Event-sourced. All writes go through `apply_session_action` (append-only `session_events`,
per-session `seq` via `unique(session_id, seq)`); a per-insert trigger `realtime.send`s each
event to the private channel `session:<id>`; clients render from the broadcast and keep a
projection. A pg_cron job promotes MSEL/feed injects on a timeline; another reaps orphaned
sessions. Presence tracks who's online per session.

**The scaling primitives:** (a) one Realtime connection per online user; (b) broadcast
messages ≈ Σ(events/s × members); (c) one global promote tick every 5s; (d) per-user client
polling as a realtime fallback.

## What was fixed in this review (staging-applied, committed)

- **Realtime-aware reconcile (client).** The 6s DB reconcile pull ran per online user forever
  (O(users) queries/s, redundant with realtime). It now pulls only when the channel is
  unhealthy or realtime has been silent >25s; a healthy active session does ~no steady-state
  polling. Health is tracked from the subscribe status + every presence/broadcast message
  (`channelHealthyRef` set on `SUBSCRIBED`), with the initial + reconnect catch-up pulls kept.
  → removes the O(users) polling axis (≈1,000 q/s at 10k users → ~0 while realtime is healthy).
- **Inject/session indexes (migration 0066).** `session_injects_pending_idx` partial index
  `(session_id, due_offset_ms) WHERE status='pending'` (matches the promote query, stays tiny);
  dropped the redundant `session_events_session_seq_idx` (the `unique(session_id, seq)` index
  already covers it — less write amplification on the highest-write table);
  `team_sessions_active_idx` partial on `status IN ('running','paused')`; reaper latest-event
  lookup is now index-backed (`ORDER BY seq DESC LIMIT 1`). `EXPLAIN` confirms the promote hot
  path uses the partial index.
- **Bounded promote tick (migration 0067).** The 5s promote now processes at most 500
  most-overdue injects per tick (oldest-due first), so one tick can't run unboundedly long or
  overlap the next at thousands of concurrent sessions. Excess falls to the next tick (a due
  inject is at most a few seconds late under extreme load). 500/5s = up to 100 promotes/s.

## Capacity model (≈6 users/session, Supabase **Pro defaults**)

| Ceiling | Bites at | Lever |
|---|---|---|
| **Realtime concurrent connections** (~500 default) | **~500 online users / ~80 sessions** | **The first hard wall.** Raise Realtime *Max Concurrent Clients* (Team/Enterprise + compute add-on; Enterprise 10k+). |
| **Realtime messages/sec** (~500 default) | **~1,200 users / ~200 sessions** | Raise the messages/sec quota; optionally coalesce burst feed events into one broadcast to cut fan-out. |
| **Reconcile-pull PostgREST load** | no longer scales with users (fixed above) | — (was ~1,000 q/s at 10k users before the realtime-aware fix). |
| **promote tick serialization** | pushed to **many thousands of sessions** by 0067's LIMIT | Shard the cron by `hash(session_id)` into 2–4 jobs if concurrent *sessions* reach the low thousands. |
| **Per-session write contention** (`max(seq)+1` retry) | not a global ceiling — per-session bounded | Only inside one very hot session; a sequence/counter-based seq assignment removes retry storms if ever needed. |

**Bottom line:** after this review the **DB/app are not the binding constraint**. To run many
classes at once (thousands of concurrent users) the required steps, in order:

1. **Raise the Supabase Realtime quotas** — concurrent connections first, then messages/sec.
   This is the true hard wall and is a plan/ops change, not code. Size the DB compute add-on
   with it (pooler connections).
2. Everything else (redundant polling, promote indexing + bounding, reaper cost) is already
   handled in code.
3. **Shard the promote cron** only when concurrent *sessions* approach the low thousands.

## Monitoring to watch at scale
- Realtime: concurrent client count and messages/sec vs the plan quota (primary dashboards).
- DB: pooler connection saturation; `promote_due_injects` per-tick duration (should stay well
  under 5s) and rows/tick; pg_cron job run history for overlap/backlog.
- Table growth: `session_events` row count — all hot queries are `session_id`-scoped and
  index-backed, so latency stays flat; add a retention/archival job only past tens of millions
  of rows (storage/vacuum concern, not latency).

## Not changed (deliberately)
- **Broadcast coalescing** and **cron sharding** — real levers for the *thousands-of-sessions*
  regime, but larger changes with client-rendering / ops implications; documented above,
  deferred until the quota wall is raised (they're moot below it).
- **Append-only event model & retention** — kept; partitioning is a future storage concern.
- All migrations here are **staging-applied**; prod needs 0061–0067 run on the prod DB plus the
  Realtime quota raise before a large cohort.
