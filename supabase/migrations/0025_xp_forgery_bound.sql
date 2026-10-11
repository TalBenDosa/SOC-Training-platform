-- HACK THE SOC :: 0025 — bound forgeable per-row XP (partial mitigation)
-- ---------------------------------------------------------------------------
-- PENTEST FINDING #5 (Aug 2026). Migration 0008 made profiles.xp itself
-- server-authoritative (a client can no longer `update({xp: 999999})`), but
-- documented a residual gap: room_progress.xp_earned, dashboard_sessions.xp_earned
-- and scenario_history.xp_earned are still written directly by the client via
-- the storage facade's remote backend, and profiles.xp is DERIVED from the sum
-- of these rows (see 0008's recompute trigger). RLS on these tables checks
-- ROW OWNERSHIP (user_id = auth.uid()), not the VALUE of xp_earned — so a
-- signed-in user can still inflate their XP by INSERTing/UPDATing a
-- completion row with an arbitrary xp_earned directly against the Supabase
-- client, bypassing the app's grading entirely.
--
-- THIS IS A PARTIAL MITIGATION, NOT A FULL CLOSE. A proper fix needs
-- server-authoritative grading for dashboard sessions and scenario history
-- (rooms already have this as of the Finding #1 fix — see
-- src/lib/rooms/grading.ts and /api/rooms/[id]/tasks/[taskId]/submit — but
-- the completion ROW ITSELF is still written client-side, so this bound is
-- what stands between that and forgery for rooms too). That is a bigger
-- follow-up: routing all three completion writes through server endpoints
-- that independently recompute xp_earned, not something to attempt blind in
-- this pass. What ships here: a wide-margin CHECK constraint per table, set
-- generously above any real value the current content can produce (see the
-- numbers referenced beside each), so it cannot affect a single legitimate
-- learner while blocking the lazy/egregious version of this attack (typing a
-- large number). A determined attacker who forges a plausible-looking value
-- still gets through — that is exactly the gap the follow-up must close.

-- Rooms: the largest room today awards ~460 XP total across all its tasks
-- (see src/data/rooms-batch-28.ts). 1000 leaves headroom for content growth.
alter table public.room_progress
  drop constraint if exists room_progress_xp_earned_bound,
  add constraint room_progress_xp_earned_bound check (xp_earned >= 0 and xp_earned <= 1000);

-- Dashboard sessions accrue XP per attack caught over an open-ended session
-- length, so there's no small natural ceiling — this bound exists purely to
-- catch an obviously-fabricated value, not to cap real long sessions.
alter table public.dashboard_sessions
  drop constraint if exists dashboard_sessions_xp_earned_bound,
  add constraint dashboard_sessions_xp_earned_bound check (xp_earned >= 0 and xp_earned <= 5000);

-- Scenario history: quiz XP (sum of question xp, typically 200-500) + IOC
-- tagging bonus (10 per tagged indicator) + report-score bonus (up to 150) +
-- time bonus (up to 50) — see the xpEarned formula in
-- src/app/api/scenarios/[slug]/grade/route.ts. 2000 leaves headroom for a
-- long IOC list on a rich scenario without affecting any real submission.
alter table public.scenario_history
  drop constraint if exists scenario_history_xp_earned_bound,
  add constraint scenario_history_xp_earned_bound check (xp_earned >= 0 and xp_earned <= 2000);

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. Legitimate writes still succeed:
--      insert into room_progress (user_id, room_id, xp_earned) values (auth.uid(), 'test-room', 400);  -- OK
-- 2. Egregious forgery is rejected:
--      insert into room_progress (user_id, room_id, xp_earned) values (auth.uid(), 'test-room', 999999);  -- ERROR: check constraint
--      update scenario_history set xp_earned = 999999 where user_id = auth.uid();  -- ERROR: check constraint
