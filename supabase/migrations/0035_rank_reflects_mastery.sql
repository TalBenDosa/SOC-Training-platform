-- HACK THE SOC :: 0035 — rank/leaderboard reflect MASTERY, not ungated practice
-- ---------------------------------------------------------------------------
-- PM audit F3. profiles.xp (which drives Rank, the Topbar tier, and the B2B
-- org leaderboard) was `xp_offset + sum(xp_earned)` across THREE tables —
-- room_progress, scenario_history, AND dashboard_sessions (0008). The dashboard
-- is the ONE surface with no mastery gate: a learner can grind the live feed
-- from day one and "level up" without passing a single graded room. That makes
-- the Rank a college sees an unreliable measure of competence — it mixes gated
-- mastery with ungated practice.
--
-- FIX: rank now derives from the GATED content only (rooms + scenarios).
-- Dashboard practice still persists in dashboard_sessions for history/stats and
-- is shown as per-session feedback — it just no longer moves the rank.
--
-- NON-DESTRUCTIVE: nobody loses their current number. We re-seed xp_offset to
-- absorb each user's PAST dashboard XP, so profiles.xp is UNCHANGED the instant
-- this runs. Only FUTURE dashboard sessions stop contributing to rank. (The
-- client stops adding dashboard XP to its local total in the same change, so the
-- optimistic Topbar rank and the server-authoritative leaderboard stay in
-- agreement — see dashboard/page.tsx.)
--
-- Order matters: the re-seed below reads the OLD three-table sum, so it must run
-- BEFORE recompute_user_xp is redefined to the two-table sum.

-- ── 1. Re-seed offset so the current total is preserved exactly ──────────────
--   new_offset = current xp − (rooms + scenarios)
--            = old_offset + (past dashboard XP)
-- After the redefinition below, xp = new_offset + rooms + scenarios = old xp.
update public.profiles p
   set xp_offset = greatest(0, p.xp - (
       coalesce((select sum(xp_earned) from public.room_progress    where user_id = p.id), 0)
     + coalesce((select sum(xp_earned) from public.scenario_history where user_id = p.id), 0)
   ));

-- ── 2. Recompute from GATED tables only (drop the dashboard_sessions term) ────
create or replace function public.recompute_user_xp(p_user uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_records integer;
  v_offset  integer;
begin
  -- Mastery only: rooms + scenarios. Dashboard practice is deliberately excluded
  -- (it has no mastery gate) — see migration header.
  select
      coalesce((select sum(xp_earned) from public.room_progress    where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.scenario_history where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
end;
$$;

comment on function public.recompute_user_xp(uuid) is
  'Sets profiles.xp = xp_offset + sum(xp_earned) across the GATED completion tables (room_progress + scenario_history). Dashboard practice is excluded so Rank reflects mastery, not ungated live-feed grinding. Sole writer of profiles.xp.';

-- ── 3. Drop the now-pointless dashboard trigger ──────────────────────────────
-- dashboard_sessions rows still insert (history/stats), but they no longer need
-- to recompute xp — the sum ignores that table now.
drop trigger if exists dashboard_sessions_recompute_xp on public.dashboard_sessions;

-- ── 4. Realign every existing profile to the new (identical) total ───────────
-- With the offset re-seeded in step 1, this is a no-op on the number for every
-- user; it just makes profiles.xp consistent with the new function immediately
-- rather than on their next room/scenario completion.
do $$
declare r record;
begin
  for r in select id from public.profiles loop
    perform public.recompute_user_xp(r.id);
  end loop;
end $$;

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. No totals changed:
--       select id, xp, xp_offset from public.profiles order by xp desc;
--    (compare against a pre-migration snapshot — every xp is identical.)
-- 2. Dashboard no longer moves rank: insert a dashboard_sessions row with
--    xp_earned > 0 for a test user, then confirm profiles.xp is UNCHANGED.
-- 3. Rooms still raise xp: complete a room, confirm xp rose by its value.
