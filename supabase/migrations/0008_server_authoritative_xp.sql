-- HACK THE SOC :: 0008 — make profiles.xp server-authoritative (no reset)
-- ---------------------------------------------------------------------------
-- FINDING #6. `profiles.xp` was written straight from the browser, so any
-- signed-in user could `update({ xp: 999999 })` from devtools and inflate their
-- score / rank / leaderboard place. Migration 0005 left it as documented debt.
--
-- Persistence-migration Stages 1 & 2 (code) first routed every completion
-- (scenario_history / room_progress / dashboard_sessions) through the storage
-- facade so those tables now populate from real play. THIS migration can then
-- make xp a function of those records without losing anyone's existing total.
--
-- DESIGN — offset + records, so nothing resets:
--     xp = xp_offset + SUM(xp_earned across the three completion tables)
--   `xp_offset` is seeded per user at migration time to exactly (current xp −
--   current sum of records), so `xp` is UNCHANGED the instant this runs. It
--   captures every point earned before the tables were populated (the
--   localStorage era). Going forward, each new completion row raises the sum and
--   therefore xp; the offset stays put. No backfill of old localStorage data is
--   needed, and no user loses XP.
--
-- LOCK — column privilege. `revoke update (xp, level)` from the client roles, so
--   PostgREST denies any client UPDATE touching them. The SECURITY DEFINER
--   recompute (runs as owner) and the service role still write xp. Direct
--   inflation is dead.
--
-- RESIDUAL (documented): per-record xp_earned is still client-written for rooms
-- and dashboard sessions (client-graded), so forging COMPLETION ROWS is still
-- possible — a far higher bar than editing one number, and it leaves rows.
-- Server-authoritative grading per source is the next hardening step.

-- ── 1. The offset column ─────────────────────────────────────────────────────
alter table public.profiles
  add column if not exists xp_offset integer not null default 0;

-- ── 2. Recompute: xp := xp_offset + sum of earned XP across completion tables ─
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
  select
      coalesce((select sum(xp_earned) from public.room_progress      where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.dashboard_sessions where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.scenario_history   where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
end;
$$;

comment on function public.recompute_user_xp(uuid) is
  'Sets profiles.xp = xp_offset + sum(xp_earned) across the three completion tables. The sole writer of profiles.xp (clients are revoked from the column).';

-- ── 3. Seed the offset so xp is preserved exactly at migration time ──────────
-- xp_offset = current xp − current sum(records). Floored at 0. After this,
-- xp = xp_offset + sum(records) = the same value it is right now.
update public.profiles p
   set xp_offset = greatest(0, p.xp - (
       coalesce((select sum(xp_earned) from public.room_progress      where user_id = p.id), 0)
     + coalesce((select sum(xp_earned) from public.dashboard_sessions where user_id = p.id), 0)
     + coalesce((select sum(xp_earned) from public.scenario_history   where user_id = p.id), 0)
   ));

-- ── 4. Keep xp current on any change to a completion table ───────────────────
create or replace function public.trg_recompute_user_xp()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform public.recompute_user_xp(coalesce(new.user_id, old.user_id));
  return null;  -- AFTER trigger
end;
$$;

drop trigger if exists room_progress_recompute_xp on public.room_progress;
create trigger room_progress_recompute_xp
  after insert or update or delete on public.room_progress
  for each row execute function public.trg_recompute_user_xp();

drop trigger if exists dashboard_sessions_recompute_xp on public.dashboard_sessions;
create trigger dashboard_sessions_recompute_xp
  after insert or update or delete on public.dashboard_sessions
  for each row execute function public.trg_recompute_user_xp();

drop trigger if exists scenario_history_recompute_xp on public.scenario_history;
create trigger scenario_history_recompute_xp
  after insert or update or delete on public.scenario_history
  for each row execute function public.trg_recompute_user_xp();

-- ── 5. Take xp/level away from clients at the column level ────────────────────
-- A PostgREST update including xp or level is now denied for anon/authenticated.
-- INSERT is unaffected (the signup trigger still seeds rows); the SECURITY
-- DEFINER recompute and service_role keep full access.
revoke update (xp, level) on public.profiles from anon, authenticated;

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. Nobody's XP changed:   select id, xp, xp_offset from public.profiles;
-- 2. Client inflation denied (as a signed-in user):
--       update public.profiles set xp = 999999 where id = auth.uid();   -- ERROR
-- 3. Earning still works: complete a scenario, then confirm xp rose by its value:
--       select xp, xp_offset from public.profiles where id = auth.uid();
