-- 0077 — Scenario XP: best attempt per scenario, server-written rows, locked xp
--
-- Team-exercise report 2026-09-28, finding #30: a failed scenario run earned
-- +260 XP and the retry another +470 — every attempt's xp_earned was summed, so
-- repeating a scenario farmed XP. Worse, scenario_history was client-writable
-- (RLS "ALL" on user_id = auth.uid(), xp_earned up to 2000), so XP could be
-- self-granted from the browser, and profiles.xp itself was not in the
-- privileged-column guard (a self-update could set it until the next recompute).
--
--  1. recompute_user_xp counts only the BEST xp_earned per scenario slug
--     (same rule as quizzes, 0070). Repeats only ever add the improvement.
--  2. No one loses XP: each user's past repeat surplus moves into xp_offset, so
--     today's totals are unchanged; only FUTURE repeats stop farming.
--  3. scenario_history becomes read-only to clients — the grade route
--     (/api/scenarios/[slug]/grade, service role) is the only writer.
--  4. profiles.xp / level join the guard; recompute_user_xp flags its own update
--     so it still works when it runs inside a learner's transaction (e.g. the
--     room_progress trigger).
--  5. Players can no longer read a team session's chosen storyline or seed
--     straight from PostgREST (review of #18): column-level SELECT without
--     scenario_id / seed. Every function that reads them is SECURITY DEFINER.

begin;

-- 1 + 4. Best-attempt recompute, flagged so the guard lets it through.
create or replace function public.recompute_user_xp(p_user uuid)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_records integer;
  v_offset  integer;
begin
  -- Rooms + scenarios (BEST attempt per slug, 0077) + standalone quizzes (best
  -- attempt, server-graded, 0070) + lessons (first completion after a recorded
  -- quiz pass, 0074). Dashboard practice stays excluded.
  select
      coalesce((select sum(xp_earned) from public.room_progress where user_id = p_user), 0)
    + coalesce((select sum(best) from (
                  select max(xp_earned) as best from public.scenario_history
                   where user_id = p_user group by slug) s), 0)
    + coalesce((select sum(xp_earned) from public.quiz_progress   where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.lesson_progress where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  perform set_config('app.xp_recompute', 'on', true);
  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
  perform set_config('app.xp_recompute', 'off', true);
end;
$function$;

create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql
set search_path to 'public'
as $function$
begin
  if auth.uid() is not null then
    new.id                := old.id;
    new.role              := old.role;
    new.org_id            := old.org_id;
    new.is_platform_admin := old.is_platform_admin;
    new.xp_offset         := old.xp_offset;
    -- XP is derived (recompute_user_xp is its sole writer, 0035). A learner's own
    -- session may not set it; the recompute flags its update (0077).
    if coalesce(current_setting('app.xp_recompute', true), 'off') <> 'on' then
      new.xp    := old.xp;
      new.level := old.level;
    end if;
  end if;
  return new;
end;
$function$;

-- 2. Preserve today's totals: move each user's past repeat surplus into the offset.
update public.profiles p
   set xp_offset = coalesce(p.xp_offset, 0) + s.surplus
  from (
    select user_id, sum(total - best) as surplus
      from (select user_id, slug, sum(xp_earned) as total, max(xp_earned) as best
              from public.scenario_history group by user_id, slug) t
     group by user_id
    having sum(total - best) > 0
  ) s
 where p.id = s.user_id;

-- 3. Clients may read their own history; only the service role writes it.
drop policy if exists "scenario_history org self" on public.scenario_history;
drop policy if exists "scenario_history self read" on public.scenario_history;
create policy "scenario_history self read" on public.scenario_history
  for select to authenticated using (user_id = (select auth.uid()));
revoke insert, update, delete, truncate on public.scenario_history from anon, authenticated;

-- 5. team_sessions: players keep their row (RLS) but not the storyline / seed.
revoke select on public.team_sessions from anon, authenticated;
grant select (id, org_id, created_by, company_id, format, difficulty, max_size, status, config,
              started_at, ended_at, created_at, updated_at, paused_at, paused_ms, schema_version,
              pause_reason, staff_seen_at, nudged_at, lifecycle_state)
  on public.team_sessions to authenticated;

-- Recompute everyone so xp reflects the new rule (totals unchanged by step 2).
do $$
declare r record;
begin
  for r in select id from public.profiles loop
    perform public.recompute_user_xp(r.id);
  end loop;
end $$;

commit;
