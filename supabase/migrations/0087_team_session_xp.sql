-- 0087 — team training earns XP.
--
-- Team exercises awarded nothing: recompute_user_xp summed rooms, scenarios,
-- quizzes and lessons only. Each player's XP for a session is now computed on
-- the server from the after-action report (src/lib/team/teamXp.ts), written
-- here by award_team_session_xp (service role only) and included in the total.
-- The value is deterministic from the frozen log, so re-awarding replaces the
-- row instead of adding to it.

create table if not exists public.team_session_xp (
  session_id      uuid not null references public.team_sessions(id) on delete cascade,
  user_id         uuid not null references auth.users(id) on delete cascade,
  xp              integer not null check (xp between 0 and 200),
  formula_version integer not null default 1,
  computed_at     timestamptz not null default now(),
  primary key (session_id, user_id)
);
create index if not exists team_session_xp_user_idx on public.team_session_xp (user_id);

alter table public.team_session_xp enable row level security;
revoke all on public.team_session_xp from public, anon, authenticated;
grant select on public.team_session_xp to authenticated;
grant all on public.team_session_xp to service_role;
drop policy if exists team_session_xp_own on public.team_session_xp;
create policy team_session_xp_own on public.team_session_xp for select to authenticated
  using (user_id = (select auth.uid()));

-- Upsert one session's awards and recompute each player's total, in one
-- transaction. Only for an ended session, only for its own roster.
create or replace function public.award_team_session_xp(p_session uuid, p_rows jsonb, p_version integer default 1)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare r record; v_n integer := 0;
begin
  if not exists (select 1 from public.team_sessions where id = p_session and status in ('ended','debriefed')) then
    raise exception 'award_team_session_xp: session % has not ended', p_session;
  end if;
  for r in
    select (x->>'user_id')::uuid as uid, greatest(0, least(200, coalesce((x->>'xp')::int, 0))) as xp
      from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) x
  loop
    if not exists (select 1 from public.team_session_members m where m.session_id = p_session and m.user_id = r.uid) then
      continue;   -- not on this session's roster
    end if;
    insert into public.team_session_xp (session_id, user_id, xp, formula_version, computed_at)
    values (p_session, r.uid, r.xp, p_version, now())
    on conflict (session_id, user_id) do update
      set xp = excluded.xp, formula_version = excluded.formula_version, computed_at = excluded.computed_at;
    perform public.recompute_user_xp(r.uid);
    v_n := v_n + 1;
  end loop;
  return v_n;
end;
$$;
revoke all on function public.award_team_session_xp(uuid, jsonb, integer) from public, anon, authenticated;
grant execute on function public.award_team_session_xp(uuid, jsonb, integer) to service_role;

-- recompute_user_xp: the 0078 body + team training.
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
  perform pg_advisory_xact_lock(hashtext('xp:' || p_user::text));

  -- Rooms + scenarios (BEST attempt per slug, 0077) + standalone quizzes (best
  -- attempt, server-graded, 0070) + lessons (first completion after a recorded
  -- quiz pass, 0074) + team exercises (server-computed per session, 0087).
  -- Dashboard practice stays excluded.
  select
      coalesce((select sum(xp_earned) from public.room_progress where user_id = p_user), 0)
    + coalesce((select sum(best) from (
                  select max(xp_earned) as best from public.scenario_history
                   where user_id = p_user group by slug) s), 0)
    + coalesce((select sum(xp_earned) from public.quiz_progress   where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.lesson_progress where user_id = p_user), 0)
    + coalesce((select sum(xp)        from public.team_session_xp where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  perform set_config('app.xp_recompute', 'on', true);
  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
  perform set_config('app.xp_recompute', 'off', true);
end;
$$;
revoke execute on function public.recompute_user_xp(uuid) from public, anon, authenticated;
grant  execute on function public.recompute_user_xp(uuid) to service_role;
