-- HACK THE SOC :: 0074 — "I practice but my points don't go up" (XP credit fixes)
-- ---------------------------------------------------------------------------
-- Follows 0070 (quiz XP). Audit 2026-09 found four more ways real practice
-- failed to reach profiles.xp (the overall score / rank / leaderboard):
--
--   1. LESSONS promised "+XP" on "Mark Complete" but recorded nothing anywhere.
--      → lesson_progress (one row per user+lesson), written ONLY server-side:
--        the lesson-quiz grade route stamps quiz_passed_at when a signed-in
--        learner passes (record_lesson_quiz_pass), and the complete route calls
--        complete_lesson(), which credits the lesson's catalog XP (decided by
--        the server from src/lib/lessons/paths.ts, never by the client) ONCE —
--        first completion only, only after a recorded quiz pass, capped 0..1000.
--        Clients get SELECT on their own rows and no write grants.
--
--   2. ROOM progress could be OVERWRITTEN WITH LOWER VALUES (a hard reload
--      started RoomClient from an empty state before the remote hydrate landed,
--      and the next save replaced the server row). The client now merges, and
--      this migration adds a DB-side guarantee: a user-driven UPDATE of a
--      room_progress row can never lower xp_earned or any per-task best in
--      per_task_xp, and never clears completed_at. (Service-role writes — admin
--      corrections — are left alone.)
--
--   3. ORG SWITCH stranded rows: the "<t> org self" policies (0011) required
--      org_id = current_org() in USING, so after an active-org change a learner
--      could neither read nor update their own earlier room_progress /
--      scenario_history rows — and because the client upserted every room in
--      one statement, one stranded row made EVERY later room save fail. Same fix
--      0046 applied to user_progress: USING only pins user_id = auth.uid();
--      WITH CHECK still pins org_id = current_org(), so writes are stamped with
--      the caller's CURRENT org (the upsert re-stamps a migrated row). The
--      "<t> org staff read" policies are untouched, so org staff visibility and
--      tenant isolation are unchanged.
--
--   4. recompute_user_xp gains the lesson term:
--        xp = xp_offset + rooms + scenarios + quizzes (0070) + lessons (new)
--      Dashboard practice stays excluded (0035 — pending product decision).
--
-- NON-DESTRUCTIVE: lesson_progress starts empty, so the recompute's sum is
-- identical the instant this runs. Defensively, xp_offset is re-seeded with
-- 0035's pattern (offset = current xp − new sum, floored at 0) so NO profile's
-- xp can drop even if some row was out of sync; for every consistent profile
-- that is a no-op. Idempotent: safe to run more than once.

-- ── 1. lesson_progress ───────────────────────────────────────────────────────
create table if not exists public.lesson_progress (
    user_id         uuid        not null references auth.users(id) on delete cascade,
    lesson_key      text        not null check (char_length(lesson_key) between 3 and 300), -- "{pathSlug}--{lessonSlug}"
    org_id          uuid,
    quiz_passed_at  timestamptz,                         -- first recorded pass of the lesson's knowledge check
    best_quiz_pct   integer     not null default 0 check (best_quiz_pct between 0 and 100),
    xp_earned       integer     not null default 0 check (xp_earned >= 0 and xp_earned <= 1000),
    completed_at    timestamptz,                         -- null = not completed (no XP yet)
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    primary key (user_id, lesson_key)
);
create index if not exists lesson_progress_user_idx on public.lesson_progress(user_id);

drop trigger if exists lesson_progress_touch on public.lesson_progress;
create trigger lesson_progress_touch before update on public.lesson_progress
  for each row execute function public.touch_updated_at();

-- RLS: read your own rows; no client writes at all.
alter table public.lesson_progress enable row level security;
drop policy if exists lesson_progress_read_own on public.lesson_progress;
create policy lesson_progress_read_own on public.lesson_progress
  for select to authenticated
  using (user_id = auth.uid());
revoke all on public.lesson_progress from anon;
revoke insert, update, delete on public.lesson_progress from authenticated;
grant select on public.lesson_progress to authenticated;

-- ── 2. Offset re-seed (0035 pattern) BEFORE the recompute is redefined ───────
-- new_offset = current xp − (rooms + scenarios + quizzes + lessons). With the
-- new function below, xp = new_offset + that sum = current xp. Only rows whose
-- offset actually needs to move are touched (a no-op for consistent profiles).
update public.profiles p
   set xp_offset = s.new_offset
  from (
    select p2.id,
           greatest(0, p2.xp - (
               coalesce((select sum(xp_earned) from public.room_progress    where user_id = p2.id), 0)
             + coalesce((select sum(xp_earned) from public.scenario_history where user_id = p2.id), 0)
             + coalesce((select sum(xp_earned) from public.quiz_progress    where user_id = p2.id), 0)
             + coalesce((select sum(xp_earned) from public.lesson_progress  where user_id = p2.id), 0)
           )) as new_offset
      from public.profiles p2
  ) s
 where s.id = p.id
   and p.xp_offset is distinct from s.new_offset;

-- ── 3. Recompute: rooms + scenarios + quizzes + lessons ──────────────────────
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
  -- Rooms + scenarios (gated mastery, 0035) + standalone quizzes (best attempt,
  -- server-graded, 0070) + lessons (first completion after a recorded quiz
  -- pass, server-decided XP, 0074). Dashboard practice stays excluded.
  select
      coalesce((select sum(xp_earned) from public.room_progress    where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.scenario_history where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.quiz_progress    where user_id = p_user), 0)
    + coalesce((select sum(xp_earned) from public.lesson_progress  where user_id = p_user), 0)
  into v_records;

  select coalesce(xp_offset, 0) into v_offset from public.profiles where id = p_user;

  update public.profiles
     set xp = greatest(0, v_offset + v_records)
   where id = p_user;
end;
$$;

comment on function public.recompute_user_xp(uuid) is
  'Sets profiles.xp = xp_offset + sum(xp_earned) across room_progress + scenario_history + quiz_progress + lesson_progress. Dashboard practice is excluded (0035). Sole writer of profiles.xp.';

drop trigger if exists lesson_progress_recompute_xp on public.lesson_progress;
create trigger lesson_progress_recompute_xp
  after insert or update or delete on public.lesson_progress
  for each row execute function public.trg_recompute_user_xp();

-- Realign every profile to the new function (a no-op on the number after §2).
do $$
declare r record;
begin
  for r in select id from public.profiles loop
    perform public.recompute_user_xp(r.id);
  end loop;
end $$;

-- ── 4. Lesson writers (service role only) ────────────────────────────────────
-- 4a. Record a passed knowledge check. Called by POST
--     /api/lessons/[slug]/quiz/grade after it grades a PASS server-side.
create or replace function public.record_lesson_quiz_pass(
  p_user uuid, p_key text, p_org uuid, p_pct integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.lesson_progress as l (user_id, lesson_key, org_id, quiz_passed_at, best_quiz_pct)
  values (p_user, p_key, p_org, now(), least(greatest(coalesce(p_pct, 0), 0), 100))
  on conflict (user_id, lesson_key) do update set
      quiz_passed_at = coalesce(l.quiz_passed_at, excluded.quiz_passed_at),
      best_quiz_pct  = greatest(l.best_quiz_pct, excluded.best_quiz_pct),
      org_id         = coalesce(excluded.org_id, l.org_id);
end;
$$;
revoke execute on function public.record_lesson_quiz_pass(uuid, text, uuid, integer) from public, anon, authenticated;
grant  execute on function public.record_lesson_quiz_pass(uuid, text, uuid, integer) to service_role;

-- 4b. Complete a lesson. Credits p_xp (the catalog value the ROUTE looked up)
--     exactly once, only after a recorded quiz pass. The row lock serialises two
--     concurrent "Mark Complete" clicks: the second sees completed_at and gets
--     'already'. The recompute trigger has updated profiles.xp by the time the
--     final select runs, so total_xp is the new overall score.
--     status: 'credited' | 'already' | 'quiz_not_passed'
create or replace function public.complete_lesson(
  p_user uuid, p_key text, p_org uuid, p_xp integer)
returns table(status text, credited integer, xp_earned integer, total_xp integer, completed_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_row public.lesson_progress%rowtype;
  v_xp  integer := least(greatest(coalesce(p_xp, 0), 0), 1000);
begin
  select * into v_row from public.lesson_progress l
   where l.user_id = p_user and l.lesson_key = p_key
   for update;

  if not found or v_row.quiz_passed_at is null then
    return query select 'quiz_not_passed'::text, 0, 0,
      (select p.xp from public.profiles p where p.id = p_user), null::timestamptz;
    return;
  end if;

  if v_row.completed_at is not null then
    return query select 'already'::text, 0, v_row.xp_earned,
      (select p.xp from public.profiles p where p.id = p_user), v_row.completed_at;
    return;
  end if;

  update public.lesson_progress l
     set completed_at = now(),
         xp_earned    = v_xp,
         org_id       = coalesce(p_org, l.org_id)
   where l.user_id = p_user and l.lesson_key = p_key;

  return query
    select 'credited'::text, l.xp_earned, l.xp_earned, p.xp, l.completed_at
      from public.lesson_progress l join public.profiles p on p.id = l.user_id
     where l.user_id = p_user and l.lesson_key = p_key;
end;
$$;
revoke execute on function public.complete_lesson(uuid, text, uuid, integer) from public, anon, authenticated;
grant  execute on function public.complete_lesson(uuid, text, uuid, integer) to service_role;

-- ── 5. room_progress: user-driven updates never lower earned progress ────────
-- per-task best: max of old/new for every task id (numeric values only; a
-- non-numeric value is dropped rather than failing the write).
create or replace function public.merge_task_xp_max(p_old jsonb, p_new jsonb)
returns jsonb
language sql
immutable
set search_path = public
as $$
  select coalesce(jsonb_object_agg(k, v), '{}'::jsonb)
    from (
      select k, max(v) as v
        from (
          select e.key as k, (e.value #>> '{}')::numeric as v
            from jsonb_each(case when jsonb_typeof(p_old) = 'object' then p_old else '{}'::jsonb end) e
           where jsonb_typeof(e.value) = 'number'
          union all
          select e.key, (e.value #>> '{}')::numeric
            from jsonb_each(case when jsonb_typeof(p_new) = 'object' then p_new else '{}'::jsonb end) e
           where jsonb_typeof(e.value) = 'number'
        ) u
       group by k
    ) m;
$$;

create or replace function public.guard_room_progress_monotonic()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  -- Only user-driven writes (the browser's upsert). The service role and SQL
  -- maintenance run with auth.uid() = null and may correct values freely.
  if auth.uid() is not null then
    new.per_task_xp  := public.merge_task_xp_max(old.per_task_xp, new.per_task_xp);
    new.xp_earned    := least(1000, greatest(coalesce(old.xp_earned, 0), coalesce(new.xp_earned, 0)));
    new.completed_at := coalesce(old.completed_at, new.completed_at);
  end if;
  return new;
end;
$$;

drop trigger if exists room_progress_guard_monotonic on public.room_progress;
create trigger room_progress_guard_monotonic
  before update on public.room_progress
  for each row execute function public.guard_room_progress_monotonic();

-- ── 6. Org switch: self rows stay readable/updatable (mirror of 0046) ────────
alter policy "room_progress org self" on public.room_progress
  using (user_id = auth.uid())
  with check ((user_id = auth.uid()) and (org_id = public.current_org()));

alter policy "scenario_history org self" on public.scenario_history
  using (user_id = auth.uid())
  with check ((user_id = auth.uid()) and (org_id = public.current_org()));

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. No totals changed: compare `select id, xp from profiles` to a pre-snapshot.
-- 2. Lessons: complete_lesson before a pass → 'quiz_not_passed'; after
--    record_lesson_quiz_pass → 'credited' (+catalog XP on profiles.xp);
--    again → 'already' (no change). An authenticated client cannot insert/update
--    lesson_progress or execute either writer.
-- 3. room_progress: as an authenticated user, upsert a row with lower xp_earned
--    / per_task_xp / null completed_at → stored values unchanged.
-- 4. Policies: pg_policies shows "<t> org self" USING (user_id = auth.uid()).
