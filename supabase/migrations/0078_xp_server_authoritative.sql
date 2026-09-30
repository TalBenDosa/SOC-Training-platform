-- HACK THE SOC :: 0078 — XP is computed and recorded by the SERVER only
-- ---------------------------------------------------------------------------
-- QA audit (2026-09-30) found the remaining client-side XP paths:
--   AUTH-002  room_progress was writable by the signed-in user (any room_id, up
--             to 1000 XP per row → unlimited XP, e.g. rooms that don't exist).
--   AUTH-007  quiz / lesson / scenario grading was stateless: grade once to see
--             the answers, resubmit for full XP.
--   P3-02     recompute_user_xp summed the tables with no lock, so two credits
--             landing at once could write a stale profiles.xp total.
-- After this migration every XP-bearing row is written by service-role API
-- routes from values PRE-DEFINED in the content (task/question xp), and the
-- grading history the XP is derived from is server-held.

-- ── 1. room_progress: server is the only writer ─────────────────────────────
-- Reads stay (RLS "room_progress org self" / "org staff read"). Writes now go
-- through record_room_task() below, called by POST /api/rooms/[id]/tasks/[t]/complete.
revoke insert, update, delete on public.room_progress from anon, authenticated;

-- ── 2. task_attempts: the server-graded source of room XP ───────────────────
-- xp_awarded = what the grader awarded for THAT submission (pre-defined task xp,
-- attempt policy applied server-side). question_index scopes log_analysis
-- sub-questions. Clients could previously UPDATE/DELETE their own attempts.
alter table public.task_attempts add column if not exists xp_awarded integer not null default 0;
alter table public.task_attempts add column if not exists question_index integer;
alter table public.task_attempts drop constraint if exists task_attempts_xp_awarded_bound;
alter table public.task_attempts add constraint task_attempts_xp_awarded_bound check (xp_awarded >= 0 and xp_awarded <= 1000);
revoke insert, update, delete on public.task_attempts from anon, authenticated;
create index if not exists task_attempts_user_room_task_idx on public.task_attempts (user_id, room_id, task_id);

-- ── 3. record_room_task — atomic, idempotent room-progress credit ────────────
-- Merges one task's server-derived XP into room_progress (per-task BEST, never
-- lowered), marks the task completed, recomputes xp_earned, and stamps
-- completed_at the first time every task is done AND the gradeable score meets
-- the pass threshold (the same 65% rule the room page applies). Serialised per
-- (user, room) so concurrent completions can't lose each other's merge.
create or replace function public.record_room_task(
  p_user uuid,
  p_org uuid,
  p_room text,
  p_task text,
  p_task_xp integer,
  p_room_task_ids text[],
  p_gradeable jsonb,          -- { taskId: maxXp } for gradeable tasks only
  p_pass_threshold numeric,
  p_telemetry jsonb default null
) returns table (task_xp integer, room_xp integer, room_completed_at timestamptz, newly_completed boolean)
  language plpgsql
  security definer set search_path = public
as $$
declare
  v_row        public.room_progress%rowtype;
  v_map        jsonb;
  v_ids        jsonb;
  v_sum        integer;
  v_done       boolean;
  v_score      numeric;
  v_max        numeric;
  v_prev_done  timestamptz;
  v_tele       jsonb;
begin
  if p_user is null or coalesce(p_room, '') = '' or coalesce(p_task, '') = '' then
    raise exception 'record_room_task: user, room and task are required';
  end if;
  perform pg_advisory_xact_lock(hashtext('room:' || p_user::text || ':' || p_room));

  insert into public.room_progress (user_id, room_id, org_id, completed_task_ids, per_task_xp, xp_earned, telemetry)
  values (p_user, p_room, p_org, '[]'::jsonb, '{}'::jsonb, 0, '[]'::jsonb)
  on conflict (user_id, room_id) do nothing;

  select * into v_row from public.room_progress where user_id = p_user and room_id = p_room for update;
  v_prev_done := v_row.completed_at;

  v_map := coalesce(v_row.per_task_xp, '{}'::jsonb);
  v_map := v_map || jsonb_build_object(
    p_task, greatest(coalesce((v_map->>p_task)::int, 0), greatest(0, least(1000, coalesce(p_task_xp, 0)))));

  v_ids := coalesce(v_row.completed_task_ids, '[]'::jsonb);
  if not (v_ids ? p_task) then v_ids := v_ids || to_jsonb(p_task); end if;

  select coalesce(sum(value::int), 0) into v_sum from jsonb_each_text(v_map);

  select coalesce(bool_and(v_ids ? t), false) into v_done from unnest(p_room_task_ids) as t;
  select coalesce(sum(least(coalesce((v_map->>g.key)::int, 0), g.value::int)), 0),
         coalesce(sum(g.value::int), 0)
    into v_score, v_max
    from jsonb_each_text(coalesce(p_gradeable, '{}'::jsonb)) as g;

  v_tele := coalesce(v_row.telemetry, '[]'::jsonb);
  if p_telemetry is not null and jsonb_array_length(v_tele) < 500 then
    v_tele := v_tele || jsonb_build_array(p_telemetry);
  end if;

  update public.room_progress set
    per_task_xp        = v_map,
    completed_task_ids = v_ids,
    xp_earned          = least(1000, v_sum),
    org_id             = coalesce(p_org, org_id),
    telemetry          = v_tele,
    completed_at       = coalesce(completed_at,
                           case when v_done and (v_max = 0 or v_score / v_max >= p_pass_threshold) then now() end),
    updated_at         = now()
  where user_id = p_user and room_id = p_room
  returning * into v_row;

  return query select (v_map->>p_task)::int, v_row.xp_earned, v_row.completed_at,
                      (v_prev_done is null and v_row.completed_at is not null);
end;
$$;
revoke all on function public.record_room_task(uuid, uuid, text, text, integer, text[], jsonb, numeric, jsonb) from public, anon, authenticated;
grant execute on function public.record_room_task(uuid, uuid, text, text, integer, text[], jsonb, numeric, jsonb) to service_role;

-- ── 4. graded_first_answers — the first graded answer per question sticks ────
-- XP for quizzes, lesson quizzes and scenario questions is derived from the
-- FIRST answer the server graded for each question, so seeing the answer on one
-- attempt can't be turned into full XP on the next. Service-role only.
create table if not exists public.graded_first_answers (
  user_id     uuid not null references auth.users(id) on delete cascade,
  kind        text not null check (kind in ('quiz', 'lesson', 'scenario')),
  content_id  text not null,
  question_id text not null,
  answer      jsonb,
  correct     boolean not null,
  created_at  timestamptz not null default now(),
  primary key (user_id, kind, content_id, question_id)
);
alter table public.graded_first_answers enable row level security;
revoke all on public.graded_first_answers from anon, authenticated;
grant select, insert on public.graded_first_answers to service_role;

-- ── 5. recompute_user_xp — serialised per user (P3-02 lost update) ───────────
-- Same body as 0077 plus a per-user transaction lock taken BEFORE the sums, so
-- a concurrent credit's recompute runs after this one commits and sees it.
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
$$;

-- ── 6. Org quiz answer keys out of the browser's reach (AUTH-009) ────────────
-- content_quizzes.content holds the FULL quiz, answers included, and was
-- SELECT-able by any signed-in member of the org (0019 grant + 0040 policy).
-- The quiz page sanitised it only in memory — the key was in the network
-- response, which would let a student answer every question right the first
-- time and defeat the first-answer rule above. Students now read published
-- quizzes through published_quizzes(), which applies the same visibility rule
-- as the RLS policy and strips answer/explanation from every question. The
-- `content` column is no longer granted to client roles (the other columns stay
-- readable, so nothing else that lists quizzes changes). Grading, the editors
-- and the plan catalogue already read with the service role.

create or replace function public.strip_quiz_key(c jsonb)
returns jsonb
language sql
immutable
set search_path = public
as $$
  select case
    when jsonb_typeof(c->'questions') = 'array' then
      jsonb_set(c, '{questions}', coalesce(
        (select jsonb_agg(case when jsonb_typeof(q) = 'object' then q - 'answer' - 'explanation' else q end order by ord)
           from jsonb_array_elements(c->'questions') with ordinality as t(q, ord)),
        '[]'::jsonb))
    else c
  end
$$;

create or replace function public.published_quizzes()
returns table (id text, content jsonb)
language sql
stable
security definer
set search_path = public
as $$
  select q.id, public.strip_quiz_key(q.content)
    from public.content_quizzes q
   where q.status = 'published'
     and (q.org_id is null or q.org_id = public.current_org())
   order by q.created_at desc
$$;

revoke all on function public.strip_quiz_key(jsonb) from public;
revoke all on function public.published_quizzes() from public, anon;
grant execute on function public.strip_quiz_key(jsonb) to authenticated, service_role;
grant execute on function public.published_quizzes() to authenticated, service_role;

revoke select on public.content_quizzes from authenticated;
grant select (id, org_id, status, title, created_by, created_at, updated_at) on public.content_quizzes to authenticated;

-- ── Verify (run manually after applying) ─────────────────────────────────────
-- As a signed-in student:
--   insert into room_progress (user_id, room_id, xp_earned) values (auth.uid(), 'fake', 1000);  → permission denied
--   update task_attempts set xp_awarded = 999 where user_id = auth.uid();                      → permission denied
--   select * from graded_first_answers;                                                        → permission denied
--   select content from content_quizzes;                                                       → permission denied
--   select * from published_quizzes();                                                         → no answer / explanation keys
-- As service_role:
--   select * from record_room_task('<uid>', null, '<room>', '<task>', 20, array['<task>'], '{"<task>":20}', 0.65);
--   → task_xp 20, room_xp 20, room_completed_at set, newly_completed true; profiles.xp includes it.
