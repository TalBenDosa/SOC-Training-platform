-- HACK THE SOC :: 0101 — the learner's own progress record (Progress v2)
-- ---------------------------------------------------------------------------
-- Spec: claude-work/research/progress-redesign/SPEC-progress-self-tracking.md
--
-- The Progress page is rebuilt around "what did I do, where did I err, what to
-- strengthen, how fast do I respond, and what did my reports say". Most of what
-- the graders tell a learner was computed and thrown away. This migration keeps
-- it, server-written only (clients get SELECT on their own rows, no writes):
--
--   1. scenario_history.report_detail  the full scenario report breakdown
--                                      (per-criterion points, what to improve,
--                                      indicators cited / missed / invented,
--                                      grader note, question results).
--   2. dashboard_incidents             one row per live-feed incident report
--                                      submitted (passed / failed) or missed,
--                                      with the three response timestamps and
--                                      the three rubric sub-scores.
--   3. learning_attempts               every quiz and lesson-check attempt
--                                      (quiz_progress keeps only the best one;
--                                      a failed lesson check was never stored).
--   4. edr_case_results                the verdict of each standalone /edr case
--                                      (it lived only in React state).
--   5. graded_first_answers.org_id     so the self view and purge_org can scope
--                                      first answers to one organisation (iron
--                                      rule: nothing from one org shows in
--                                      another). Backfilled from membership.
--   6. purge_org                       also deletes all of the above.
--
-- NON-DESTRUCTIVE: new tables start empty; the new columns are nullable; no XP
-- is read from any of them. Idempotent.

-- ── 1. scenario_history.report_detail ───────────────────────────────────────
alter table public.scenario_history add column if not exists report_detail jsonb;
comment on column public.scenario_history.report_detail is
  'Full report breakdown from the grade route (items, improvements, indicators, aiFeedback, quizScore, questions[{id,correct}]). Kept out of report so the hydrate payload stays small.';

-- ── 2. dashboard_incidents ──────────────────────────────────────────────────
create table if not exists public.dashboard_incidents (
  id               bigint generated always as identity primary key,
  user_id          uuid not null references auth.users(id) on delete cascade,
  org_id           uuid references public.organizations(id) on delete cascade,
  shift_key        text check (char_length(shift_key) <= 64),
  incident_key     text check (char_length(incident_key) <= 120),
  story_id         text check (char_length(story_id) <= 120),
  title            text not null check (char_length(title) between 1 and 300),
  company          text check (char_length(company) <= 120),
  severity         text check (severity in ('critical', 'high', 'medium', 'low')),
  mitre            text[] not null default '{}',
  outcome          text not null check (outcome in ('passed', 'failed', 'missed')),
  injected_at      timestamptz,
  first_opened_at  timestamptz,
  report_opened_at timestamptz,
  submitted_at     timestamptz not null default now(),
  report_score     integer check (report_score between 0 and 100),
  attack_score     integer check (attack_score between 0 and 40),
  ioc_score        integer check (ioc_score between 0 and 30),
  action_score     integer check (action_score between 0 and 30),
  graded_by        text check (graded_by in ('ai', 'deterministic')),
  feedback         text check (char_length(feedback) <= 4000),
  strengths        text[] not null default '{}',
  gaps             text[] not null default '{}',
  summary          text check (char_length(summary) <= 4000),
  missed_tell      text check (char_length(missed_tell) <= 600),
  created_at       timestamptz not null default now()
);
create index if not exists dashboard_incidents_user_idx on public.dashboard_incidents (user_id, created_at desc);
create index if not exists dashboard_incidents_org_idx  on public.dashboard_incidents (org_id);

alter table public.dashboard_incidents enable row level security;
drop policy if exists dashboard_incidents_read_own on public.dashboard_incidents;
create policy dashboard_incidents_read_own on public.dashboard_incidents
  for select to authenticated using (user_id = auth.uid());
revoke all on public.dashboard_incidents from anon;
revoke insert, update, delete on public.dashboard_incidents from authenticated;
grant select on public.dashboard_incidents to authenticated;
grant select, insert on public.dashboard_incidents to service_role;

-- ── 3. learning_attempts ────────────────────────────────────────────────────
create table if not exists public.learning_attempts (
  id          bigint generated always as identity primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete cascade,
  kind        text not null check (kind in ('quiz', 'lesson')),
  content_id  text not null check (char_length(content_id) between 1 and 300),
  score_pct   integer not null check (score_pct between 0 and 100),
  correct     integer not null check (correct >= 0),
  total       integer not null check (total >= 0),
  passed      boolean not null,
  created_at  timestamptz not null default now()
);
create index if not exists learning_attempts_user_idx on public.learning_attempts (user_id, created_at desc);
create index if not exists learning_attempts_org_idx  on public.learning_attempts (org_id);

alter table public.learning_attempts enable row level security;
drop policy if exists learning_attempts_read_own on public.learning_attempts;
create policy learning_attempts_read_own on public.learning_attempts
  for select to authenticated using (user_id = auth.uid());
revoke all on public.learning_attempts from anon;
revoke insert, update, delete on public.learning_attempts from authenticated;
grant select on public.learning_attempts to authenticated;
grant select, insert on public.learning_attempts to service_role;

-- ── 4. edr_case_results ─────────────────────────────────────────────────────
create table if not exists public.edr_case_results (
  id           bigint generated always as identity primary key,
  user_id      uuid not null references auth.users(id) on delete cascade,
  org_id       uuid references public.organizations(id) on delete cascade,
  case_id      text not null check (char_length(case_id) between 1 and 120),
  title        text check (char_length(title) <= 300),
  chosen       text check (char_length(chosen) <= 120),
  correct      boolean not null,
  duration_ms  integer check (duration_ms between 0 and 86400000),
  created_at   timestamptz not null default now()
);
create index if not exists edr_case_results_user_idx on public.edr_case_results (user_id, created_at desc);
create index if not exists edr_case_results_org_idx  on public.edr_case_results (org_id);

alter table public.edr_case_results enable row level security;
drop policy if exists edr_case_results_read_own on public.edr_case_results;
create policy edr_case_results_read_own on public.edr_case_results
  for select to authenticated using (user_id = auth.uid());
revoke all on public.edr_case_results from anon;
revoke insert, update, delete on public.edr_case_results from authenticated;
grant select on public.edr_case_results to authenticated;
grant select, insert on public.edr_case_results to service_role;

-- ── Bounded per user (these are records, not an unbounded log) ──────────────
create or replace function public.progress_rows_cap()
returns trigger
language plpgsql
set search_path = public
as $$
declare
  v_count integer;
begin
  execute format('select count(*) from public.%I where user_id = $1', tg_table_name)
    into v_count using new.user_id;
  if v_count >= 20000 then
    return null;   -- past a generous cap, further rows are dropped silently
  end if;
  return new;
end;
$$;
drop trigger if exists dashboard_incidents_cap on public.dashboard_incidents;
create trigger dashboard_incidents_cap before insert on public.dashboard_incidents
  for each row execute function public.progress_rows_cap();
drop trigger if exists learning_attempts_cap on public.learning_attempts;
create trigger learning_attempts_cap before insert on public.learning_attempts
  for each row execute function public.progress_rows_cap();
drop trigger if exists edr_case_results_cap on public.edr_case_results;
create trigger edr_case_results_cap before insert on public.edr_case_results
  for each row execute function public.progress_rows_cap();

-- ── 5. graded_first_answers.org_id ──────────────────────────────────────────
alter table public.graded_first_answers add column if not exists org_id uuid;
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'graded_first_answers_org_id_fkey') then
    alter table public.graded_first_answers
      add constraint graded_first_answers_org_id_fkey foreign key (org_id)
      references public.organizations(id) on delete set null;
  end if;
end $$;
create index if not exists graded_first_answers_user_org_idx on public.graded_first_answers (user_id, org_id);

-- Backfill: the org the learner had most recently joined when they answered.
update public.graded_first_answers g
   set org_id = (
     select m.org_id from public.org_members m
      where m.user_id = g.user_id
        and m.joined_at <= g.created_at
      order by m.joined_at desc
      limit 1)
 where g.org_id is null;

-- ── 6. purge_org — same body as 0080 plus the progress records ──────────────
create or replace function public.purge_org(p_org uuid)
 returns void
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
begin
  if p_org = 'd0d0d0d0-0000-4000-8000-000000000000' then
    raise exception 'cannot_purge_internal';
  end if;

  delete from public.room_progress     where org_id = p_org;
  delete from public.dashboard_sessions where org_id = p_org;
  delete from public.scenario_history   where org_id = p_org;
  delete from public.ai_usage           where org_id = p_org;
  delete from public.user_progress      where org_id = p_org;
  -- 0080 (P4-13): the rest of the learner data earned in this college.
  delete from public.quiz_progress      where org_id = p_org;
  delete from public.lesson_progress    where org_id = p_org;
  delete from public.task_attempts      where org_id = p_org;
  -- 0101: the learner's own progress records.
  delete from public.dashboard_incidents  where org_id = p_org;
  delete from public.learning_attempts    where org_id = p_org;
  delete from public.edr_case_results     where org_id = p_org;
  delete from public.graded_first_answers where org_id = p_org;

  -- Preserve the audit trail but drop the tenant FK (nullable) so the org delete
  -- below can't be blocked by audit_log_org_id_fkey.
  update public.audit_log set org_id = null where org_id = p_org;

  -- Re-home the accounts to the internal org so their NOT NULL org_id FK stays
  -- valid and they can still sign in after the college leaves.
  update public.profiles set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id = p_org;

  delete from public.org_members  where org_id = p_org;
  delete from public.invitations  where org_id = p_org;
  delete from public.organizations where id = p_org;
end;
$function$;
revoke execute on function public.purge_org(uuid) from public, anon, authenticated;
grant  execute on function public.purge_org(uuid) to service_role;
