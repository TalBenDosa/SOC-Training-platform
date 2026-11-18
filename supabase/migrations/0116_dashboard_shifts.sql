-- 0116: the solo SOC Dashboard's shift record (Stage B1, dashboard review 2026-11).
--
-- Until now the browser picked the attack story AND sent its answer (title, techniques,
-- indicators) to the grader, which believed it: a hand-made request could pass any report.
-- The browser also inserted its own dashboard_sessions row (caught / presented / XP).
--
-- From here the server deals each story of a training, keeps its answer in this table and
-- grades only against it; the session row is written by the server when the training ends.
--
--   dashboard_shifts   one row per solo training: company, level, the stories dealt (each
--                      with its answer and when its first phase can appear), the best score
--                      and catch time per story, and the dashboard_sessions row it closed into.
--                      Service role only: no learner can read the answers or write the row.
--   dashboard_sessions learners keep reading their own rows; INSERT moves to the service role
--                      (the same move scenario_history made in 0077).
--
-- Idempotent. Verify after applying:
--   select relrowsecurity from pg_class where relname = 'dashboard_shifts';          -- true
--   select count(*) from pg_policies where tablename = 'dashboard_shifts';           -- 0
--   select has_table_privilege('authenticated', 'public.dashboard_shifts', 'select'); -- false
--   select has_table_privilege('authenticated', 'public.dashboard_sessions', 'insert'); -- false
--   select has_table_privilege('authenticated', 'public.dashboard_sessions', 'select'); -- true

begin;

create table if not exists public.dashboard_shifts (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references auth.users(id) on delete cascade,
  org_id       uuid references public.organizations(id) on delete cascade,
  company_id   text not null,
  difficulty   text not null check (difficulty in ('easy','medium','hard')),
  stack        jsonb not null default '{}'::jsonb,
  -- [{ storyId, title, mitre[], indicators[], dealtAt, opensAt, bestScore, caughtAt }]
  stories      jsonb not null default '[]'::jsonb,
  started_at   timestamptz not null default now(),
  ended_at     timestamptz,
  session_id   uuid references public.dashboard_sessions(id) on delete set null,
  created_at   timestamptz not null default now()
);

create index if not exists dashboard_shifts_user_idx on public.dashboard_shifts (user_id, started_at desc);
create index if not exists dashboard_shifts_org_idx  on public.dashboard_shifts (org_id);

alter table public.dashboard_shifts enable row level security;
-- No policies on purpose: only the service role (the API routes) reads or writes a shift.
revoke all on public.dashboard_shifts from anon, authenticated;

-- dashboard_sessions: the learner reads their own rows; only the service role writes them.
drop policy if exists "dashboard_sessions org self"  on public.dashboard_sessions;
drop policy if exists "dashboard_sessions self read" on public.dashboard_sessions;
create policy "dashboard_sessions self read" on public.dashboard_sessions
  for select to authenticated using (user_id = (select auth.uid()));
revoke insert, update, delete, truncate on public.dashboard_sessions from anon, authenticated;

commit;
