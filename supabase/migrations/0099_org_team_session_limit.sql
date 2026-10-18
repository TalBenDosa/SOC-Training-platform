-- 0099: how many team exercises (Team Training) an organization may run (Tal, 2026-10-18).
--
-- Team Training is sold as a premium, limited experience: the super-admin sets a cap per
-- organization when creating it or in its licence settings. NULL = unlimited (every existing
-- organization keeps working as before), 0 = no team exercises, N = N exercises. An exercise
-- counts once it STARTS (team_sessions.started_at), so a lobby that was never started is free.
-- Enforced by the app routes (POST /api/team/sessions and /start), which run with the service
-- role; organizations stays readable by its own members under the existing RLS.
--
-- Verify: select column_name, data_type, is_nullable from information_schema.columns
--          where table_schema = 'public' and table_name = 'organizations' and column_name = 'team_session_limit';
--         -> integer, YES

alter table public.organizations
  add column if not exists team_session_limit integer
  constraint organizations_team_session_limit_nonneg check (team_session_limit is null or team_session_limit >= 0);

comment on column public.organizations.team_session_limit is
  'Team exercises the organization may start (NULL = unlimited, 0 = none). Counted from team_sessions.started_at.';
