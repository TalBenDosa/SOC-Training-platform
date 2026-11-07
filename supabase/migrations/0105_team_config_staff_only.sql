-- 0105: team_sessions.config is staff-only (exercise variety memory, 2026-11-07).
--
-- /start now stores what an exercise drew (benign-positive alert makers, the decoy, the twist,
-- inject variants, attack storylines) in team_sessions.config.variety, so the organization's next
-- exercises do not repeat them. config already held the instructor's attack plan
-- (config.attacks, with the chosen storyline ids). Both are answer material.
--
-- Every app read of team_sessions goes through server routes with the service role, and the
-- session GET strips config for everyone (staff get a sanitized attack_plan). But 0077 still
-- granted the config COLUMN to `authenticated`, so a player could read it straight from PostgREST
-- for their own session (RLS team_sessions_read). This re-grants the same column list without it.
-- No client code selects team_sessions directly (checked 2026-11-07), and the table is not in a
-- realtime publication, so nothing a player uses depends on the column.
--
-- Also: an index for the history read (/start: the org's last started sessions, newest first).
--
-- NOT APPLIED by the change that added it. Apply with the usual prod migration procedure.

begin;

revoke select on public.team_sessions from anon, authenticated;
grant select (id, org_id, created_by, company_id, format, difficulty, max_size, status,
              started_at, ended_at, created_at, updated_at, paused_at, paused_ms, schema_version,
              pause_reason, staff_seen_at, nudged_at, lifecycle_state)
  on public.team_sessions to authenticated;

create index if not exists team_sessions_org_started_idx
  on public.team_sessions (org_id, started_at desc)
  where started_at is not null;

commit;

-- Verify (as a signed-in player of a running session):
--   select config from team_sessions where id = '<session>';   → permission denied for table team_sessions
--   select id, status from team_sessions where id = '<session>'; → the row
