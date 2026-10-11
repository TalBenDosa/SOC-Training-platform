-- HACK THE SOC :: 0052 — schedule the feed tick — Phase 0.2
-- ===========================================================================
-- pg_cron promotes due injects into session_events every few seconds; the 0051
-- broadcast trigger then fans each one out to the session's private topic. Split
-- from 0051 so an extension-permission issue can't roll back the RPC core.
--
-- pg_cron 1.6+ supports sub-minute schedules. If `create extension` is not
-- permitted via the pooler role, enable pg_cron once in the dashboard
-- (Database ▸ Extensions) and re-run just the cron.schedule() block below.
-- Idempotent.
-- ===========================================================================

create extension if not exists pg_cron;

-- (re)schedule: unschedule a prior definition, then schedule every 5 seconds
do $$
begin
  perform cron.unschedule('team-promote-injects');
exception when others then null;  -- not scheduled yet
end $$;

select cron.schedule('team-promote-injects', '5 seconds', $$ select public.promote_due_injects(); $$);

-- Verification:
--   select jobname, schedule, active from cron.job where jobname='team-promote-injects';
--   select public.promote_due_injects();  -- manual tick returns rows promoted
