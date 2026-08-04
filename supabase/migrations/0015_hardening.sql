-- HACK THE SOC :: 0015 — Phase 5 hardening
-- ===========================================================================
-- 1. Drop the speculative 0001 tables the app never used (they carry RLS and
--    attack surface for no benefit — verified unreferenced in src/).
-- 2. purge_org(): atomic offboarding — delete a college's learner data, re-home
--    its accounts to the internal org (so logins survive), then delete the org.
-- Run after 0010–0014, and AFTER exporting any org you intend to purge. Claude
-- cannot run it.

-- ── 1. Remove unused scaffold (app uses only the 0002 tables + profiles) ────
drop view  if exists public.leaderboard cascade;
drop table if exists public.ai_messages          cascade;
drop table if exists public.ai_conversations     cascade;
drop table if exists public.xp_events            cascade;
drop table if exists public.user_badges          cascade;
drop table if exists public.badges               cascade;
drop table if exists public.detections           cascade;
drop table if exists public.hunts                cascade;
drop table if exists public.investigation_notes  cascade;
drop table if exists public.investigations       cascade;
drop table if exists public.telemetry_events     cascade;
drop table if exists public.alerts               cascade;
drop table if exists public.scenario_runs        cascade;
drop table if exists public.lesson_progress      cascade;
drop table if exists public.lessons              cascade;
drop table if exists public.modules              cascade;
drop table if exists public.learning_paths       cascade;
drop table if exists public.scenarios            cascade;   -- 0001 reference table; app scenarios live in code

-- ── 2. Atomic org offboarding ───────────────────────────────────────────────
create or replace function public.purge_org(p_org uuid) returns void
  language plpgsql
  security definer set search_path = public
as $$
begin
  if p_org = 'd0d0d0d0-0000-4000-8000-000000000000' then
    raise exception 'cannot_purge_internal';
  end if;

  delete from public.room_progress     where org_id = p_org;
  delete from public.dashboard_sessions where org_id = p_org;
  delete from public.scenario_history   where org_id = p_org;
  delete from public.ai_usage           where org_id = p_org;
  delete from public.user_progress      where org_id = p_org;

  -- Re-home the accounts to the internal org so their NOT NULL org_id FK stays
  -- valid and they can still sign in (as unaffiliated users) after the college
  -- leaves. Their college progress above is gone (export first).
  update public.profiles set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id = p_org;

  delete from public.org_members  where org_id = p_org;
  delete from public.invitations  where org_id = p_org;
  delete from public.organizations where id = p_org;
end;
$$;

revoke execute on function public.purge_org(uuid) from anon, authenticated, public;

-- ── Verify ──────────────────────────────────────────────────────────────────
-- select count(*) from information_schema.tables where table_name = 'ai_messages'; -- 0
