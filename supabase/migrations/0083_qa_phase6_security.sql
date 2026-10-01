-- 0083_qa_phase6_security.sql — QA phase 6 (security) database fixes.
--
-- SEC-05  revoke_user_sessions(): end every refresh session of a user whose access
--         was just taken away (removed from an org, deactivated). The app calls it
--         after the membership change; service-role only.
-- SEC-07  dashboard_sessions append-only + sanity / rate trigger.
-- SEC-08  ai_usage writable by the server only.
-- SEC-20  no TRUNCATE for clients, no writes for anon (existing + future tables).
-- SEC-21  profiles.rank / streak_days guarded like role / xp.

-- ── SEC-05 ── revoke a user's sessions ──────────────────────────────────────────
create or replace function public.revoke_user_sessions(p_user uuid)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  n integer;
begin
  -- auth.refresh_tokens.session_id cascades, so no new access token can be minted.
  delete from auth.sessions where user_id = p_user;
  get diagnostics n = row_count;
  return n;
end;
$$;
revoke execute on function public.revoke_user_sessions(uuid) from public, anon, authenticated;
grant  execute on function public.revoke_user_sessions(uuid) to service_role;

-- ── SEC-07 ── dashboard_sessions: append-only, sane, rate-bounded ─────────────
-- The live-feed shift is simulated in the browser, so the server can't recompute
-- its score; what it CAN refuse is rewriting / deleting history and rows no real
-- shift produces. (XP never comes from this table — instructors' analytics and
-- the streak do.)
revoke update, delete, truncate on public.dashboard_sessions from anon, authenticated;

create or replace function public.dashboard_session_guard()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if auth.uid() is null then return new; end if;            -- service role: trusted
  new.played_at := now();                                   -- never backdated / future-dated
  if new.attacks_presented_count < 0 or new.attacks_caught_count < 0 or new.fn_count < 0
     or new.events_opened_count < 0 or new.duration_ms < 0 or coalesce(new.avg_catch_ms, 0) < 0
     or new.xp_earned < 0 then
    raise exception 'invalid_session: negative value';
  end if;
  -- The detection rate is DERIVED from the counts here, never taken from the client
  -- (a forged 100% on a 0-of-8 shift was accepted before).
  new.attacks_caught_count := least(new.attacks_caught_count, new.attacks_presented_count);
  new.detect_rate := case when new.attacks_presented_count > 0
                          then round(100.0 * new.attacks_caught_count / new.attacks_presented_count)::int else 0 end;
  if new.duration_ms > 6 * 3600 * 1000 or new.attacks_presented_count > 500
     or new.events_opened_count > 20000 or new.xp_earned > 5000 then
    raise exception 'invalid_session: out of range';
  end if;
  if (select count(*) from public.dashboard_sessions
       where user_id = new.user_id and played_at > now() - interval '1 hour') >= 30 then
    raise exception 'invalid_session: too many sessions in an hour';
  end if;
  return new;
end;
$$;
drop trigger if exists dashboard_session_guard on public.dashboard_sessions;
create trigger dashboard_session_guard before insert on public.dashboard_sessions
  for each row execute function public.dashboard_session_guard();

-- ── SEC-08 ── ai_usage is metering — only the server writes it ────────────────
-- A learner could DELETE their own rows (under-count spend → the AI budget cap
-- never trips) or INSERT huge fake costs (trip the GLOBAL cap → AI off for all).
revoke insert, update, delete, truncate on public.ai_usage from anon, authenticated;
drop policy if exists "ai_usage org self" on public.ai_usage;
create policy "ai_usage self read" on public.ai_usage
  for select to authenticated using (user_id = (select auth.uid()) and org_id = public.current_org());

-- ── SEC-20 ── excess default grants ──────────────────────────────────────────
-- TRUNCATE bypasses RLS entirely, and anon (the public, signed-out key) needs no
-- write on any table — sign-up runs through Auth + SECURITY DEFINER triggers.
-- Neither is reachable through PostgREST today; this removes them outright.
do $$
declare t record;
begin
  for t in select c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'public' and c.relkind in ('r', 'p') loop
    execute format('revoke truncate on public.%I from anon, authenticated', t.relname);
    execute format('revoke insert, update, delete on public.%I from anon', t.relname);
  end loop;
end $$;
alter default privileges in schema public revoke truncate on tables from anon, authenticated;
alter default privileges in schema public revoke insert, update, delete on tables from anon;

-- ── SEC-21 ── profiles.rank / streak_days are not the learner's to set ────────
-- guard_profile_privileged_columns copied from 0077 with those two added.
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
    new.rank              := old.rank;
    new.streak_days       := old.streak_days;
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
