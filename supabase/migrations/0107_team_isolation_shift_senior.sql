-- 0107: an isolation is approved by the SENIOR ON SHIFT (owner decision, 2026-11-08).
--
-- The owner: the shift senior approves. In a role split that is the Tier-3; when a SOC
-- Manager is on shift, the Manager is the most senior role and approves.
--
-- Until now (0104, 0106) a Tier-3 could never approve their own request (it fell to another
-- Tier-3 or the exercise admin), and the rung order was not written down as "the senior".
-- The exercise admin may do everything (owner, 2026-11-08): the override stays.
--
-- After 0107 (same rule as src/lib/team/isolationApproval.ts, keep them in step):
--   1. team_isolation_senior_tier(session, actor): 'mgr' when a seated, active SOC Manager
--      or Lead is on shift; else 't3' when a seated, active Tier-3 is; else 'staff'.
--      "Active" = heartbeat in the last 120 seconds; the person acting counts as active.
--   2. team_isolation_can_approve: that tier answers. The exercise admin (instructor seat,
--      0106 team_can_hold_staff_seat) may always approve or deny as well, senior or not.
--   3. A requester who is themselves the senior on shift (a Tier-3 with no active Manager)
--      isolates on their own authority: an AFTER INSERT trigger answers their request at once
--      with `isolation.approved` { request_seq, auto: 'shift_senior' }, actor = the requester,
--      and the 0104 trigger then records edr.host_isolated as for any approval.
--   Nobody else approves their own request (a Tier-2 never is the senior on shift).
--
-- Idempotent: create or replace, drop trigger if exists.
-- Verify (staging), see scripts/test-0107-db.mjs for the full run in PGlite:
--   select public.team_isolation_senior_tier('<session>', null);   -- 'mgr' | 't3' | 'staff'

begin;

create or replace function public.team_isolation_senior_tier(p_session uuid, p_actor uuid)
returns text language plpgsql stable security definer set search_path = public as $$
declare
  v_now timestamptz := clock_timestamp();
begin
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role in ('mgr','lead')
                and (m.user_id = p_actor or m.last_seen_at > v_now - interval '120 seconds')) then
    return 'mgr';
  end if;
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role = 't3'
                and (m.user_id = p_actor or m.last_seen_at > v_now - interval '120 seconds')) then
    return 't3';
  end if;
  return 'staff';
end $$;

create or replace function public.team_isolation_can_approve(p_session uuid, p_user uuid, p_requester uuid)
returns boolean language plpgsql stable security definer set search_path = public as $$
declare
  v_role text;
  v_tier text;
begin
  if p_user is null then return false; end if;
  select role into v_role from public.team_session_members
   where session_id = p_session and user_id = p_user and status <> 'left';
  if v_role is null then return false; end if;
  -- The exercise admin may do everything (0106: only a seat holder who may hold it).
  if v_role = 'instructor' then return public.team_can_hold_staff_seat(p_session, p_user); end if;
  v_tier := public.team_isolation_senior_tier(p_session, p_user);
  -- The requester is the senior on shift: their own authority (a Tier-2 never is).
  if p_user = p_requester then
    return (v_tier = 'mgr' and v_role in ('mgr','lead')) or (v_tier = 't3' and v_role = 't3');
  end if;
  if v_tier = 'mgr' then return v_role in ('mgr','lead'); end if;
  if v_tier = 't3'  then return v_role = 't3'; end if;
  return false;   -- nobody senior on shift: the exercise admin only (above)
end $$;

-- AFTER INSERT on a request: the senior on shift asking is the senior on shift deciding.
create or replace function public.team_isolation_auto_approve() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if NEW.actor_id is not null and public.team_isolation_can_approve(NEW.session_id, NEW.actor_id, NEW.actor_id) then
    perform public.team_insert_event(NEW.session_id, NEW.actor_id, NEW.role, 'isolation.approved',
      jsonb_build_object('request_seq', NEW.seq, 'auto', 'shift_senior'));
  end if;
  return NEW;
end $$;

drop trigger if exists session_events_isolation_auto_approve on public.session_events;
create trigger session_events_isolation_auto_approve after insert on public.session_events
  for each row when (NEW.type = 'isolation.requested')
  execute function public.team_isolation_auto_approve();

-- ── grants: server-side only ─────────────────────────────────────────────────
revoke all on function public.team_isolation_senior_tier(uuid, uuid)        from public, anon, authenticated;
revoke all on function public.team_isolation_can_approve(uuid, uuid, uuid)  from public, anon, authenticated;
revoke all on function public.team_isolation_auto_approve()                 from public, anon, authenticated;
grant execute on function public.team_isolation_senior_tier(uuid, uuid)       to service_role;
grant execute on function public.team_isolation_can_approve(uuid, uuid, uuid) to service_role;

commit;
