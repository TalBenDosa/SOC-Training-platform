-- 0106: Team Training is run by the organization admin only (owner decision, 2026-11).
--
-- Until now the database treated the org role `instructor` as team staff, exactly like
-- `org_admin`:
--   * is_session_staff(p_session)   (0049): current_org_role() in ('org_admin','instructor')
--       -> realtime topic read (0071 section 14), team_heartbeat's staff_seen_at stamp.
--   * team_staff_sessions()         (0071): same rule
--       -> RLS read of EVERY session of the org, its roster, events, state, and the
--          staff-only session_injects (the answer key: expected_action).
--   * the session SEAT role 'instructor' (team_session_members.role) carries staff power by
--     itself: staff.inject, isolation approve / deny / release (0104 session_action_allowed),
--     and team_isolation_can_approve() returns true for it as an override, always.
--     Nothing checked WHO holds that seat.
--
-- After 0106:
--   1. is_session_staff / team_staff_sessions: org_admin only, and the JWT claim must be
--      backed by an active org_admin row in org_members (a demoted admin's token, valid up
--      to an hour, no longer reads every session).
--   2. team_can_hold_staff_seat(session, user): an active org_admin of the session's org, or
--      the platform owner (profiles.is_platform_admin). The one DB rule for the seat.
--   3. Holding the seat: a trigger refuses inserting, or changing a row to, role
--      'instructor' for anyone else (the API seats only the creator, a team admin, there).
--   4. Using the seat: a trigger refuses any session_events row written with role
--      'instructor' by an actor who may not hold it, so a legacy seat held by an org
--      instructor (or a demoted admin) can no longer inject, approve, deny or release.
--      apply_session_action raises, nothing is written.
--   5. team_isolation_can_approve: the instructor-seat override applies only to a seat
--      holder who may hold it.
--
-- An org instructor seated as a player (t1, t2, ...) keeps exactly that seat's rights.
-- Existing rows are not rewritten. Idempotent: create or replace, drop trigger if exists.
-- NOT APPLIED by the change that added it. Apply with the usual prod migration procedure.
-- Verify: node scripts/test-0106-db.mjs (PGlite, every migration).

begin;

-- ── 2. the seat rule ─────────────────────────────────────────────────────────
create or replace function public.team_can_hold_staff_seat(p_session uuid, p_user uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select p_user is not null and (
    exists (select 1 from public.profiles p where p.id = p_user and p.is_platform_admin = true)
    or exists (
      select 1 from public.team_sessions ts
        join public.org_members om on om.org_id = ts.org_id and om.user_id = p_user
       where ts.id = p_session and om.role = 'org_admin' and om.status = 'active'
         and (om.affiliation_expires_at is null or om.affiliation_expires_at > now()))
  )
$$;
revoke all on function public.team_can_hold_staff_seat(uuid, uuid) from public, anon, authenticated;
grant execute on function public.team_can_hold_staff_seat(uuid, uuid) to service_role;

-- ── 1. staff = org admin (JWT claim AND a live org_admin row) ────────────────
create or replace function public.is_session_staff(p_session uuid)
  returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.team_sessions s
      join public.org_members om on om.org_id = s.org_id and om.user_id = auth.uid()
     where s.id = p_session
       and s.org_id = public.current_org()
       and public.current_org_role() = 'org_admin'
       and om.role = 'org_admin' and om.status = 'active'
       and (om.affiliation_expires_at is null or om.affiliation_expires_at > now())
  )
$$;
revoke execute on function public.is_session_staff(uuid) from public, anon;
grant  execute on function public.is_session_staff(uuid) to authenticated;

create or replace function public.team_staff_sessions() returns setof uuid
  language sql stable security definer set search_path = public as $$
  select ts.id from public.team_sessions ts
   where ts.org_id = public.current_org() and public.current_org_role() = 'org_admin'
     and exists (select 1 from public.org_members om
                  where om.org_id = ts.org_id and om.user_id = auth.uid()
                    and om.role = 'org_admin' and om.status = 'active'
                    and (om.affiliation_expires_at is null or om.affiliation_expires_at > now()))
$$;
revoke execute on function public.team_staff_sessions() from public, anon;
grant  execute on function public.team_staff_sessions() to authenticated;

-- ── 3. holding the instructor seat ───────────────────────────────────────────
create or replace function public.team_guard_staff_seat()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.role = 'instructor'
     and (tg_op = 'INSERT' or old.role is distinct from 'instructor' or old.user_id is distinct from new.user_id)
     and not public.team_can_hold_staff_seat(new.session_id, new.user_id) then
    raise exception 'team_admin_only: the instructor seat is held only by an organization admin or the platform owner'
      using errcode = '42501';
  end if;
  return new;
end $$;
revoke all on function public.team_guard_staff_seat() from public, anon, authenticated;

drop trigger if exists team_session_members_staff_seat on public.team_session_members;
create trigger team_session_members_staff_seat
  before insert or update of role, user_id on public.team_session_members
  for each row execute function public.team_guard_staff_seat();

-- ── 4. using the instructor seat ─────────────────────────────────────────────
create or replace function public.team_guard_staff_event()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.role = 'instructor' and new.actor_id is not null
     and not public.team_can_hold_staff_seat(new.session_id, new.actor_id) then
    raise exception 'team_admin_only: only an organization admin or the platform owner acts from the instructor seat'
      using errcode = '42501';
  end if;
  return new;
end $$;
revoke all on function public.team_guard_staff_event() from public, anon, authenticated;

drop trigger if exists session_events_staff_seat on public.session_events;
create trigger session_events_staff_seat
  before insert on public.session_events
  for each row execute function public.team_guard_staff_event();

-- ── 5. isolation approval: 0104 body, the override only for an eligible seat holder ─
-- Same rule as isolationApprovers() in src/lib/team/isolationApproval.ts.
create or replace function public.team_isolation_can_approve(p_session uuid, p_user uuid, p_requester uuid)
returns boolean language plpgsql stable security definer set search_path = public as $$
declare
  v_role text;
  v_now  timestamptz := clock_timestamp();
begin
  if p_user is null or p_user = p_requester then return false; end if;
  select role into v_role from public.team_session_members
   where session_id = p_session and user_id = p_user and status <> 'left';
  if v_role is null then return false; end if;
  -- 0106: the staff override, always, but only for a seat holder who may hold it.
  if v_role = 'instructor' then return public.team_can_hold_staff_seat(p_session, p_user); end if;
  -- 1. a seated, active SOC Manager / Lead (the acting user counts as active)
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role in ('mgr','lead')
                and m.user_id is distinct from p_requester
                and (m.user_id = p_user or m.last_seen_at > v_now - interval '120 seconds')) then
    return v_role in ('mgr','lead');
  end if;
  -- 2. else a seated, active Tier-3 who is not the requester
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role = 't3'
                and m.user_id is distinct from p_requester
                and (m.user_id = p_user or m.last_seen_at > v_now - interval '120 seconds')) then
    return v_role = 't3';
  end if;
  -- 3. else the exercise admin only (handled above)
  return false;
end $$;

commit;
