-- HACK THE SOC :: 0053 — role actions + real telemetry seeding — Phase 0.4
-- ===========================================================================
-- Two changes:
--  1. start_team_session no longer seeds the synthetic 0.2 timeline. The REAL
--     telemetry (company benign pool + a fitting attack story, same data the
--     single-player dashboard uses) is now generated in TypeScript and inserted
--     into session_injects by POST /api/team/sessions/[id]/start, because that
--     content lives in the app bundle, not in SQL. pg_cron still promotes it.
--  2. session_action_allowed gains 'containment.denied' (Incident Lead) so the
--     Lead can reject as well as approve a containment request.
-- Idempotent (create or replace).
-- ===========================================================================

create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','grade.assigned') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role = 'lead'          and p_status = 'running'
    when p_type = 'containment.denied'       then p_role = 'lead'          and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then true
    else p_status in ('lobby','running')
  end
$$;

-- Redefine start_team_session WITHOUT the synthetic seed (the app seeds real
-- telemetry after this returns). Everything else — staff gate, ready-check,
-- status transition, system session.started event — is unchanged.
create or replace function public.start_team_session(p_session uuid)
  returns public.team_sessions language plpgsql security definer set search_path = public as $$
declare v_row public.team_sessions; v_notready int; v_next bigint;
begin
  if not public.is_session_staff(p_session) then raise exception 'staff_only'; end if;
  select count(*) into v_notready from public.team_session_members
    where session_id = p_session and role <> 'instructor' and status not in ('ready','active');
  if v_notready > 0 then raise exception 'not_all_ready: % member(s) not ready', v_notready; end if;
  update public.team_sessions set status = 'running', started_at = now()
    where id = p_session and status in ('lobby','paused') returning * into v_row;
  if v_row.id is null then raise exception 'cannot_start_from_current_status'; end if;
  select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = p_session;
  insert into public.session_events(session_id, seq, actor_id, role, type, payload)
    values (p_session, v_next, null, null, 'session.started', jsonb_build_object('at', now()));
  insert into public.session_state(session_id, seq) values (p_session, v_next)
    on conflict (session_id) do update set seq = excluded.seq, updated_at = now();
  return v_row;
end $$;
