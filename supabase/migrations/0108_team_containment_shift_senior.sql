-- 0108: account containment follows the senior on shift too; the exercise admin may approve
-- anything and may isolate a host themselves (owner decision, 2026-11-08: "the shift senior;
-- the organization admin has the option to approve an isolation or to isolate themselves").
--
-- Until now a containment request (disable an account, block an indicator, ...) could be
-- answered only by a SOC Manager or Lead (session_action_allowed), so in a team without one
-- the request waited forever, and the exercise admin could not answer it at all.
--
-- After 0108 (same rule as isolation, 0107; TypeScript: src/lib/team/isolationApproval.ts):
--   1. containment.approved / containment.denied: the role gate opens to Tier-3 and the
--      instructor seat; a BEFORE INSERT trigger (team_containment_validate_answer) then lets
--      only the senior on shift (team_isolation_can_approve against the request's author)
--      or the exercise admin (always) answer. Anyone else gets not_approver.
--   2. A containment request from the senior on shift (a Tier-3 with no active Manager) is
--      approved at once by the server (`containment.approved` { event_id, request_seq, target,
--      auto: 'shift_senior' }, actor = the requester); the analyst then executes it as usual.
--   3. The exercise admin may send `isolation.requested` too: team_isolation_can_approve says
--      yes for their own request, so 0107's trigger approves it at once and the host is isolated.
--
-- Idempotent: create or replace, drop trigger if exists.
-- Verify (staging), see scripts/test-0108-db.mjs for the full run in PGlite:
--   select public.session_action_allowed('containment.approved','t3','running');   -- true
--   select public.session_action_allowed('isolation.requested','instructor','running'); -- true

begin;

-- ── 1. the action gate (0104 verbatim, with the 0108 lines) ─────────────────
create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','session.paused','session.resumed','grade.assigned',
                    'hint.nudge','member.added','member.role_changed','member.removed','decision.expired','stakeholder.asked',
                    'presence.notice','session.end_scheduled','session.end_cancelled','session.reap_warning',
                    'edr.host_isolated') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role in ('t1','t2','t3') and p_status = 'running'
    when p_type in ('alert.claimed','alert.released') then p_role = 't1'   and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.bounced'       then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.resolved'      then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'elevation.requested'      then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'elevation.acknowledged'   then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'report.submitted'         then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    -- 0108: the senior on shift answers (fine-grained check: team_containment_validate_answer)
    when p_type = 'containment.approved'     then p_role in ('lead','mgr','t3','instructor') and p_status = 'running'
    when p_type = 'containment.denied'       then p_role in ('lead','mgr','t3','instructor') and p_status = 'running'
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    -- 0104: isolation is a request the shift senior approves (fine-grained check: team_isolation_validate);
    -- the server records edr.host_isolated itself. Release stays direct.
    -- 0108: the exercise admin may isolate too (their request is approved at once)
    when p_type = 'isolation.requested'      then p_role in ('t2','t3','instructor') and p_status = 'running'
    when p_type in ('isolation.approved','isolation.denied') then p_role in ('mgr','lead','t3','instructor') and p_status = 'running'
    when p_type = 'edr.host_released'        then p_role in ('t2','t3','mgr','lead','instructor') and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'sitrep.sent'              then p_role in ('lead','mgr') and p_status = 'running'
    -- 0093: SOC Manager command (declare / severity / decision cards)
    when p_type in ('incident.declared','incident.severity_changed') then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'decision.answered'        then p_role in ('lead','mgr') and p_status = 'running'
    -- 0094: stakeholder questions + incident report (manager), advice on a containment request (analysts)
    when p_type in ('stakeholder.replied','stakeholder.report_sent') then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.advised'      then p_role in ('t2','t3')    and p_status = 'running'
    -- 0095: Tier-3 forensics (evidence collection, findings) and RTR actions from the EDR console
    when p_type in ('forensic.collected','forensic.finding','forensic.report') then p_role = 't3' and p_status = 'running'
    when p_type = 'rtr.action'               then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'coordination.nudge'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    when p_type = 'staff.inject'             then p_role = 'instructor'    and p_status = 'running'
    when p_type = 'ticket.answered'          then p_role = 't1'            and p_status = 'running'
    -- 0098: a written response to an inject in the role's Action-required box (a decoy, a twist,
    -- a management request when the team has no SOC Manager)
    when p_type = 'inject.responded'         then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type in ('sentinel.incident_updated','sentinel.comment_added','sentinel.bookmark_added','sentinel.task_set','sentinel.query_run')
      then p_role in ('t1','t2','t3','de','ti') and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then p_status in ('running','paused')
    else false
  end
$$;

-- ── 2. who may answer a containment request ─────────────────────────────────
-- The request answered: request_seq when given, else the latest request on the case.
create or replace function public.team_containment_request_of(p_session uuid, p_payload jsonb)
returns public.session_events language plpgsql stable security definer set search_path = public as $$
declare v_req public.session_events;
begin
  if coalesce(p_payload->>'request_seq', '') ~ '^[0-9]{1,12}$' then
    select * into v_req from public.session_events
     where session_id = p_session and type = 'containment.requested' and seq = (p_payload->>'request_seq')::bigint;
  else
    select * into v_req from public.session_events
     where session_id = p_session and type = 'containment.requested' and payload->>'event_id' = p_payload->>'event_id'
     order by seq desc limit 1;
  end if;
  return v_req;
end $$;

create or replace function public.team_containment_validate_answer() returns trigger
  language plpgsql security definer set search_path = public as $$
declare v_req public.session_events;
begin
  if NEW.actor_id is null then return NEW; end if;                 -- system writes pass
  v_req := public.team_containment_request_of(NEW.session_id, NEW.payload);
  if v_req.seq is null then return NEW; end if;                    -- team_validate_action refuses it first
  if not public.team_isolation_can_approve(NEW.session_id, NEW.actor_id, v_req.actor_id) then
    raise exception 'not_approver';
  end if;
  return NEW;
end $$;

drop trigger if exists session_events_containment_validate_answer on public.session_events;
create trigger session_events_containment_validate_answer before insert on public.session_events
  for each row when (NEW.type in ('containment.approved','containment.denied'))
  execute function public.team_containment_validate_answer();

-- ── 3. the senior on shift asking is the senior on shift deciding ───────────
create or replace function public.team_containment_auto_approve() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  if NEW.actor_id is not null and public.team_isolation_can_approve(NEW.session_id, NEW.actor_id, NEW.actor_id) then
    perform public.team_insert_event(NEW.session_id, NEW.actor_id, NEW.role, 'containment.approved',
      jsonb_strip_nulls(jsonb_build_object(
        'event_id', NEW.payload->>'event_id', 'request_seq', NEW.seq, 'target', NEW.payload->>'target',
        'auto', 'shift_senior', 'reason', 'Approved on the senior on shift''s own authority')));
  end if;
  return NEW;
end $$;

drop trigger if exists session_events_containment_auto_approve on public.session_events;
create trigger session_events_containment_auto_approve after insert on public.session_events
  for each row when (NEW.type = 'containment.requested')
  execute function public.team_containment_auto_approve();

-- ── grants: server-side only ─────────────────────────────────────────────────
revoke all on function public.team_containment_request_of(uuid, jsonb)   from public, anon, authenticated;
revoke all on function public.team_containment_validate_answer()          from public, anon, authenticated;
revoke all on function public.team_containment_auto_approve()             from public, anon, authenticated;

commit;
