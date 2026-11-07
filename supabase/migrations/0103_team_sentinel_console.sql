-- 0103: Sentinel console actions in Team Training.
--
-- A session can investigate in Sentinel instead of the EDR console (team_sessions.config.console).
-- What analysts do there goes on the session log, so the team shares one incident state and the
-- shift review can read it. Isolation keeps its own actions and its Tier-2 / Tier-3 gate.
--
-- Verify (staging): select public.session_action_allowed('sentinel.query_run','t1','running');  -- true
--                   select public.session_action_allowed('sentinel.query_run','t1','lobby');    -- false
--                   select public.session_action_allowed('sentinel.query_run','lead','running'); -- false

create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','session.paused','session.resumed','grade.assigned',
                    'hint.nudge','member.added','member.role_changed','member.removed','decision.expired','stakeholder.asked') then false
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
    when p_type = 'containment.approved'     then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.denied'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    when p_type in ('edr.host_isolated','edr.host_released') then p_role in ('t2','t3') and p_status = 'running'
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
