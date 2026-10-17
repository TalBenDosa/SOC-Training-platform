-- 0098: Team SOC, a written response to an inject (2026-10-18 review of the Team Training exercises).
--
-- In four exercises no help-desk ticket, decoy ("false lead") or management request was ever
-- handled: tickets sat in a card at the bottom of the Tier-1 column and an "update" inject had
-- no way to answer it at all. Injects now open in an Action-required box at the top of each
-- role's console, and a decoy / twist / management request (with no SOC Manager) is answered
-- with `inject.responded` { inject_seq, inject_id, decision, note } — note required in the UI.
--
-- The only change below is the new 'inject.responded' line; the function is otherwise the 0095
-- definition verbatim (0097 changed team_validate_action, not this function).
--
-- Verify (staging): select public.session_action_allowed('inject.responded','t2','running') -> true;
--                   select public.session_action_allowed('inject.responded','t2','lobby')   -> false.

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
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then p_status in ('running','paused')
    else false
  end
$$;
