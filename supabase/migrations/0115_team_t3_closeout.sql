-- 0115: the Tier-3 close-out in team training (spec: research T3-INTERFACE-SPEC.md, stage E).
--
--   t3.closeout  how the attacker got in, the first host, what to remove, which accounts to reset,
--                what to block, and one detection query; graded in the report against the story.
--
-- The function below is 0113's session_action_allowed verbatim, plus the 0115 line.
-- Idempotent: create or replace.
-- Verify:
--   select public.session_action_allowed('t3.closeout','t3','running');   -- true
--   select public.session_action_allowed('t3.closeout','t2','running');   -- false

begin;

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
    -- 0112: Tier-3 case work (sweeps, the shared scope register, the containment-readiness verdict)
    when p_type in ('t3.scan','t3.scope.entity','t3.readiness') then p_role = 't3' and p_status = 'running'
    -- 0113: Tier-3 own work: Tier-2 asks a consult, Tier-3 answers it, Tier-3 reviews closed alerts
    when p_type = 'consult.asked'            then p_role = 't2'            and p_status = 'running'
    when p_type in ('consult.answered','review.verdict') then p_role = 't3' and p_status = 'running'
    -- 0115: the Tier-3 close-out (root cause, eradication, one detection)
    when p_type = 't3.closeout'              then p_role = 't3'            and p_status = 'running'
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

commit;
