-- HACK THE SOC :: 0058 — remaining UX/UI-spec action types — G-07 / G-14 / G-15
-- ===========================================================================
-- Closes the last spec gaps that need new gate-allowed action types (all are
-- ordinary append-only session_events, role×phase gated like everything else):
--
--   G-07 escalation state machine (feedback loop to T1):
--     escalation.bounced   (t2/t3)        — send an insufficient escalation BACK to T1
--     escalation.resolved  (t2/t3/lead)   — close the escalation thread
--
--   G-14 help-desk + instructor injects:
--     staff.inject         (instructor)   — post a manual inject/announcement/help-desk ticket
--     ticket.answered      (t1)           — T1 answers a help-desk ticket (approve/deny + note)
--
--   G-15 tail (Lead situational reporting):
--     sitrep.sent          (lead)         — a 4-question SITREP to the team/management
--
-- (G-06 reuses rule.published; G-17 only adds a payload field to intel.published —
--  neither needs a new type.) Idempotent create-or-replace of the whole gate.
-- ===========================================================================

create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','grade.assigned') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.bounced'       then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.resolved'      then p_role in ('t2','t3','lead') and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role = 'lead'          and p_status = 'running'
    when p_type = 'containment.denied'       then p_role = 'lead'          and p_status = 'running'
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'sitrep.sent'              then p_role = 'lead'          and p_status = 'running'
    -- Shared Case (§5.1)
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    -- Scope split (G-10)
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    -- Help-desk + instructor injects (G-14)
    when p_type = 'staff.inject'             then p_role = 'instructor'    and p_status = 'running'
    when p_type = 'ticket.answered'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then true
    else p_status in ('lobby','running')
  end
$$;

-- Verification:
--   select public.session_action_allowed('escalation.bounced','t2','running');  -- t
--   select public.session_action_allowed('escalation.resolved','lead','running');-- t
--   select public.session_action_allowed('staff.inject','instructor','running');-- t
--   select public.session_action_allowed('staff.inject','t1','running');        -- f
--   select public.session_action_allowed('ticket.answered','t1','running');     -- t
--   select public.session_action_allowed('sitrep.sent','lead','running');       -- t
--   select public.session_action_allowed('sitrep.sent','mgr','running');        -- f
