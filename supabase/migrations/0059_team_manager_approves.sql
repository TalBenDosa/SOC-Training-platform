-- HACK THE SOC :: 0059 — SOC Manager inherits the coordinator authority
-- ===========================================================================
-- The team role set is being narrowed to {t1, t2, t3, mgr} (T1/T2 = many players,
-- T3 = 1, Manager = 1). With the Incident Lead removed from new sessions, the SOC
-- Manager becomes the approving authority. We WIDEN the coordinator actions to
-- include 'mgr' alongside 'lead' (keeping 'lead' so older sessions still work):
--     containment.approved / containment.denied  → lead OR mgr
--     sitrep.sent                                 → lead OR mgr
-- decision.logged and handover.noted already allow lead+mgr. Idempotent.
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
    when p_type = 'escalation.resolved'      then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.denied'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'sitrep.sent'              then p_role in ('lead','mgr') and p_status = 'running'
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
--   select public.session_action_allowed('containment.approved','mgr','running');  -- t
--   select public.session_action_allowed('containment.approved','lead','running'); -- t (back-compat)
--   select public.session_action_allowed('sitrep.sent','mgr','running');           -- t
--   select public.session_action_allowed('containment.approved','t2','running');   -- f
