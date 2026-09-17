-- HACK THE SOC :: 0054 — actions for the remaining roles — Phase 0.6
-- ===========================================================================
-- Completes role coverage so T3, Detection Engineer, Threat Intel and SOC
-- Manager each have real, gated actions (not just the shared feed):
--   hunt.logged      (t3)         — a threat-hunt hypothesis + finding
--   rule.published / rule.tuned (de) — a detection rule authored mid-incident
--   intel.published  (ti)         — an intel note (actor/technique/next-step)
--   handover.noted   (mgr, lead)  — a shift/handover note
-- Everything else is carried over verbatim. Idempotent (create or replace).
-- ===========================================================================

create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','grade.assigned') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role = 'lead'          and p_status = 'running'
    when p_type = 'containment.denied'       then p_role = 'lead'          and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then true
    else p_status in ('lobby','running')
  end
$$;
