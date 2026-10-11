-- HACK THE SOC :: 0057 — scope split + containment execution — UX/UI spec G-10 + G-09
-- ===========================================================================
-- Two depth features from docs/SPEC-team-ux-ui.md §14:
--
--   G-10 (T2/T3 split): the Shared-Case scope stops being auto-only. T2 SETS the
--     incident scope (the hosts/users/techniques it believes are in play) and T3
--     CONFIRMS or AMENDS it — this is what makes Tier-3 distinct from Tier-2 and
--     it feeds the scope-accuracy rubric criteria (§4.f #3, §5.f #1).
--       scope.set        (t2/t3)  — propose/replace the working scope
--       scope.confirmed  (t3)     — lock the final scope (confirm or amend)
--
--   G-09 (containment executed): approval alone never stopped anything. After the
--     Lead approves, T2/T3 EXECUTES the isolation; the executed event is the
--     shared containment state and gives a real MTTC (Δ requested→executed).
--       containment.executed (t2/t3) — isolation carried out on the target host
--
-- All three are ordinary append-only session_events gated by role×phase, exactly
-- like every other team action. No new table (the log is the truth). Idempotent.
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
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    -- Shared Case (§5.1)
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    -- Scope split (§4.f/§5.f · G-10)
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then true
    else p_status in ('lobby','running')
  end
$$;

-- Verification:
--   select public.session_action_allowed('scope.set','t2','running');        -- t
--   select public.session_action_allowed('scope.confirmed','t2','running');  -- f (t3 only)
--   select public.session_action_allowed('containment.executed','t2','running'); -- t
--   select public.session_action_allowed('containment.executed','lead','running'); -- f
