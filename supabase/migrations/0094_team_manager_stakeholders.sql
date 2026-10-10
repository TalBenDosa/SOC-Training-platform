-- 0094: SOC Manager, part 2 (Tal, 2026-10-10).
-- * stakeholder.replied: the SOC Manager answers a question a stakeholder asked (CISO, CEO
--   office, Legal, the business owner) in the stakeholder window. stakeholder.asked is fired by
--   the server only (team_fire_question), from what really happens in the session.
-- * stakeholder.report_sent: the incident report to stakeholders (needs a declaration).
-- * containment.advised: a Tier-2 / Tier-3 second opinion (support / object + reason) on a
--   teammate's containment request. A team disagreement card fires only on a REAL objection.
-- * session_action_allowed + team_validate_action recreated from 0093 with the additions.

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
    when p_type = 'coordination.nudge'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    when p_type = 'staff.inject'             then p_role = 'instructor'    and p_status = 'running'
    when p_type = 'ticket.answered'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then p_status in ('running','paused')
    else false
  end
$$;

create or replace function public.team_validate_action(
  p_session uuid, p_uid uuid, p_type text, p_payload jsonb)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_eid     text := nullif(btrim(coalesce(p_payload->>'event_id', '')), '');
  -- explicit take-over is honoured only where it means something: a claim or an ack
  v_take    boolean := p_type in ('alert.claimed','escalation.acknowledged')
                       and coalesce(p_payload->>'takeover', '') = 'true';
  v_last    public.session_events;
  v_seq     bigint;
  v_target  text;
  v_txt     text;
begin
  -- ── helpers are inlined as small queries (all index-backed) ──────────────
  -- 1. actions on a FEED LOG
  if p_type in ('alert.claimed','alert.released','disposition.set','escalation.requested') then
    if v_eid is null then raise exception 'invalid_payload: event_id is required'; end if;
    if not exists (select 1 from public.session_events
                    where session_id = p_session and type = 'feed.event' and payload->>'id' = v_eid) then
      raise exception 'unknown_event: %', v_eid;
    end if;
    -- current soft-claim on this log: latest claimed / released / disposition / escalation
    select * into v_last from public.session_events
     where session_id = p_session and payload->>'event_id' = v_eid
       and type in ('alert.claimed','alert.released','disposition.set','escalation.requested')
     order by seq desc limit 1;
    if found and v_last.type = 'alert.claimed' and v_last.actor_id is distinct from p_uid
       and public.team_active_ms(p_session, v_last.occurred_at, clock_timestamp()) < 300000   -- 0088: running time (M3)
       and not v_take then
      raise exception 'claim_held';
    end if;
  end if;

  if p_type = 'disposition.set' then
    if coalesce(p_payload->>'verdict', '') not in ('true_positive','false_positive','benign','suspicious') then
      raise exception 'invalid_payload: verdict must be true_positive, false_positive, benign or suspicious';
    end if;
  elsif p_type = 'escalation.requested' then
    v_txt := btrim(coalesce(nullif(p_payload->>'summary', ''), p_payload->>'what', ''));
    if v_txt = '' then raise exception 'invalid_payload: the escalation needs a summary'; end if;
    if p_payload ? 'severity' and coalesce(p_payload->>'severity', '') not in ('low','medium','high','critical') then
      raise exception 'invalid_payload: severity must be low, medium, high or critical';
    end if;
    -- still-open escalation for this log (latest lifecycle event is a request)?
    select type into v_txt from public.session_events
     where session_id = p_session and payload->>'event_id' = v_eid
       and type in ('escalation.requested','escalation.bounced','escalation.resolved')
     order by seq desc limit 1;
    if v_txt = 'escalation.requested' then raise exception 'already_escalated: %', v_eid; end if;
  end if;

  -- 2. actions on an ESCALATED log
  if p_type in ('escalation.acknowledged','escalation.bounced','escalation.resolved','elevation.requested',
                'report.submitted','containment.requested','containment.approved','containment.denied',
                'containment.executed') then
    if v_eid is null then raise exception 'invalid_payload: event_id is required'; end if;
    select max(seq) into v_seq from public.session_events
     where session_id = p_session and type = 'escalation.requested' and payload->>'event_id' = v_eid;
    if v_seq is null then raise exception 'not_escalated: %', v_eid; end if;

    -- P9-06 (QA Phase 9): a bounce or resolve must act on an OPEN case. Reject it when the
    -- latest lifecycle event for this log is already terminal (bounced or resolved), so two
    -- Tier-2s acting at once can't leave the case both 'resolved' AND 'bounced'.
    if p_type in ('escalation.bounced','escalation.resolved') then
      select type into v_txt from public.session_events
       where session_id = p_session and payload->>'event_id' = v_eid
         and type in ('escalation.bounced','escalation.resolved')
       order by seq desc limit 1;
      if v_txt in ('escalation.bounced','escalation.resolved') then
        raise exception 'case_closed: %', v_eid;
      end if;
    end if;

    if p_type = 'escalation.acknowledged' and not v_take and exists (
         select 1 from public.session_events
          where session_id = p_session and type = 'escalation.acknowledged' and payload->>'event_id' = v_eid
            and seq > v_seq and actor_id is distinct from p_uid) then
      raise exception 'case_owned';
    elsif p_type = 'escalation.bounced' and btrim(coalesce(p_payload->>'reason', '')) = '' then
      raise exception 'invalid_payload: a bounce needs a reason for Tier-1';
    elsif p_type = 'report.submitted' and btrim(coalesce(p_payload->>'summary', '')) = '' then
      raise exception 'invalid_payload: the report needs a summary';
    elsif p_type = 'containment.requested' then
      v_target := btrim(coalesce(p_payload->>'target', ''));
      if v_target = '' then raise exception 'invalid_payload: containment needs a target'; end if;
      select type into v_txt from public.session_events
       where session_id = p_session and payload->>'event_id' = v_eid
         and type in ('containment.requested','containment.approved','containment.denied')
         and coalesce(payload->>'target', '') = v_target
       order by seq desc limit 1;
      if v_txt = 'containment.requested' then
        raise exception 'invalid_payload: a request for % is already pending', v_target;
      end if;
    elsif p_type in ('containment.approved','containment.denied') then
      -- The decision must answer an OPEN request: the one named by request_seq (the UI
      -- always sends it), else any open request on this log for the same target.
      -- A request is closed by a decision naming its seq, or (legacy) a decision with
      -- no request_seq whose target is empty or equal.
      if not exists (
           select 1 from public.session_events r
            where r.session_id = p_session and r.type = 'containment.requested' and r.payload->>'event_id' = v_eid
              and (case when coalesce(p_payload->>'request_seq', '') ~ '^[0-9]+$'
                        then r.seq = (p_payload->>'request_seq')::bigint
                        else coalesce(p_payload->>'target', '') = '' or r.payload->>'target' = p_payload->>'target' end)
              and not exists (select 1 from public.session_events d
                               where d.session_id = p_session and d.payload->>'event_id' = v_eid
                                 and d.type in ('containment.approved','containment.denied') and d.seq > r.seq
                                 and (d.payload->>'request_seq' = r.seq::text
                                      or (not (d.payload ? 'request_seq')
                                          and (coalesce(d.payload->>'target', '') = '' or d.payload->>'target' = r.payload->>'target'))))) then
        raise exception 'no_pending_request';
      end if;
      if p_type = 'containment.denied' and btrim(coalesce(p_payload->>'reason', '')) = '' then
        raise exception 'invalid_payload: a denial needs a reason';
      end if;
    elsif p_type = 'containment.executed' then
      -- Execute only an APPROVED request, and only once.
      if coalesce(p_payload->>'request_seq', '') ~ '^[0-9]+$' then
        v_seq := (p_payload->>'request_seq')::bigint;
        if not exists (select 1 from public.session_events d
                        where d.session_id = p_session and d.type = 'containment.approved' and d.payload->>'event_id' = v_eid
                          and d.seq > v_seq and d.payload->>'request_seq' = v_seq::text)
           and not exists (select 1 from public.session_events r                      -- legacy approval (no request_seq)
                            where r.session_id = p_session and r.seq = v_seq and r.type = 'containment.requested'
                              and (select type from public.session_events x
                                    where x.session_id = p_session and x.payload->>'event_id' = v_eid and x.seq > r.seq
                                      and x.type in ('containment.approved','containment.denied')
                                    order by x.seq limit 1) = 'containment.approved') then
          raise exception 'not_approved';
        end if;
        if exists (select 1 from public.session_events
                    where session_id = p_session and type = 'containment.executed' and payload->>'request_seq' = v_seq::text) then
          raise exception 'invalid_payload: this containment was already executed';
        end if;
      else
        select type into v_txt from public.session_events
         where session_id = p_session and payload->>'event_id' = v_eid
           and type in ('containment.requested','containment.approved','containment.denied','containment.executed')
           and (coalesce(p_payload->>'target', '') = '' or coalesce(payload->>'target', '') in ('', p_payload->>'target'))
         order by seq desc limit 1;
        if coalesce(v_txt, '') = 'containment.executed' then raise exception 'invalid_payload: this containment was already executed'; end if;
        if coalesce(v_txt, '') <> 'containment.approved' then raise exception 'not_approved'; end if;
      end if;
    end if;
  end if;

  if p_type = 'elevation.acknowledged' then
    if v_eid is null then raise exception 'invalid_payload: event_id is required'; end if;
    if not exists (select 1 from public.session_events
                    where session_id = p_session and type = 'elevation.requested' and payload->>'event_id' = v_eid) then
      raise exception 'not_escalated: % was not elevated', v_eid;
    end if;
  end if;

  -- 3. help-desk tickets: answer a real ticket, once
  if p_type = 'ticket.answered' then
    if coalesce(p_payload->>'ticket_seq', '') !~ '^[0-9]+$' then raise exception 'invalid_payload: ticket_seq is required'; end if;
    if coalesce(p_payload->>'decision', '') not in ('handled','rejected') then
      raise exception 'invalid_payload: decision must be handled or rejected';
    end if;
    if not exists (select 1 from public.session_events
                    where session_id = p_session and seq = (p_payload->>'ticket_seq')::bigint
                      and type = 'staff.inject' and payload->>'kind' = 'ticket') then
      raise exception 'invalid_payload: seq % is not a help-desk ticket', p_payload->>'ticket_seq';
    end if;
    if exists (select 1 from public.session_events
                where session_id = p_session and type = 'ticket.answered'
                  and payload->>'ticket_seq' = p_payload->>'ticket_seq') then
      raise exception 'ticket_answered';
    end if;
  end if;

  -- 3b. EDR network containment (0082): a host name, and a real state change —
  -- isolating a host the team already isolated (or releasing one that isn't) is refused,
  -- so the log holds one clean isolate/release timeline per host for the report.
  if p_type in ('edr.host_isolated','edr.host_released') then
    v_target := btrim(coalesce(p_payload->>'host', ''));
    if v_target = '' or length(v_target) > 255 or v_target !~ '^[A-Za-z0-9][A-Za-z0-9._-]*$' then
      raise exception 'invalid_payload: a valid host name is required';
    end if;
    select type into v_txt from public.session_events
     where session_id = p_session and type in ('edr.host_isolated','edr.host_released')
       and lower(payload->>'host') = lower(v_target)
     order by seq desc limit 1;
    if p_type = 'edr.host_isolated' and v_txt = 'edr.host_isolated' then
      raise exception 'invalid_payload: % is already isolated', v_target;
    elsif p_type = 'edr.host_released' and v_txt is distinct from 'edr.host_isolated' then
      raise exception 'invalid_payload: % is not isolated', v_target;
    end if;
  end if;

  -- 3c. SOC Manager command (0093)
  if p_type = 'incident.declared' then
    if coalesce(p_payload->>'severity', '') !~ '^[1-4]$' then
      raise exception 'invalid_payload: severity must be 1 to 4';
    end if;
    if exists (select 1 from public.session_events where session_id = p_session and type = 'incident.declared') then
      raise exception 'invalid_payload: the incident is already declared';
    end if;
  elsif p_type = 'incident.severity_changed' then
    if coalesce(p_payload->>'severity', '') !~ '^[1-4]$' then
      raise exception 'invalid_payload: severity must be 1 to 4';
    end if;
    if btrim(coalesce(p_payload->>'reason', '')) = '' then
      raise exception 'invalid_payload: a severity change needs a reason';
    end if;
    if not exists (select 1 from public.session_events where session_id = p_session and type = 'incident.declared') then
      raise exception 'invalid_payload: declare the incident first';
    end if;
  elsif p_type = 'decision.answered' then
    -- answer a FIRED decision card, with one of ITS options, once
    if coalesce(p_payload->>'inject_id', '') !~ '^[0-9a-f-]{36}$' then
      raise exception 'invalid_payload: inject_id is required';
    end if;
    if coalesce(p_payload->>'confidence', '') not in ('low','medium','high') then
      raise exception 'invalid_payload: confidence must be low, medium or high';
    end if;
    if length(coalesce(p_payload->>'rationale', '')) > 400 then
      raise exception 'invalid_payload: the rationale is too long';
    end if;
    if not exists (select 1 from public.session_injects i
                    where i.id = (p_payload->>'inject_id')::uuid and i.session_id = p_session
                      and i.status = 'fired' and i.body->>'kind' = 'decision'
                      and exists (select 1 from jsonb_array_elements(coalesce(i.body->'options', '[]'::jsonb)) o
                                   where o->>'id' = p_payload->>'option')) then
      raise exception 'invalid_payload: not an open decision card or not one of its options';
    end if;
    if exists (select 1 from public.session_events
                where session_id = p_session and type = 'decision.answered'
                  and payload->>'inject_id' = p_payload->>'inject_id') then
      raise exception 'invalid_payload: this card was already answered';
    end if;
  end if;

  -- 3d. Stakeholders + containment advice (0094)
  if p_type = 'stakeholder.replied' then
    -- answer a question a stakeholder REALLY asked (fired by the director), once
    if coalesce(p_payload->>'inject_id', '') !~ '^[0-9a-f-]{36}$' then
      raise exception 'invalid_payload: inject_id is required';
    end if;
    v_txt := btrim(coalesce(p_payload->>'text', ''));
    if v_txt = '' then raise exception 'invalid_payload: the answer is empty'; end if;
    if length(v_txt) > 1200 then raise exception 'invalid_payload: the answer is too long'; end if;
    if not exists (select 1 from public.session_injects i
                    where i.id = (p_payload->>'inject_id')::uuid and i.session_id = p_session
                      and i.status = 'fired' and i.body->>'kind' = 'question') then
      raise exception 'invalid_payload: not a stakeholder question in this session';
    end if;
    if exists (select 1 from public.session_events
                where session_id = p_session and type = 'stakeholder.replied'
                  and payload->>'inject_id' = p_payload->>'inject_id') then
      raise exception 'invalid_payload: this question was already answered';
    end if;
  elsif p_type = 'stakeholder.report_sent' then
    if not exists (select 1 from public.session_events where session_id = p_session and type = 'incident.declared') then
      raise exception 'invalid_payload: declare the incident first';
    end if;
    if coalesce(p_payload->>'audience', '') not in ('ciso','executives','legal','business_owner','all') then
      raise exception 'invalid_payload: unknown audience';
    end if;
    if coalesce(p_payload->>'status', '') not in ('investigating','contained','eradicated','recovering','closed') then
      raise exception 'invalid_payload: unknown status';
    end if;
    if coalesce(p_payload->>'data_impact', '') not in ('none_known','suspected','confirmed') then
      raise exception 'invalid_payload: data impact must be none_known, suspected or confirmed';
    end if;
    if btrim(coalesce(p_payload->>'what_happened', '')) = '' then
      raise exception 'invalid_payload: the report needs what happened';
    end if;
    if coalesce(p_payload->>'next_update_min', '') !~ '^[0-9]{1,3}$' then
      raise exception 'invalid_payload: the next update time is required';
    end if;
    if length(p_payload::text) > 12000 then
      raise exception 'invalid_payload: the report is too long';
    end if;
  elsif p_type = 'containment.advised' then
    -- a second opinion on a REAL containment request, by someone other than the requester, once
    if coalesce(p_payload->>'request_seq', '') !~ '^[0-9]{1,10}$' then
      raise exception 'invalid_payload: request_seq is required';
    end if;
    if coalesce(p_payload->>'stance', '') not in ('support','object') then
      raise exception 'invalid_payload: stance must be support or object';
    end if;
    v_txt := btrim(coalesce(p_payload->>'reason', ''));
    if p_payload->>'stance' = 'object' and v_txt = '' then
      raise exception 'invalid_payload: an objection needs a reason';
    end if;
    if length(v_txt) > 300 then raise exception 'invalid_payload: the reason is too long'; end if;
    select * into v_last from public.session_events
     where session_id = p_session and seq = (p_payload->>'request_seq')::bigint and type = 'containment.requested';
    if not found then raise exception 'invalid_payload: not a containment request in this session'; end if;
    if v_last.actor_id = p_uid then raise exception 'invalid_payload: you made this request'; end if;
    if exists (select 1 from public.session_events
                where session_id = p_session and type = 'containment.advised' and actor_id = p_uid
                  and payload->>'request_seq' = p_payload->>'request_seq') then
      raise exception 'invalid_payload: you already gave your view on this request';
    end if;
  end if;

  -- 4. content-bearing actions must carry content
  if p_type in ('message.sent','note.added') then
    v_txt := btrim(coalesce(p_payload->>'text', ''));
    if v_txt = '' then raise exception 'invalid_payload: the message is empty'; end if;
    if length(v_txt) > 4000 then raise exception 'invalid_payload: the message is too long'; end if;
  elsif p_type = 'sitrep.sent' and btrim(coalesce(p_payload->>'situation', '') || coalesce(p_payload->>'status', '')) = '' then
    raise exception 'invalid_payload: a SITREP needs the situation';
  elsif p_type = 'decision.logged' and (btrim(coalesce(p_payload->>'decision', '')) = '' or btrim(coalesce(p_payload->>'rationale', '')) = '') then
    raise exception 'invalid_payload: a decision needs the decision and its rationale';
  elsif p_type = 'hunt.logged' and btrim(coalesce(p_payload->>'hypothesis', '') || coalesce(p_payload->>'finding', '')) = '' then
    raise exception 'invalid_payload: a hunt needs a hypothesis or a finding';
  elsif p_type = 'intel.published' and btrim(coalesce(p_payload->>'ioc', '') || coalesce(p_payload->>'actor', '')
                                          || coalesce(p_payload->>'technique', '') || coalesce(p_payload->>'recommendation', '')) = '' then
    raise exception 'invalid_payload: intel needs an IOC, actor, technique or recommendation';
  elsif p_type = 'staff.inject' and btrim(coalesce(p_payload->>'text', '')) = '' then
    raise exception 'invalid_payload: the inject needs text';
  elsif p_type in ('coordination.nudge','case.assigned') then
    v_txt := coalesce(p_payload->>(case when p_type = 'case.assigned' then 'owner' else 'target' end), '');
    if p_type = 'case.assigned' and v_txt = '' then
      null;                                                  -- "unassigned" is a valid choice
    elsif v_txt !~ '^[0-9a-fA-F-]{36}$' or not exists (
         select 1 from public.team_session_members
          where session_id = p_session and user_id = v_txt::uuid and status <> 'left') then
      raise exception 'invalid_payload: % must be a session member', case when p_type = 'case.assigned' then 'owner' else 'target' end;
    end if;
  elsif p_type = 'evidence.pinned' and v_eid is not null and not exists (
         select 1 from public.session_events
          where session_id = p_session and type = 'feed.event' and payload->>'id' = v_eid) then
    raise exception 'unknown_event: %', v_eid;
  end if;
end $$;

-- Fire one stakeholder question (service role only; called by the incident director). The
-- director decides WHICH question from the live session (a real declaration, a real isolation,
-- the team's own words about data, a real severity change); this makes it atomic and
-- once-per-question. The grading hints go to expected_action; the question itself is published
-- as a 'stakeholder.asked' event the SOC Manager answers in the stakeholder window.
create or replace function public.team_fire_question(p_session uuid, p_qid text, p_body jsonb, p_answer jsonb)
  returns bigint language plpgsql security definer set search_path = public as $$
declare
  v_start  timestamptz;
  v_pms    bigint;
  v_ver    int;
  v_inject uuid;
  v_ev     public.session_events;
begin
  if p_qid is null or p_qid !~ '^[a-z0-9_]{1,40}$' then raise exception 'invalid question id'; end if;
  if not public.team_try_lock_session(p_session) then return null; end if;
  select started_at, coalesce(paused_ms, 0), coalesce(schema_version, 1) into v_start, v_pms, v_ver
    from public.team_sessions where id = p_session and status = 'running';
  if not found or v_ver < 2 then return null; end if;
  if exists (select 1 from public.session_injects
              where session_id = p_session and channel = 'inject' and trigger->>'question' = p_qid) then
    return null;
  end if;
  insert into public.session_injects(session_id, due_offset_ms, trigger, to_roles, persona, channel, body, expected_action, status)
    values (p_session,
            floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms,
            jsonb_build_object('kind', 'on_state', 'question', p_qid),
            array['mgr','lead'], p_body->'from'->>'role', 'inject',
            p_body || jsonb_build_object('kind', 'question', 'qid', p_qid),
            p_answer, 'fired')
    returning id into v_inject;
  v_ev := public.team_insert_event(p_session, null, null, 'stakeholder.asked',
            p_body || jsonb_build_object('kind', 'question', 'qid', p_qid, 'inject_id', v_inject));
  update public.session_injects set fired_seq = v_ev.seq where id = v_inject;
  return v_ev.seq;
end $$;

revoke execute on function public.team_fire_question(uuid, text, jsonb, jsonb) from public, anon, authenticated;
grant  execute on function public.team_fire_question(uuid, text, jsonb, jsonb) to service_role;

-- verify:
--   select public.session_action_allowed('stakeholder.replied','mgr','running');   -- t
--   select public.session_action_allowed('stakeholder.asked','mgr','running');     -- f
--   select public.session_action_allowed('containment.advised','t3','running');    -- t
--   select public.session_action_allowed('containment.advised','t1','running');    -- f
--   select has_function_privilege('authenticated','public.team_fire_question(uuid,text,jsonb,jsonb)','execute');  -- f
