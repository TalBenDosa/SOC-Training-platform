-- 0079_team_free_text.sql
--
-- Team exercise: no minimum length on what analysts write (product decision,
-- Tal 2026-09-30). 0073 required ≥ 5 characters for an escalation summary and a
-- Tier-2 report summary, and ≥ 3 for a bounce / containment-denial reason. The
-- client additionally demanded 12+ words; both are removed. A field that must be
-- present (e.g. the summary) must still not be EMPTY — nothing else is enforced.
-- Report depth still counts in the end-of-exercise scoring (computeReport), it
-- just no longer blocks sending.
--
-- team_validate_action is copied verbatim from 0073 with only those four checks
-- changed. The 16 KB payload ceiling (apply_session_action) is unchanged — it is
-- an abuse bound, several thousand words, not a writing limit.

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
       and v_last.occurred_at > clock_timestamp() - interval '5 minutes' and not v_take then
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
revoke execute on function public.team_validate_action(uuid, uuid, text, jsonb) from public, anon, authenticated;
grant  execute on function public.team_validate_action(uuid, uuid, text, jsonb) to service_role;
