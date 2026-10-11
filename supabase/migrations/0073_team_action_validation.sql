-- HACK THE SOC :: 0073 — Team-SOC server-side action validation (live playtest 2026-09-27)
-- ===========================================================================
-- The 7-agent live playtest showed the server stored anything the client sent:
-- an empty escalation, a verdict "probably_fine", claims/dispositions on ids that
-- aren't in the feed, a second answer to the same help-desk ticket, a second T1
-- claim silently overwriting a live one, two responders acking the same case.
--  • team_validate_action(): called by apply_session_action UNDER the session
--    lock (so the checks are race-free). Rejects with stable codes the client maps
--    to friendly text: invalid_payload / unknown_event / not_escalated /
--    already_escalated / claim_held / case_owned / ticket_answered /
--    no_pending_request / not_approved.
--  • Ownership: a live (<5 min) T1 claim and a first acknowledgement are enforced;
--    `takeover: true` in the payload is the explicit take-over.
--  • Containment is a small state machine per (log, target): request → approve |
--    deny → (execute after approve); a new request after a denial is allowed.
--  • Coverage tick: an online Tier-3 covers a missing Tier-2 (no needless pause).
--  • replenish_feed recycles PURE NOISE only — never story control steps, ITSM
--    records or inject-support logs (they now carry benign/fp verdicts too).
-- CREATE OR REPLACE keeps existing grants; the new function is service-only.
-- ===========================================================================

create index if not exists session_events_event_ref_idx
  on public.session_events (session_id, (payload->>'event_id'));
create index if not exists session_events_feed_id_idx
  on public.session_events (session_id, (payload->>'id')) where type = 'feed.event';

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
    if length(v_txt) < 5 then raise exception 'invalid_payload: the escalation needs a summary'; end if;
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
    elsif p_type = 'escalation.bounced' and length(btrim(coalesce(p_payload->>'reason', ''))) < 3 then
      raise exception 'invalid_payload: a bounce needs a reason for Tier-1';
    elsif p_type = 'report.submitted' and length(btrim(coalesce(p_payload->>'summary', ''))) < 5 then
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
      if p_type = 'containment.denied' and length(btrim(coalesce(p_payload->>'reason', ''))) < 3 then
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

-- ── apply_session_action: 0071 body + the validation hook ────────────────────
create or replace function public.apply_session_action(
  p_session uuid, p_type text, p_payload jsonb default '{}'::jsonb,
  p_expected_seq bigint default null, p_idempotency_key text default null
) returns public.session_events
  language plpgsql security definer set search_path = public as $$
declare
  v_uid     uuid := auth.uid();
  v_role    text;
  v_status  text;
  v_version integer;
  v_org     uuid;
  v_head    bigint;
  v_row     public.session_events;
  v_prior   public.session_events;
  v_payload jsonb := coalesce(p_payload, '{}'::jsonb);
  v_kind    text;
  v_pubkind text;
  v_inject  uuid;
  v_dwell   integer;
begin
  if v_uid is null then raise exception 'auth_required'; end if;
  if pg_column_size(v_payload) > 16384 then raise exception 'payload_too_large'; end if;

  perform public.team_lock_session(p_session);          -- ONE lock rule: lock first

  select status, schema_version, org_id into v_status, v_version, v_org
    from public.team_sessions where id = p_session;      -- status re-read UNDER the lock
  if v_status is null then raise exception 'no_such_session'; end if;

  select m.role into v_role
    from public.team_session_members m
   where m.session_id = p_session and m.user_id = v_uid and m.status <> 'left'
     and exists (select 1 from public.org_members om
                  where om.org_id = v_org and om.user_id = v_uid and om.status = 'active'
                    and (om.affiliation_expires_at is null or om.affiliation_expires_at > now()));
  if v_role is null then raise exception 'not_a_member'; end if;

  if p_idempotency_key is not null then
    select * into v_prior from public.session_events
      where session_id = p_session and actor_id = v_uid and idempotency_key = p_idempotency_key;
    if found then return v_prior; end if;               -- replays are exempt from limits
  end if;

  if not public.session_action_allowed(p_type, v_role, v_status) then
    raise exception 'action_not_allowed: % for role % in status %', p_type, v_role, v_status;
  end if;

  -- 0073: shape / reference / ownership checks, race-free under the session lock.
  if p_type <> 'event.opened' then
    perform public.team_validate_action(p_session, v_uid, p_type, v_payload);
  end if;

  -- v2: click telemetry never enters the event log (no seq, no broadcast, no gaps).
  if p_type = 'event.opened' and v_version >= 2 then
    v_dwell := case when (v_payload->>'dwell_ms') ~ '^[0-9]+(\.[0-9]+)?$'
                    then least(3600000, floor((v_payload->>'dwell_ms')::numeric))::integer else 0 end;
    insert into public.session_clicks(session_id, user_id, event_id, dwell_ms)
      values (p_session, v_uid, left(coalesce(v_payload->>'event_id', ''), 200), v_dwell);
    return null;
  end if;

  -- Lenient per-actor rate limit (clicks excluded): burst 30 / 10s, 90 / min.
  if p_type <> 'event.opened' and (
       (select count(*) from public.session_events e
         where e.session_id = p_session and e.actor_id = v_uid and e.type <> 'event.opened'
           and e.occurred_at > clock_timestamp() - interval '10 seconds') >= 30
    or (select count(*) from public.session_events e
         where e.session_id = p_session and e.actor_id = v_uid and e.type <> 'event.opened'
           and e.occurred_at > clock_timestamp() - interval '60 seconds') >= 90) then
    raise exception 'rate_limited';
  end if;

  v_head := public.team_next_seq(p_session) - 1;
  if v_head >= 20000 and p_type not in ('member.ready','member.unready') then
    raise exception 'session_full';                     -- player actions only; system writers exempt
  end if;
  if p_expected_seq is not null and p_expected_seq <> v_head then
    raise exception 'seq_conflict: expected % but head is %', p_expected_seq, v_head;
  end if;

  -- Instructor-typed curveballs: keep the real kind + expected answer in
  -- session_injects (staff-only) and publish a neutral kind to the team.
  if p_type = 'staff.inject' then
    v_kind := coalesce(nullif(v_payload->>'kind', ''), 'announcement');
    v_pubkind := case when v_kind in ('twist','false_lead','mgmt_pressure') then 'update' else v_kind end;
    insert into public.session_injects(session_id, due_offset_ms, trigger, channel, body, expected_action, status)
      values (p_session, 0, jsonb_build_object('kind','manual','by', v_uid), 'inject',
              (v_payload - 'expected_response' - 'linked_objective') || jsonb_build_object('kind', v_pubkind),
              jsonb_strip_nulls(jsonb_build_object('kind', v_kind,
                'expected_response', v_payload->'expected_response',
                'linked_objective',  v_payload->'linked_objective')),
              'fired')
      returning id into v_inject;
    v_payload := (v_payload - 'expected_response' - 'linked_objective')
                 || jsonb_build_object('kind', v_pubkind, 'inject_id', v_inject);
  end if;

  v_row := public.team_insert_event(p_session, v_uid, v_role, p_type, v_payload, p_idempotency_key);
  if p_type = 'staff.inject' then
    update public.session_injects set fired_seq = v_row.seq where id = v_inject;
  end if;

  if p_type = 'member.ready' then
    update public.team_session_members
      set status = 'ready', ready_at = now(), confirmed_entry_at = coalesce(confirmed_entry_at, now())
      where session_id = p_session and user_id = v_uid;
  elsif p_type = 'member.unready' then
    update public.team_session_members set status = 'invited', ready_at = null
      where session_id = p_session and user_id = v_uid;
  end if;

  return v_row;
end $$;

-- ── lifecycle tick: 0072 body, Tier-3 covers a missing Tier-2 ────────────────
create or replace function public.team_lifecycle_tick()
  returns int language plpgsql security definer set search_path = public as $$
declare
  s          public.team_sessions;
  v_now      timestamptz := clock_timestamp();
  v_grace    timestamptz;
  v_missing  text[];
  v_everyone boolean;
  v_owner    timestamptz;
  v_want     text;
  v_detail   text;
  v_state    jsonb;
  v_stale    integer;
  v_fresh    timestamptz;
  v_first    timestamptz;
  v_changes  int := 0;
begin
  for s in
    select * from public.team_sessions
     where status in ('running','paused') and schema_version >= 2
     order by random() limit 200                                  -- fair: every live session gets visited
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;
      select * into s from public.team_sessions where id = s.id;           -- fresh under lock
      if s.status not in ('running','paused') then continue; end if;
      v_state := coalesce(s.lifecycle_state, '{}'::jsonb);

      -- grace after start / last resume
      select greatest(s.started_at, coalesce(max(e.occurred_at), s.started_at)) into v_grace
        from public.session_events e where e.session_id = s.id and e.type = 'session.resumed';
      if v_now < v_grace + interval '60 seconds' then continue; end if;

      -- who is missing (core relay T1 → T2), everyone gone, instructor/staff gone
      select coalesce(array_agg(r.role order by r.role), '{}') into v_missing
        from (select distinct m.role from public.team_session_members m
               where m.session_id = s.id and m.status <> 'left' and m.role in ('t1','t2')) r
       where not exists (select 1 from public.team_session_members m2
                          where m2.session_id = s.id and m2.status <> 'left'
                            and (m2.role = r.role or (r.role = 't2' and m2.role = 't3'))   -- 0073: an online T3 covers T2
                            and m2.last_seen_at > v_now - interval '120 seconds');
      select not exists (select 1 from public.team_session_members m
                          where m.session_id = s.id and m.status <> 'left'
                            and m.role not in ('instructor','observer')
                            and m.last_seen_at > v_now - interval '120 seconds') into v_everyone;
      select greatest(s.staff_seen_at, (select max(m.last_seen_at) from public.team_session_members m
                                         where m.session_id = s.id and m.role = 'instructor'))
        into v_owner;

      v_want := null; v_detail := null;
      if coalesce(v_owner, '-infinity'::timestamptz) < v_now - interval '180 seconds' then
        v_want := 'owner_left';
        v_detail := 'The instructor dropped out of the live room — paused until they''re back.';
      elsif v_everyone then
        v_want := 'coverage'; v_detail := 'Everyone has left the exercise.';
      elsif array_length(v_missing, 1) > 0 then
        v_want := 'coverage';
        v_detail := 'No ' || array_to_string(array(select case x when 't1' then 'Tier-1' else 'Tier-2' end
                                                   from unnest(v_missing) x), ' and no ') || ' online right now.';
      end if;

      if s.status = 'running' then
        if v_want is not null then
          v_stale := coalesce((v_state->>'stale')::int, 0) + 1;
          if v_stale >= 2 then                                              -- two stale ticks in a row
            perform public.team_transition(s.id, 'paused', v_want, null, v_detail);
            v_changes := v_changes + 1;
          else
            update public.team_sessions set lifecycle_state = v_state || jsonb_build_object('stale', v_stale) where id = s.id;
          end if;
        elsif v_state ? 'stale' then
          update public.team_sessions set lifecycle_state = v_state - 'stale' where id = s.id;
        end if;

        -- spoiler-free "nobody escalated yet" hint, once, randomized 3–6 min after the first attack log
        -- (only while the room is healthy — never in the tick that pauses it)
        if s.nudged_at is null and v_want is null then
          if exists (select 1 from public.session_events e where e.session_id = s.id and e.type = 'escalation.requested') then
            update public.team_sessions set nudged_at = v_now where id = s.id;   -- settled: no hint needed
          else
            select min(e.occurred_at) into v_first
              from public.session_injects i
              join public.session_events e on e.session_id = i.session_id and e.seq = i.fired_seq
             where i.session_id = s.id and i.status = 'fired' and i.channel = 'feed'
               and i.expected_action->>'expected_verdict' in ('tp','escalate');
            if v_first is not null
               and v_now > v_first + make_interval(secs => 180 + (abs(hashtext(s.id::text)) % 181)) then
              perform public.append_system_event(s.id, 'hint.nudge',
                jsonb_build_object('text', 'Real attack activity may be streaming in the feed — nobody has escalated anything yet. Re-check the high-severity logs.'));
              update public.team_sessions set nudged_at = v_now where id = s.id;
            end if;
          end if;
        end if;

      elsif s.status = 'paused' and s.pause_reason in ('coverage','owner_left') then
        if v_want is null then
          v_fresh := nullif(v_state->>'fresh_since', '')::timestamptz;
          if v_fresh is null then
            update public.team_sessions set lifecycle_state = v_state || jsonb_build_object('fresh_since', v_now) where id = s.id;
          elsif v_now - v_fresh >= interval '30 seconds' then                 -- resume hysteresis
            perform public.team_transition(s.id, 'running', 'auto_resume', null, null);
            v_changes := v_changes + 1;
          end if;
        else
          if v_state ? 'fresh_since' then
            update public.team_sessions set lifecycle_state = v_state - 'fresh_since' where id = s.id;
          end if;
          if v_want is distinct from s.pause_reason then
            perform public.team_transition(s.id, 'paused', v_want, null, v_detail);
            v_changes := v_changes + 1;
          end if;
        end if;
      end if;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('lifecycle_error', s.id, sqlerrm);
    end;
  end loop;
  return v_changes;
end $$;

-- ── replenish_feed: 0072 body, recycle pure noise only ───────────────────────
create or replace function public.replenish_feed()
  returns int language plpgsql security definer set search_path = public as $$
declare
  s       record;
  r       record;
  v_start timestamptz;
  v_pms   bigint;
  v_off   bigint;
  v_count int := 0;
begin
  for s in
    select ts.id from public.team_sessions ts
     where ts.status = 'running'
       and (select count(*) from public.session_injects i
             where i.session_id = ts.id and i.status = 'pending' and i.channel = 'feed') < 4   -- only sessions that need it
     order by random()                                                                            -- fair: no session starves
     limit 100
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;
      select started_at, coalesce(paused_ms, 0) into v_start, v_pms
        from public.team_sessions where id = s.id and status = 'running';
      if not found then continue; end if;
      if (select count(*) from public.session_injects
           where session_id = s.id and status = 'pending' and channel = 'feed') >= 4 then
        continue;
      end if;
      -- Resume from "now" on the pause-aware session clock (was ignoring paused_ms).
      v_off := greatest(0, floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms);
      for r in
        select body, expected_action from public.session_injects
         where session_id = s.id and status = 'fired' and channel = 'feed'   -- never recycle MSEL injects
           and coalesce(expected_action->>'expected_verdict', body->>'expected_verdict', '') not in ('tp','escalate')
           -- 0073: pure noise only (story control steps / ITSM / inject support are benign too now)
           and not (coalesce(expected_action, '{}'::jsonb) ?| array['incident_id', 'supports_inject'])
           and coalesce(expected_action->>'origin', 'noise') = 'noise'
           and coalesce(expected_action->>'is_baseline', '') <> 'true'
         order by random() limit 6
      loop
        v_off := v_off + 3000 + floor(random() * 4000)::bigint;
        insert into public.session_injects(session_id, due_offset_ms, trigger, channel, body, expected_action, status)
        values (s.id, v_off, jsonb_build_object('kind', 'at_time'), 'feed',
                r.body || jsonb_build_object(
                  'id', 'e' || substr(md5(random()::text || clock_timestamp()::text), 1, 12)),  -- opaque, no "_r" tell
                -- ts kept as-is: it sits on the same synthetic base as its raw{} fields, and the
                -- client re-times every log to its occurred_at (a fresh "now" ts here used to
                -- leave the raw timestamps behind and mark recycled noise).
                r.expected_action, 'pending');
        v_count := v_count + 1;
      end loop;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('replenish_error', s.id, sqlerrm);
    end;
  end loop;
  return v_count;
end $$;
