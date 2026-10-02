-- HACK THE SOC :: 0088 — Team-SOC QA fixes (docs/team-review/QA-2026-10-02-team-training.md)
-- ===========================================================================
--  M2  Click telemetry: `event.opened` must name a feed log this session has FIRED;
--      dwell capped at 10 min; its own rate budget (20 / 10s, 120 / min — over it the
--      click is dropped silently). The action budget is now checked BEFORE the role
--      gate and validation. The report reads clicks as one aggregate row per
--      (player, log) — team_session_click_totals — so a click flood can't push the
--      report past its row cap any more.
--  M3  Pauses never count: team_active_ms() = running time between two instants
--      (paused spans rebuilt from session.paused / resumed / ended). The Tier-1 claim
--      lock (5 min) now ages in running time — the same rule as the live projections.
--  M4  ioc-truth lookups are budgeted per player (team_ioc_lookup_allowed).
--  M5  One report build at a time per session: team_try_lease / team_release_lease
--      (a short lease row; a crashed holder just lets it expire).
--  L1  The 60-member roster cap is enforced in a trigger (count + write in one step).
--  L5  team_sessions.xp_awarded_at, stamped by award_team_session_xp even when the
--      session scored nobody — the daily sweep selects on it (no 200-row window, no
--      zero-player session re-entering every night). Back-filled from team_session_xp.
--
-- Safe on a live database: additive only (one nullable column, two service-only
-- tables, new service-only functions, one roster trigger); the three redefined
-- functions keep their signatures and grants and are copied verbatim from 0073 /
-- 0082 / 0087 with only the marked lines changed. App code deployed before this
-- migration keeps working (it never calls the new functions; old clients' clicks
-- always carry a fired log id). The new app code falls back when the functions are
-- missing, but should ship AFTER this migration for the fixes to take effect.
-- ===========================================================================

alter table public.team_sessions add column if not exists xp_awarded_at timestamptz;

create index if not exists session_clicks_user_time_idx
  on public.session_clicks (session_id, user_id, occurred_at desc);

-- ── M3: running (un-paused) milliseconds between two instants of a session ────
create or replace function public.team_active_ms(p_session uuid, p_from timestamptz, p_to timestamptz)
returns bigint language sql stable set search_path = public as $$
  with life as (
    select type, occurred_at, lead(occurred_at) over (order by seq) as next_at
      from public.session_events
     where session_id = p_session and type in ('session.paused','session.resumed','session.ended')
  ), spans as (
    -- a second session.paused (reason switch) simply continues the span
    select occurred_at as s, coalesce(next_at, p_to) as e from life where type = 'session.paused'
  )
  select greatest(0,
           floor(extract(epoch from (p_to - p_from)) * 1000)::bigint
           - coalesce((select sum(greatest(0, floor(extract(epoch from (least(e, p_to) - greatest(s, p_from))) * 1000)))
                         from spans where e > p_from and s < p_to), 0)::bigint)
$$;
revoke execute on function public.team_active_ms(uuid, timestamptz, timestamptz) from public, anon, authenticated;
grant  execute on function public.team_active_ms(uuid, timestamptz, timestamptz) to service_role;

-- ── 1. team_validate_action: 0082 body, claim TTL in running time (M3) ─────────
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

-- ── 2. apply_session_action: 0073 body, budgets first + validated clicks (M2) ──
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
  v_eid     text;
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

  -- 0088 (QA M2): the budgets are checked FIRST — before the role gate and the
  -- validation work — so an actor over budget is refused cheaply whatever they send.
  -- (A rejected attempt can't itself be counted: its transaction rolls back.)
  -- Actions: lenient per-actor limit, burst 30 / 10s, 90 / min (unchanged numbers).
  -- Clicks (v2 telemetry): their own budget, 20 / 10s and 120 / min; past it a click
  -- is dropped silently — telemetry is analytics, never an error the player sees.
  if p_type = 'event.opened' and v_version >= 2 then
    if (select count(*) from public.session_clicks c
         where c.session_id = p_session and c.user_id = v_uid
           and c.occurred_at > clock_timestamp() - interval '10 seconds') >= 20
    or (select count(*) from public.session_clicks c
         where c.session_id = p_session and c.user_id = v_uid
           and c.occurred_at > clock_timestamp() - interval '60 seconds') >= 120 then
      return null;
    end if;
  elsif p_type <> 'event.opened' and (
       (select count(*) from public.session_events e
         where e.session_id = p_session and e.actor_id = v_uid and e.type <> 'event.opened'
           and e.occurred_at > clock_timestamp() - interval '10 seconds') >= 30
    or (select count(*) from public.session_events e
         where e.session_id = p_session and e.actor_id = v_uid and e.type <> 'event.opened'
           and e.occurred_at > clock_timestamp() - interval '60 seconds') >= 90) then
    raise exception 'rate_limited';
  end if;

  if not public.session_action_allowed(p_type, v_role, v_status) then
    raise exception 'action_not_allowed: % for role % in status %', p_type, v_role, v_status;
  end if;

  -- 0073: shape / reference / ownership checks, race-free under the session lock.
  if p_type <> 'event.opened' then
    perform public.team_validate_action(p_session, v_uid, p_type, v_payload);
  end if;

  -- v2: click telemetry never enters the event log (no seq, no broadcast, no gaps).
  -- 0088 (QA M2): a click must name a log this session has FIRED (no forged ids, no
  -- unbounded junk keys), and its dwell is capped at 10 minutes (a tab left open is
  -- not 10 minutes of reading).
  if p_type = 'event.opened' and v_version >= 2 then
    v_eid := nullif(btrim(coalesce(v_payload->>'event_id', '')), '');
    if v_eid is null or length(v_eid) > 200 or not exists (
         select 1 from public.session_events
          where session_id = p_session and type = 'feed.event' and payload->>'id' = v_eid) then
      raise exception 'unknown_event: %', coalesce(left(v_eid, 64), '');
    end if;
    v_dwell := case when (v_payload->>'dwell_ms') ~ '^[0-9]+(\.[0-9]+)?$'
                    then least(600000, floor((v_payload->>'dwell_ms')::numeric))::integer else 0 end;
    insert into public.session_clicks(session_id, user_id, event_id, dwell_ms)
      values (p_session, v_uid, v_eid, v_dwell);
    return null;
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
revoke execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) from public, anon;
grant  execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) to authenticated;

-- ── 3. award_team_session_xp: 0087 body + the awarded stamp (L5) ──────────────
create or replace function public.award_team_session_xp(p_session uuid, p_rows jsonb, p_version integer default 1)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare r record; v_n integer := 0;
begin
  if not exists (select 1 from public.team_sessions where id = p_session and status in ('ended','debriefed')) then
    raise exception 'award_team_session_xp: session % has not ended', p_session;
  end if;
  for r in
    select (x->>'user_id')::uuid as uid, greatest(0, least(200, coalesce((x->>'xp')::int, 0))) as xp
      from jsonb_array_elements(coalesce(p_rows, '[]'::jsonb)) x
  loop
    if not exists (select 1 from public.team_session_members m where m.session_id = p_session and m.user_id = r.uid) then
      continue;   -- not on this session's roster
    end if;
    insert into public.team_session_xp (session_id, user_id, xp, formula_version, computed_at)
    values (p_session, r.uid, r.xp, p_version, now())
    on conflict (session_id, user_id) do update
      set xp = excluded.xp, formula_version = excluded.formula_version, computed_at = excluded.computed_at;
    perform public.recompute_user_xp(r.uid);
    v_n := v_n + 1;
  end loop;
  -- 0088 (QA L5): stamp the session even when nobody was scored (a zero-player
  -- session), so the daily sweep never picks it up again.
  update public.team_sessions set xp_awarded_at = now() where id = p_session;
  return v_n;
end;
$$;
revoke all on function public.award_team_session_xp(uuid, jsonb, integer) from public, anon, authenticated;
grant execute on function public.award_team_session_xp(uuid, jsonb, integer) to service_role;

-- ── 4. M2: click telemetry as one row per (player, log) for the report ─────────
-- computeReport needs, per player, the DISTINCT logs opened and the longest read of
-- each; opens / total dwell come along for analytics. Ordered for stable paging.
create or replace function public.team_session_click_totals(p_session uuid)
returns table (user_id uuid, event_id text, opens integer, max_dwell_ms integer, sum_dwell_ms bigint, first_at timestamptz)
language sql stable security definer set search_path = public as $$
  select c.user_id, coalesce(c.event_id, ''), count(*)::integer, max(c.dwell_ms), sum(c.dwell_ms)::bigint, min(c.occurred_at)
    from public.session_clicks c
   where c.session_id = p_session
   group by c.user_id, coalesce(c.event_id, '')
   order by 1, 2
$$;
revoke execute on function public.team_session_click_totals(uuid) from public, anon, authenticated;
grant  execute on function public.team_session_click_totals(uuid) to service_role;

-- ── 5. M5: a short build lease per (session, kind) ─────────────────────────────
create table if not exists public.team_session_leases (
  session_id uuid not null references public.team_sessions(id) on delete cascade,
  kind       text not null check (kind in ('report','xp')),
  expires_at timestamptz not null,
  primary key (session_id, kind)
);
alter table public.team_session_leases enable row level security;
revoke all on public.team_session_leases from public, anon, authenticated;
grant all on public.team_session_leases to service_role;

-- true = the caller holds the lease now (it was free or had expired).
create or replace function public.team_try_lease(p_session uuid, p_kind text, p_ttl_s integer default 60)
returns boolean language plpgsql security definer set search_path = public as $$
declare v_ok boolean;
begin
  insert into public.team_session_leases (session_id, kind, expires_at)
  values (p_session, p_kind, clock_timestamp() + make_interval(secs => greatest(5, least(coalesce(p_ttl_s, 60), 600))))
  on conflict (session_id, kind) do update set expires_at = excluded.expires_at
    where public.team_session_leases.expires_at < clock_timestamp()
  returning true into v_ok;
  return coalesce(v_ok, false);
end $$;
revoke execute on function public.team_try_lease(uuid, text, integer) from public, anon, authenticated;
grant  execute on function public.team_try_lease(uuid, text, integer) to service_role;

create or replace function public.team_release_lease(p_session uuid, p_kind text)
returns void language sql security definer set search_path = public as $$
  delete from public.team_session_leases where session_id = p_session and kind = p_kind
$$;
revoke execute on function public.team_release_lease(uuid, text) from public, anon, authenticated;
grant  execute on function public.team_release_lease(uuid, text) to service_role;

-- ── 6. M4: per-player budget for threat-intel lookups ──────────────────────────
create table if not exists public.team_ioc_lookups (
  id         bigserial primary key,
  session_id uuid not null references public.team_sessions(id) on delete cascade,
  user_id    uuid not null references auth.users(id) on delete cascade,
  n          integer not null check (n between 1 and 100),
  at         timestamptz not null default clock_timestamp()
);
create index if not exists team_ioc_lookups_user_idx on public.team_ioc_lookups (session_id, user_id, at desc);
alter table public.team_ioc_lookups enable row level security;
revoke all on public.team_ioc_lookups from public, anon, authenticated;
grant all on public.team_ioc_lookups to service_role;
revoke all on sequence public.team_ioc_lookups_id_seq from public, anon, authenticated;
grant usage, select on sequence public.team_ioc_lookups_id_seq to service_role;

-- 40 calls and 200 IOCs per player per rolling minute (honest play — a lookup batch
-- per opened log — stays far below). true = allowed, and the call is recorded.
create or replace function public.team_ioc_lookup_allowed(p_session uuid, p_user uuid, p_n integer)
returns boolean language plpgsql security definer set search_path = public as $$
declare v_calls integer; v_iocs integer; v_n integer := greatest(1, least(coalesce(p_n, 1), 100));
begin
  perform pg_advisory_xact_lock(hashtext('ioc:' || p_session::text || ':' || p_user::text));
  delete from public.team_ioc_lookups
   where session_id = p_session and user_id = p_user and at < clock_timestamp() - interval '10 minutes';
  select count(*), coalesce(sum(n), 0) into v_calls, v_iocs from public.team_ioc_lookups
   where session_id = p_session and user_id = p_user and at > clock_timestamp() - interval '60 seconds';
  if v_calls >= 40 or v_iocs + v_n > 200 then return false; end if;
  insert into public.team_ioc_lookups (session_id, user_id, n) values (p_session, p_user, v_n);
  return true;
end $$;
revoke execute on function public.team_ioc_lookup_allowed(uuid, uuid, integer) from public, anon, authenticated;
grant  execute on function public.team_ioc_lookup_allowed(uuid, uuid, integer) to service_role;

-- ── 7. L1: the 60-member roster cap, enforced where the row is written ────────
-- The members route checked the cap, then inserted — two concurrent adds could both
-- pass. A per-session roster lock (NOT the session's action lock, so no lock-order
-- interplay) makes the count and the write one step. Single seats already have a
-- unique index (0065); the route maps both conflicts to 409.
create or replace function public.team_roster_cap()
returns trigger language plpgsql set search_path = public as $$
begin
  if new.status = 'left' then return new; end if;
  if tg_op = 'UPDATE' then
    if old.status <> 'left' then return new; end if;           -- only a re-join counts toward the cap
  end if;
  perform pg_advisory_xact_lock(hashtext('team_roster'), hashtext(new.session_id::text));
  if (select count(*) from public.team_session_members m
       where m.session_id = new.session_id and m.status <> 'left' and m.user_id <> new.user_id) >= 60 then
    raise exception 'roster_full: a session holds at most 60 members';
  end if;
  return new;
end $$;
revoke execute on function public.team_roster_cap() from public, anon, authenticated;
drop trigger if exists team_roster_cap on public.team_session_members;
create trigger team_roster_cap before insert or update of status on public.team_session_members
  for each row execute function public.team_roster_cap();

-- ── 8. L5 back-fill: sessions that already have XP rows are awarded ───────────
update public.team_sessions s
   set xp_awarded_at = x.at
  from (select session_id, max(computed_at) as at from public.team_session_xp group by session_id) x
 where x.session_id = s.id and s.xp_awarded_at is null;

-- Verification (run by hand after applying):
--  1. select public.team_active_ms('<session with a pause>', started_at, ended_at) from team_sessions where id = '<id>';
--     → (ended_at − started_at) minus the paused time, in ms.
--  2. As a player of a running v2 session: apply_session_action(<id>, 'event.opened',
--     '{"event_id":"nope"}') → unknown_event; a fired log id → a session_clicks row,
--     dwell_ms ≤ 600000.
--  3. select * from team_session_click_totals('<id>') limit 5;
--  4. select team_try_lease('<id>', 'report', 30), team_try_lease('<id>', 'report', 30); → true, false
--     select team_release_lease('<id>', 'report');
--  5. select count(*) from team_sessions where status in ('ended','debriefed') and xp_awarded_at is null;
