-- HACK THE SOC :: 0071 — Team-SOC Phase 2: server authority (audit 2026-09-26)
-- ===========================================================================
-- Backward-compatible and VERSION-GATED: team_sessions.schema_version (new /start
-- sets 2). v1 sessions (already running / legacy clients) keep today's behavior;
-- all new lifecycle / presence / click / answer-key behavior applies to v2 only.
--
--  • One lock rule: every writer takes the per-session advisory lock FIRST.
--    User paths block on ONE session; background jobs loop per session with a
--    try-lock and skip busy sessions (they never wait → no lock cycles).
--  • Single seq allocator (no retry loops); occurred_at = clock_timestamp().
--  • team_transition(): status flip + lifecycle event in ONE transaction,
--    pause_reason tracked in a column, end ⇒ pending injects 'skipped'.
--  • Server-side presence: team_heartbeat() + team_lifecycle_tick() replace the
--    client "elected member" coverage / owner-left logic (v2).
--  • apply_session_action: lock-first status re-check, left/inactive members
--    rejected, lenient rate limit + hard cap, staff.inject kind masked (answer
--    kept in session_injects), v2 click telemetry kept OFF the event log.
--  • Access: client write policies dropped; set-based read policies; realtime
--    read for session staff; is_team_member excludes left / inactive members.
--  • Ops: team_ops_events (errors instead of silent swallows), team_ops_health,
--    team_session_reports (server-authoritative AAR), cron purge.
-- Every new object is revoked from public/anon/authenticated (service_role
-- only) except team_heartbeat and the RLS set helpers (authenticated).
-- Apply with the team cron jobs paused (see runbook in the PR/commit).
-- ===========================================================================

-- ── 0. Columns (DDL first) ──────────────────────────────────────────────────
alter table public.team_sessions
  add column if not exists schema_version  integer not null default 1,
  add column if not exists pause_reason    text,
  add column if not exists staff_seen_at   timestamptz,
  add column if not exists nudged_at       timestamptz,
  add column if not exists lifecycle_state jsonb not null default '{}'::jsonb;
alter table public.team_session_members
  add column if not exists last_seen_at timestamptz;
alter table public.session_events
  alter column occurred_at set default clock_timestamp();

create index if not exists session_events_actor_time_idx
  on public.session_events (session_id, actor_id, occurred_at desc);

-- ── 1. New tables (service-only) ────────────────────────────────────────────
create table if not exists public.session_clicks (
  id          bigserial primary key,
  session_id  uuid not null references public.team_sessions(id) on delete cascade,
  user_id     uuid not null,
  event_id    text,
  dwell_ms    integer not null default 0 check (dwell_ms between 0 and 3600000),
  occurred_at timestamptz not null default clock_timestamp()
);
create index if not exists session_clicks_session_idx on public.session_clicks (session_id, user_id);

create table if not exists public.team_ops_events (
  id         bigserial primary key,
  at         timestamptz not null default clock_timestamp(),
  kind       text not null,
  session_id uuid,
  detail     text
);
create index if not exists team_ops_events_at_idx on public.team_ops_events (at desc);

create table if not exists public.team_session_reports (
  session_id  uuid primary key references public.team_sessions(id) on delete cascade,
  report      jsonb not null,
  computed_at timestamptz not null default now()
);

alter table public.session_clicks       enable row level security;
alter table public.team_ops_events      enable row level security;
alter table public.team_session_reports enable row level security;
revoke all on public.session_clicks, public.team_ops_events, public.team_session_reports from public, anon, authenticated;
grant all on public.session_clicks, public.team_ops_events, public.team_session_reports to service_role;
revoke all on sequence public.session_clicks_id_seq, public.team_ops_events_id_seq from public, anon, authenticated;
grant usage, select on sequence public.session_clicks_id_seq, public.team_ops_events_id_seq to service_role;

-- ── 2. Lock + allocator + insert helper (callers hold the session lock) ─────
create or replace function public.team_lock_session(p_session uuid) returns void
  language sql volatile set search_path = public as $$
  select pg_advisory_xact_lock(hashtext('team_seq'), hashtext(p_session::text));
$$;
create or replace function public.team_try_lock_session(p_session uuid) returns boolean
  language sql volatile set search_path = public as $$
  select pg_try_advisory_xact_lock(hashtext('team_seq'), hashtext(p_session::text));
$$;
create or replace function public.team_next_seq(p_session uuid) returns bigint
  language sql volatile set search_path = public as $$
  select coalesce(max(seq), 0) + 1 from public.session_events where session_id = p_session;
$$;
create or replace function public.team_insert_event(
  p_session uuid, p_actor uuid, p_role text, p_type text, p_payload jsonb, p_idem text default null)
returns public.session_events language plpgsql security definer set search_path = public as $$
declare v_row public.session_events;
begin
  insert into public.session_events(session_id, seq, actor_id, role, type, payload, idempotency_key)
    values (p_session, public.team_next_seq(p_session), p_actor, p_role, p_type, coalesce(p_payload, '{}'::jsonb), p_idem)
    returning * into v_row;
  insert into public.session_state(session_id, seq) values (p_session, v_row.seq)
    on conflict (session_id) do update set seq = greatest(public.session_state.seq, excluded.seq), updated_at = now();
  return v_row;
end $$;

-- ── 3. RLS set helpers (evaluated once per query, not per row) ──────────────
create or replace function public.team_my_sessions() returns setof uuid
  language sql stable security definer set search_path = public as $$
  select m.session_id
    from public.team_session_members m
    join public.team_sessions ts on ts.id = m.session_id
    join public.org_members om on om.org_id = ts.org_id and om.user_id = m.user_id
   where m.user_id = auth.uid() and m.status <> 'left' and om.status = 'active'
     and (om.affiliation_expires_at is null or om.affiliation_expires_at > now())
$$;
create or replace function public.team_staff_sessions() returns setof uuid
  language sql stable security definer set search_path = public as $$
  select ts.id from public.team_sessions ts
   where ts.org_id = public.current_org() and public.current_org_role() in ('org_admin','instructor')
$$;

create or replace function public.is_team_member(p_session uuid, p_user uuid)
  returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.team_session_members m
      join public.team_sessions ts on ts.id = m.session_id
      join public.org_members om on om.org_id = ts.org_id and om.user_id = m.user_id
     where m.session_id = p_session and m.user_id = p_user and m.status <> 'left'
       and om.status = 'active'
       and (om.affiliation_expires_at is null or om.affiliation_expires_at > now())
  )
$$;

-- ── 4. Gate: new system-only types (member.ready/unready stay player-writable) ─
create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','session.paused','session.resumed','grade.assigned',
                    'hint.nudge','member.added','member.role_changed','member.removed') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
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
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'sitrep.sent'              then p_role in ('lead','mgr') and p_status = 'running'
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

-- ── 5. apply_session_action — lock-first, hardened ──────────────────────────
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

-- ── 6. System event + atomic lifecycle transition (service role) ────────────
create or replace function public.append_system_event(p_session uuid, p_type text, p_payload jsonb default '{}'::jsonb)
returns bigint language plpgsql security definer set search_path = public as $$
begin
  perform public.team_lock_session(p_session);
  return (public.team_insert_event(p_session, null, null, p_type, coalesce(p_payload, '{}'::jsonb))).seq;
end $$;

create or replace function public.team_transition(
  p_session uuid, p_to text, p_reason text default 'manual', p_by uuid default null, p_detail text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  s          public.team_sessions;
  v_now      timestamptz := clock_timestamp();
  v_type     text;
  v_notready integer;
  v_ev       public.session_events;
begin
  perform public.team_lock_session(p_session);          -- lock first, then the row
  select * into s from public.team_sessions where id = p_session for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;

  if p_to = 'running' and s.status = 'lobby' then
    select count(*) into v_notready from public.team_session_members
      where session_id = p_session and role not in ('instructor','observer')
        and status not in ('ready','active');
    if v_notready > 0 then
      return jsonb_build_object('ok', false, 'error', 'not_ready', 'count', v_notready);
    end if;
    update public.team_sessions
       set status = 'running', started_at = v_now, paused_at = null, paused_ms = 0,
           pause_reason = null, lifecycle_state = '{}'::jsonb
     where id = p_session;
    v_type := 'session.started';
  elsif p_to = 'paused' and s.status = 'running' then
    update public.team_sessions set status = 'paused', paused_at = v_now, pause_reason = p_reason,
           lifecycle_state = '{}'::jsonb where id = p_session;
    v_type := 'session.paused';
  elsif p_to = 'paused' and s.status = 'paused'
        and coalesce(s.pause_reason, '') <> 'manual' and p_reason is distinct from s.pause_reason then
    -- reason switch (coverage ↔ owner_left) or upgrade to manual (the tick then never resumes it)
    update public.team_sessions set pause_reason = p_reason, lifecycle_state = '{}'::jsonb where id = p_session;
    v_type := 'session.paused';
  elsif p_to = 'running' and s.status = 'paused' then
    update public.team_sessions
       set status = 'running',
           paused_ms = coalesce(s.paused_ms, 0)
                       + greatest(0, floor(extract(epoch from (v_now - coalesce(s.paused_at, v_now))) * 1000))::bigint,
           paused_at = null, pause_reason = null, lifecycle_state = '{}'::jsonb
     where id = p_session;
    v_type := 'session.resumed';
  elsif p_to = 'ended' and s.status in ('lobby','running','paused') then
    update public.team_sessions set status = 'ended', ended_at = v_now, paused_at = null where id = p_session;
    update public.session_injects set status = 'skipped' where session_id = p_session and status = 'pending';
    v_type := 'session.ended';
  else
    return jsonb_build_object('ok', true, 'noop', true, 'status', s.status);
  end if;

  v_ev := public.team_insert_event(p_session, null, null, v_type,
            jsonb_strip_nulls(jsonb_build_object('at', v_now, 'reason', p_reason, 'detail', p_detail, 'by', p_by)));
  return jsonb_build_object('ok', true, 'seq', v_ev.seq, 'type', v_type);
end $$;

-- ── 7. Background jobs: per-session loops, try-lock, error isolation ────────
create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare
  s       record;
  r       record;
  v_start timestamptz;
  v_pms   bigint;
  v_off   bigint;
  v_type  text;
  v_ev    public.session_events;
  v_count int := 0;
begin
  for s in
    select ts.id from public.team_sessions ts
     where ts.status = 'running'
       and exists (select 1 from public.session_injects i where i.session_id = ts.id and i.status = 'pending')
     order by ts.started_at
     limit 50
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;   -- busy → next tick
      select started_at, coalesce(paused_ms, 0) into v_start, v_pms
        from public.team_sessions where id = s.id and status = 'running';
      if not found then continue; end if;
      v_off := floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms;
      for r in
        select i.* from public.session_injects i
         where i.session_id = s.id and i.status = 'pending' and i.due_offset_ms <= v_off
         order by i.due_offset_ms
         limit 200
         for update of i skip locked
      loop
        v_type := case when r.channel = 'inject' then 'staff.inject' else 'feed.event' end;
        v_ev := public.team_insert_event(s.id, null, null, v_type, r.body || jsonb_build_object('inject_id', r.id));
        update public.session_injects set status = 'fired', fired_seq = v_ev.seq
         where id = r.id and status = 'pending';
        v_count := v_count + 1;
      end loop;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('promote_error', s.id, sqlerrm);
    end;
  end loop;
  return v_count;
end $$;

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
  for s in select ts.id from public.team_sessions ts where ts.status = 'running' order by ts.started_at limit 50 loop
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
         order by random() limit 6
      loop
        v_off := v_off + 3000 + floor(random() * 4000)::bigint;
        insert into public.session_injects(session_id, due_offset_ms, trigger, channel, body, expected_action, status)
        values (s.id, v_off, jsonb_build_object('kind', 'at_time'), 'feed',
                r.body || jsonb_build_object(
                  'id', 'e' || substr(md5(random()::text || clock_timestamp()::text), 1, 12),  -- opaque, no "_r" tell
                  'ts', to_char(now() at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')),
                r.expected_action, 'pending');
        v_count := v_count + 1;
      end loop;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('replenish_error', s.id, sqlerrm);
    end;
  end loop;
  return v_count;
end $$;

create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_res jsonb; v_count int := 0;
begin
  for r in
    select ts.id from public.team_sessions ts
     where ts.status in ('running','paused')
       and (
         ts.started_at < now() - interval '4 hours'                                   -- absolute cap
         or (ts.status = 'paused' and ts.pause_reason = 'manual'
             and coalesce(ts.paused_at, ts.started_at) < now() - interval '3 hours')   -- long manual pause
         or ((ts.status = 'running' or coalesce(ts.pause_reason, '') <> 'manual')
             and coalesce((select max(e.occurred_at) from public.session_events e
                            where e.session_id = ts.id and e.actor_id is not null), ts.started_at)
                 < now() - interval '30 minutes'                                      -- no human action
             and coalesce((select max(m.last_seen_at) from public.team_session_members m
                            where m.session_id = ts.id), '-infinity'::timestamptz)
                 < now() - interval '10 minutes')                                     -- nobody's heartbeat
       )
     limit 50
  loop
    begin
      v_res := public.team_transition(r.id, 'ended', 'reaped', null, null);
      if coalesce((v_res->>'ok')::boolean, false) and not coalesce((v_res->>'noop')::boolean, false) then
        v_count := v_count + 1;
      end if;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('reap_error', r.id, sqlerrm);
    end;
  end loop;
  return v_count;
end $$;

-- ── 8. Server-side presence (v2) ────────────────────────────────────────────
create or replace function public.team_heartbeat(p_session uuid) returns void
  language plpgsql security definer set search_path = public as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then return; end if;
  update public.team_session_members m set last_seen_at = clock_timestamp()
   where m.session_id = p_session and m.user_id = v_uid and m.status <> 'left'
     and (m.last_seen_at is null or m.last_seen_at < clock_timestamp() - interval '10 seconds');
  if public.is_session_staff(p_session) then
    update public.team_sessions set staff_seen_at = clock_timestamp()
     where id = p_session and (staff_seen_at is null or staff_seen_at < clock_timestamp() - interval '10 seconds');
  end if;
end $$;

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
     order by started_at limit 50
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
                          where m2.session_id = s.id and m2.role = r.role and m2.status <> 'left'
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

-- ── 9. Broadcast trigger: log failures instead of swallowing them ───────────
create or replace function public.broadcast_session_event() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  perform realtime.send(
    jsonb_build_object('seq', NEW.seq, 'type', NEW.type, 'actor_id', NEW.actor_id,
                       'role', NEW.role, 'payload', NEW.payload, 'occurred_at', NEW.occurred_at),
    'session_event',
    'session:' || NEW.session_id::text,
    true
  );
  return NEW;
exception when others then
  begin
    insert into public.team_ops_events(kind, session_id, detail) values ('broadcast_failed', NEW.session_id, sqlerrm);
  exception when others then null;
  end;
  return NEW;   -- a broadcast hiccup must never fail the write
end $$;

-- ── 10. Ops health view (service-only) ──────────────────────────────────────
create or replace view public.team_ops_health as
select
  (select count(*) from public.team_sessions where status = 'running')                  as running_sessions,
  (select count(*) from public.team_sessions where status = 'paused')                   as paused_sessions,
  (select coalesce(max(floor(extract(epoch from (clock_timestamp() - s.started_at)) * 1000)::bigint
                       - s.paused_ms - i.due_offset_ms), 0) / 1000.0
     from public.session_injects i join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and i.due_offset_ms <= floor(extract(epoch from (clock_timestamp() - s.started_at)) * 1000)::bigint - s.paused_ms)
                                                                                         as max_promote_lag_s,
  (select count(*) from public.team_ops_events where at > now() - interval '1 hour')    as ops_errors_1h,
  (select count(*) from public.team_ops_events
    where kind = 'broadcast_failed' and at > now() - interval '1 hour')                 as broadcast_failures_1h;

-- ── 11. Access: drop client write paths, set-based reads ────────────────────
drop policy if exists team_sessions_write on public.team_sessions;
drop policy if exists tsm_write on public.team_session_members;
revoke insert, update, delete on public.team_sessions, public.team_session_members from authenticated;

drop policy if exists team_sessions_read on public.team_sessions;
create policy team_sessions_read on public.team_sessions for select to authenticated
  using (id in (select public.team_my_sessions()) or id in (select public.team_staff_sessions()));
drop policy if exists tsm_read on public.team_session_members;
create policy tsm_read on public.team_session_members for select to authenticated
  using (session_id in (select public.team_my_sessions()) or session_id in (select public.team_staff_sessions()));
drop policy if exists session_events_read on public.session_events;
create policy session_events_read on public.session_events for select to authenticated
  using (session_id in (select public.team_my_sessions()) or session_id in (select public.team_staff_sessions()));
drop policy if exists session_state_read on public.session_state;
create policy session_state_read on public.session_state for select to authenticated
  using (session_id in (select public.team_my_sessions()) or session_id in (select public.team_staff_sessions()));
drop policy if exists session_injects_staff_read on public.session_injects;
create policy session_injects_staff_read on public.session_injects for select to authenticated
  using (session_id in (select public.team_staff_sessions()));

-- ── 12. Privileges for every new / replaced function ────────────────────────
revoke execute on function public.team_lock_session(uuid)                        from public, anon, authenticated;
revoke execute on function public.team_try_lock_session(uuid)                    from public, anon, authenticated;
revoke execute on function public.team_next_seq(uuid)                            from public, anon, authenticated;
revoke execute on function public.team_insert_event(uuid, uuid, text, text, jsonb, text) from public, anon, authenticated;
revoke execute on function public.append_system_event(uuid, text, jsonb)         from public, anon, authenticated;
revoke execute on function public.team_transition(uuid, text, text, uuid, text)  from public, anon, authenticated;
revoke execute on function public.team_lifecycle_tick()                          from public, anon, authenticated;
revoke execute on function public.promote_due_injects()                          from public, anon, authenticated;
revoke execute on function public.replenish_feed()                               from public, anon, authenticated;
revoke execute on function public.reap_stale_team_sessions()                     from public, anon, authenticated;
grant  execute on function public.append_system_event(uuid, text, jsonb)         to service_role;
grant  execute on function public.team_transition(uuid, text, text, uuid, text)  to service_role;
grant  execute on function public.team_lifecycle_tick()                          to service_role;

revoke execute on function public.team_heartbeat(uuid)   from public, anon;
grant  execute on function public.team_heartbeat(uuid)   to authenticated;
revoke execute on function public.team_my_sessions()     from public, anon;
revoke execute on function public.team_staff_sessions()  from public, anon;
grant  execute on function public.team_my_sessions()     to authenticated;
grant  execute on function public.team_staff_sessions()  to authenticated;
revoke execute on function public.is_team_member(uuid, uuid) from public, anon;
grant  execute on function public.is_team_member(uuid, uuid) to authenticated;
revoke execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) from public, anon;
grant  execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) to authenticated;

revoke all on public.team_ops_health from public, anon, authenticated;
grant select on public.team_ops_health to service_role;

-- ── 13. Cron: lifecycle tick every 10s; daily run-history purge ─────────────
do $$ begin perform cron.unschedule('team-lifecycle-tick'); exception when others then null; end $$;
select cron.schedule('team-lifecycle-tick', '10 seconds', $cron$ select public.team_lifecycle_tick(); $cron$);
do $$ begin perform cron.unschedule('team-cron-purge'); exception when others then null; end $$;
select cron.schedule('team-cron-purge', '17 3 * * *',
  $cron$ delete from cron.job_run_details where end_time < now() - interval '3 days'; $cron$);

-- ── 14. Realtime: session staff may RECEIVE (not send) on the topic — LAST ──
drop policy if exists "team session realtime read" on realtime.messages;
create policy "team session realtime read" on realtime.messages
  for select to authenticated
  using (
    extension in ('broadcast','presence')
    and (public.is_team_member(public.team_topic_session(realtime.topic()), auth.uid())
         or public.is_session_staff(public.team_topic_session(realtime.topic())))
  );
