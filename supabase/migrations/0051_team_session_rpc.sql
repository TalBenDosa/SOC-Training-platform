-- HACK THE SOC :: 0051 — Team session write-path + shared live feed — Phase 0.2
-- ===========================================================================
-- The server-authoritative core. Clients never write session_events directly
-- (0049 grants no INSERT); every mutation goes through apply_session_action(),
-- a SECURITY DEFINER RPC that enforces membership + role×phase rules + optimistic
-- concurrency + idempotency, appends ONE event, and updates the projection — all
-- in one transaction. A trigger broadcasts every new event to the private topic
-- session:<id> (Broadcast-from-Database), so all members' browsers see the same
-- event within ~tens of ms. The feed itself is a deterministic timeline seeded
-- per session and promoted on time (promote_due_injects, scheduled in 0052).
--
-- Idempotent. See docs/SPEC-team-soc-multiplayer.md §8.2/§8.5/§13.
-- ===========================================================================

-- ── Role × action × phase gate (extensible; the single place authz lives) ────
create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    -- server/system-only event types can NEVER originate from a client action
    when p_type in ('feed.event','inject.fired','session.started','grade.assigned') then false
    -- lobby ready-check (§13.11) — any member, only while in the lobby
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    -- triage / investigation / command — role-gated, only while running
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role = 'lead'          and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'       -- any member
    when p_type = 'event.opened'             then p_status = 'running'       -- click telemetry, any member
    when p_type = 'message.sent'             then true                       -- war-room, any time
    -- default: members may author generic events while in lobby or running
    else p_status in ('lobby','running')
  end
$$;

-- ── apply_session_action — THE write path ────────────────────────────────────
create or replace function public.apply_session_action(
  p_session uuid, p_type text, p_payload jsonb default '{}'::jsonb,
  p_expected_seq bigint default null, p_idempotency_key text default null
) returns public.session_events
  language plpgsql security definer set search_path = public as $$
declare
  v_uid    uuid := auth.uid();
  v_role   text;
  v_status text;
  v_next   bigint;
  v_row    public.session_events;
  v_prior  public.session_events;
begin
  if v_uid is null then raise exception 'auth_required'; end if;

  select role into v_role from public.team_session_members
    where session_id = p_session and user_id = v_uid;
  if v_role is null then raise exception 'not_a_member'; end if;

  select status into v_status from public.team_sessions where id = p_session;
  if v_status is null then raise exception 'no_such_session'; end if;

  -- idempotency: a retried action (same key) returns the original result
  if p_idempotency_key is not null then
    select * into v_prior from public.session_events
      where session_id = p_session and actor_id = v_uid and idempotency_key = p_idempotency_key;
    if found then return v_prior; end if;
  end if;

  if not public.session_action_allowed(p_type, v_role, v_status) then
    raise exception 'action_not_allowed: % for role % in status %', p_type, v_role, v_status;
  end if;

  select coalesce(max(seq), 0) into v_next from public.session_events where session_id = p_session;
  if p_expected_seq is not null and p_expected_seq <> v_next then
    raise exception 'seq_conflict: expected % but head is %', p_expected_seq, v_next;
  end if;
  v_next := v_next + 1;

  insert into public.session_events(session_id, seq, actor_id, role, type, payload, idempotency_key)
    values (p_session, v_next, v_uid, v_role, p_type, coalesce(p_payload, '{}'::jsonb), p_idempotency_key)
    returning * into v_row;

  insert into public.session_state(session_id, seq) values (p_session, v_next)
    on conflict (session_id) do update set seq = excluded.seq, updated_at = now();

  -- lobby ready-check side effects (§13.11): the "I'm ready" click also = ROE ack
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
grant execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) to authenticated;

-- ── Broadcast-from-Database: fan every new event out to the private topic ────
create or replace function public.broadcast_session_event() returns trigger
  language plpgsql security definer set search_path = public as $$
begin
  perform realtime.send(
    jsonb_build_object('seq', NEW.seq, 'type', NEW.type, 'actor_id', NEW.actor_id,
                       'role', NEW.role, 'payload', NEW.payload, 'occurred_at', NEW.occurred_at),
    'session_event',
    'session:' || NEW.session_id::text,
    true   -- private topic (RLS from 0050 gates who receives it)
  );
  return NEW;
exception when others then
  -- a broadcast hiccup (missing daily partition / no listeners) must never fail the write
  return NEW;
end $$;

drop trigger if exists session_events_broadcast on public.session_events;
create trigger session_events_broadcast after insert on public.session_events
  for each row execute function public.broadcast_session_event();

-- ── Deterministic timeline (0.2 synthetic; the real useLiveEvents engine feeds
--    this table in 0.4). Offsets are seeded from the session seed → reproducible. ─
create or replace function public.seed_session_timeline(p_session uuid)
  returns int language plpgsql security definer set search_path = public as $$
declare v_seed text; i int; v_off bigint; v_count int := 0;
begin
  select seed into v_seed from public.team_sessions where id = p_session;
  if v_seed is null then raise exception 'no_such_session'; end if;
  -- don't double-seed
  if exists (select 1 from public.session_injects where session_id = p_session) then return 0; end if;
  for i in 0..11 loop
    v_off := (i * 8000) + (('x' || substr(md5(v_seed || i::text), 1, 4))::bit(16)::int % 3000);
    insert into public.session_injects(session_id, due_offset_ms, trigger, to_roles, channel, body, expected_action, status)
    values (p_session, v_off, jsonb_build_object('kind','at_time'), '{}', 'feed',
            jsonb_build_object('n', i,
              'severity', case when i in (5,8) then 'high' else 'low' end,
              'summary',  case when i in (5,8) then 'Suspicious activity burst #'||i else 'Routine event #'||i end),
            case when i in (5,8) then jsonb_build_object('verdict','escalate') else null end,
            'pending');
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;
grant execute on function public.seed_session_timeline(uuid) to authenticated;

-- ── start_team_session — staff-only, enforces the ready-check, seeds the feed ─
create or replace function public.start_team_session(p_session uuid)
  returns public.team_sessions language plpgsql security definer set search_path = public as $$
declare v_row public.team_sessions; v_notready int; v_next bigint;
begin
  if not public.is_session_staff(p_session) then raise exception 'staff_only'; end if;
  select count(*) into v_notready from public.team_session_members
    where session_id = p_session and role <> 'instructor' and status not in ('ready','active');
  if v_notready > 0 then raise exception 'not_all_ready: % member(s) not ready', v_notready; end if;
  update public.team_sessions set status = 'running', started_at = now()
    where id = p_session and status in ('lobby','paused') returning * into v_row;
  if v_row.id is null then raise exception 'cannot_start_from_current_status'; end if;
  perform public.seed_session_timeline(p_session);
  -- emit a system 'session.started' event directly (start doesn't require the
  -- caller to be a playing member); the trigger broadcasts it to all clients.
  select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = p_session;
  insert into public.session_events(session_id, seq, actor_id, role, type, payload)
    values (p_session, v_next, null, null, 'session.started', jsonb_build_object('at', now()));
  insert into public.session_state(session_id, seq) values (p_session, v_next)
    on conflict (session_id) do update set seq = excluded.seq, updated_at = now();
  return v_row;
end $$;
grant execute on function public.start_team_session(uuid) to authenticated;

-- ── promote_due_injects — the tick (called by pg_cron in 0052) ────────────────
create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + (i.due_offset_ms || ' milliseconds')::interval <= now()
    order by i.session_id, i.due_offset_ms
  loop
    select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.session_id;
    insert into public.session_events(session_id, seq, actor_id, role, type, payload)
      values (r.session_id, v_next, null, null, 'feed.event', r.body || jsonb_build_object('inject_id', r.id));
    update public.session_injects set status = 'fired', fired_seq = v_next where id = r.id;
    update public.session_state set seq = v_next, updated_at = now() where session_id = r.session_id;
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;
grant execute on function public.promote_due_injects() to authenticated;
