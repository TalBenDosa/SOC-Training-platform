-- 0104_team_lifecycle_isolation.sql
--
-- Team Training fixes after the 2026-11 expert review of two real exercises.
--
-- 1. NO AUTOMATIC PAUSE (owner's top request). The lifecycle tick used to pause the
--    whole room when the instructor's heartbeat went stale (owner_left, seen 3 times
--    in two exercises, 5 to 19 s each) or a Tier-1 / Tier-2 seat went offline
--    (coverage). A pause now happens only when staff or the session's Manager press
--    Pause: team_transition refuses any other pause reason. The tick raises a
--    non-blocking `presence.notice` { kind, state: raised | cleared, missing, detail }
--    instead, and resumes any automatic pause left over from before this migration.
-- 2. 4-HOUR REAPER ON ACTIVE TIME, WITH A WARNING. The cap counts running time only
--    (paused time excluded) and a `session.reap_warning` is appended at least 4 minutes
--    before the reaper ends a session (team_sessions.reap_warned_at).
-- 3. SCHEDULED END. Staff (or the Manager) end the shift two minutes ahead:
--    team_schedule_end() stores team_sessions.end_at and appends
--    `session.end_scheduled` { ends_at, by, delay_ms }; team_cancel_end() undoes it
--    (`session.end_cancelled`); the lifecycle tick ends the session at end_at
--    (`session.ended` reason "scheduled"). "End now" stays team_transition(ended).
--    Ending while paused now closes the open pause into paused_ms, and the injects
--    that never fired are marked skip_reason 'shift_ended' for the report.
-- 4. ISOLATION NEEDS THE SHIFT SENIOR'S APPROVAL. Tier-2 / Tier-3 send
--    `isolation.requested` { host, reason, incident?, case? }; the approver answers
--    `isolation.approved` / `isolation.denied` { request_seq, reason? }. Approver rule
--    (same as src/lib/team/isolationApproval.ts): a seated, active SOC Manager or Lead;
--    else a seated, active Tier-3 who is not the requester; else the instructor seat.
--    The instructor may always approve as an override; nobody approves their own
--    request. On approval a trigger records `edr.host_isolated` (actor = requester)
--    and one EDR containment status row. Clients can no longer write
--    edr.host_isolated. Release stays direct (`edr.host_released`) for Tier-2,
--    Tier-3, the Manager / Lead and the instructor.
-- 5. AN ISOLATED HOST LEAVES THE EXERCISE. promote_due_injects releases no feed row
--    whose hostname is the isolated host or whose source / destination is its
--    address: such injects are marked skipped with skip_reason 'isolated:<host>'.
--    replenish_feed no longer recycles rows about an isolated host. A release brings
--    the host back.
--
-- Idempotent: add column if not exists, create or replace, drop trigger if exists.
-- Verify (staging), see scripts/test-0104-db.mjs for the full run in PGlite:
--   select public.session_action_allowed('edr.host_isolated','t2','running');     -- false
--   select public.session_action_allowed('isolation.requested','t2','running');   -- true

-- ── columns ──────────────────────────────────────────────────────────────────
alter table public.team_sessions   add column if not exists end_at           timestamptz;
alter table public.team_sessions   add column if not exists end_scheduled_by uuid;
alter table public.team_sessions   add column if not exists reap_warned_at   timestamptz;
alter table public.team_sessions   add column if not exists presence_notice  text;
alter table public.session_injects add column if not exists skip_reason      text;

-- ── 1 + 3. team_transition: manual pauses only; ending closes the open pause ─
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

  -- 0104: only a human pause. Any automatic reason (coverage, owner_left, ...) is refused.
  if p_to = 'paused' and coalesce(p_reason, '') <> 'manual' then
    return jsonb_build_object('ok', true, 'noop', true, 'refused', 'automatic_pause_disabled', 'status', s.status);
  end if;

  if p_to = 'running' and s.status = 'lobby' then
    select count(*) into v_notready from public.team_session_members
      where session_id = p_session and role not in ('instructor','observer')
        and status not in ('ready','active','left');
    if v_notready > 0 then
      return jsonb_build_object('ok', false, 'error', 'not_ready', 'count', v_notready);
    end if;
    update public.team_sessions
       set status = 'running', started_at = v_now, paused_at = null, paused_ms = 0,
           pause_reason = null, lifecycle_state = '{}'::jsonb,
           end_at = null, end_scheduled_by = null, reap_warned_at = null, presence_notice = null
     where id = p_session;
    v_type := 'session.started';
  elsif p_to = 'paused' and s.status = 'running' then
    update public.team_sessions set status = 'paused', paused_at = v_now, pause_reason = 'manual',
           lifecycle_state = '{}'::jsonb where id = p_session;
    v_type := 'session.paused';
  elsif p_to = 'paused' and s.status = 'paused' and coalesce(s.pause_reason, '') <> 'manual' then
    -- a leftover automatic pause upgraded to manual (the tick then never resumes it)
    update public.team_sessions set pause_reason = 'manual', lifecycle_state = '{}'::jsonb where id = p_session;
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
    update public.team_sessions
       set status = 'ended', ended_at = v_now, paused_at = null,
           -- 0104: an end during a pause closes that pause into the stored total
           paused_ms = coalesce(s.paused_ms, 0)
                       + case when s.status = 'paused' and s.paused_at is not null
                              then greatest(0, floor(extract(epoch from (v_now - s.paused_at)) * 1000))::bigint else 0 end
     where id = p_session;
    update public.session_injects set status = 'skipped', skip_reason = coalesce(skip_reason, 'shift_ended')
     where session_id = p_session and status = 'pending';
    v_type := 'session.ended';
  else
    return jsonb_build_object('ok', true, 'noop', true, 'status', s.status);
  end if;

  v_ev := public.team_insert_event(p_session, null, null, v_type,
            jsonb_strip_nulls(jsonb_build_object('at', v_now, 'reason', p_reason, 'detail', p_detail, 'by', p_by)));
  return jsonb_build_object('ok', true, 'seq', v_ev.seq, 'type', v_type);
end $$;

-- ── 3. scheduled end ─────────────────────────────────────────────────────────
create or replace function public.team_schedule_end(p_session uuid, p_by uuid default null, p_delay_ms integer default 120000)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  s     public.team_sessions;
  v_now timestamptz := clock_timestamp();
  v_end timestamptz;
begin
  perform public.team_lock_session(p_session);
  select * into s from public.team_sessions where id = p_session for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if s.status not in ('running','paused') then
    return jsonb_build_object('ok', true, 'noop', true, 'status', s.status);
  end if;
  if s.end_at is not null and s.end_at > v_now then
    return jsonb_build_object('ok', true, 'noop', true, 'ends_at', s.end_at);
  end if;
  v_end := v_now + make_interval(secs => greatest(0, least(coalesce(p_delay_ms, 120000), 600000)) / 1000.0);
  update public.team_sessions set end_at = v_end, end_scheduled_by = p_by where id = p_session;
  perform public.team_insert_event(p_session, null, null, 'session.end_scheduled',
    jsonb_strip_nulls(jsonb_build_object('ends_at', v_end, 'by', p_by, 'delay_ms', greatest(0, least(coalesce(p_delay_ms, 120000), 600000)))));
  return jsonb_build_object('ok', true, 'ends_at', v_end);
end $$;

create or replace function public.team_cancel_end(p_session uuid, p_by uuid default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare s public.team_sessions;
begin
  perform public.team_lock_session(p_session);
  select * into s from public.team_sessions where id = p_session for update;
  if not found then return jsonb_build_object('ok', false, 'error', 'not_found'); end if;
  if s.status not in ('running','paused') or s.end_at is null then
    return jsonb_build_object('ok', true, 'noop', true, 'status', s.status);
  end if;
  update public.team_sessions set end_at = null, end_scheduled_by = null where id = p_session;
  perform public.team_insert_event(p_session, null, null, 'session.end_cancelled', jsonb_strip_nulls(jsonb_build_object('by', p_by)));
  return jsonb_build_object('ok', true);
end $$;

-- ── 1 + 3. lifecycle tick: presence notices (no pause) + scheduled ends ──────
create or replace function public.team_lifecycle_tick()
  returns int language plpgsql security definer set search_path = public as $$
declare
  s          public.team_sessions;
  r          record;
  v_now      timestamptz := clock_timestamp();
  v_grace    timestamptz;
  v_missing  text[];
  v_everyone boolean;
  v_owner    timestamptz;
  v_want     text;
  v_detail   text;
  v_state    jsonb;
  v_stale    integer;
  v_first    timestamptz;
  v_changes  int := 0;
begin
  -- Scheduled ends (every schema version): the server keeps the end time.
  for r in
    select ts.id from public.team_sessions ts
     where ts.end_at is not null and ts.end_at <= v_now and ts.status in ('running','paused')
     limit 100
  loop
    begin
      perform public.team_transition(r.id, 'ended', 'scheduled', null, null);
      v_changes := v_changes + 1;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('lifecycle_error', r.id, sqlerrm);
    end;
  end loop;

  for s in
    select * from public.team_sessions
     where status in ('running','paused') and schema_version >= 2
     order by random() limit 200
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;
      select * into s from public.team_sessions where id = s.id;
      if s.status not in ('running','paused') then continue; end if;
      v_state := coalesce(s.lifecycle_state, '{}'::jsonb);

      -- An automatic pause left over from before 0104 is lifted: only humans pause now.
      if s.status = 'paused' and coalesce(s.pause_reason, 'manual') <> 'manual' then
        perform public.team_transition(s.id, 'running', 'auto_resume', null, null);
        v_changes := v_changes + 1;
        continue;
      end if;

      select greatest(s.started_at, coalesce(max(e.occurred_at), s.started_at)) into v_grace
        from public.session_events e where e.session_id = s.id and e.type = 'session.resumed';
      if v_now < v_grace + interval '60 seconds' then continue; end if;

      select coalesce(array_agg(r2.role order by r2.role), '{}') into v_missing
        from (select distinct m.role from public.team_session_members m
               where m.session_id = s.id and m.status <> 'left' and m.role in ('t1','t2')) r2
       where not exists (select 1 from public.team_session_members m2
                          where m2.session_id = s.id and m2.status <> 'left'
                            and (m2.role = r2.role or (r2.role = 't2' and m2.role = 't3'))
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
        v_detail := 'The instructor is not in the live room. The shift keeps running.';
      elsif v_everyone then
        v_want := 'everyone_left'; v_detail := 'No player is online right now.';
      elsif array_length(v_missing, 1) > 0 then
        v_want := 'coverage';
        v_detail := 'No ' || array_to_string(array(select case x when 't1' then 'Tier-1' else 'Tier-2' end
                                                   from unnest(v_missing) x), ' and no ') || ' online right now.';
      end if;

      if v_want is not null and v_want is distinct from s.presence_notice then
        v_stale := coalesce((v_state->>'stale')::int, 0) + 1;
        if v_stale >= 2 then                                              -- two stale ticks in a row
          if s.presence_notice is not null then
            perform public.append_system_event(s.id, 'presence.notice',
              jsonb_build_object('kind', s.presence_notice, 'state', 'cleared'));
          end if;
          perform public.append_system_event(s.id, 'presence.notice',
            jsonb_strip_nulls(jsonb_build_object('kind', v_want, 'state', 'raised', 'detail', v_detail,
              'missing', case when v_want = 'coverage' then to_jsonb(v_missing) else null end)));
          update public.team_sessions set presence_notice = v_want, lifecycle_state = v_state - 'stale' where id = s.id;
          v_changes := v_changes + 1;
        else
          update public.team_sessions set lifecycle_state = v_state || jsonb_build_object('stale', v_stale) where id = s.id;
        end if;
      elsif v_want is null then
        if s.presence_notice is not null then
          perform public.append_system_event(s.id, 'presence.notice',
            jsonb_build_object('kind', s.presence_notice, 'state', 'cleared'));
          update public.team_sessions set presence_notice = null where id = s.id;
          v_changes := v_changes + 1;
        end if;
        if v_state ? 'stale' then
          update public.team_sessions set lifecycle_state = v_state - 'stale' where id = s.id;
        end if;
      end if;

      -- spoiler-free "nobody escalated yet" hint, once, randomized 3 to 6 min after the first attack log
      if s.status = 'running' and s.nudged_at is null then
        if exists (select 1 from public.session_events e where e.session_id = s.id and e.type = 'escalation.requested') then
          update public.team_sessions set nudged_at = v_now where id = s.id;
        else
          select min(e.occurred_at) into v_first
            from public.session_injects i
            join public.session_events e on e.session_id = i.session_id and e.seq = i.fired_seq
           where i.session_id = s.id and i.status = 'fired' and i.channel = 'feed'
             and i.expected_action->>'expected_verdict' in ('tp','escalate');
          if v_first is not null
             and v_now > v_first + make_interval(secs => 180 + (abs(hashtext(s.id::text)) % 181)) then
            perform public.append_system_event(s.id, 'hint.nudge',
              jsonb_build_object('text', 'Real attack activity may be streaming in the feed. Nobody has escalated anything yet. Re-check the high-severity logs.'));
            update public.team_sessions set nudged_at = v_now where id = s.id;
          end if;
        end if;
      end if;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('lifecycle_error', s.id, sqlerrm);
    end;
  end loop;
  return v_changes;
end $$;

-- ── 2. reaper: 4 hours of ACTIVE time, warned first ──────────────────────────
create or replace function public.team_active_ms_now(s public.team_sessions)
returns bigint language sql stable set search_path = public as $$
  select case when s.started_at is null then 0
    else greatest(0, floor(extract(epoch from (coalesce(s.paused_at, now()) - s.started_at)) * 1000)::bigint - coalesce(s.paused_ms, 0)) end
$$;

create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare
  r       record;
  w       public.team_sessions;
  v_res   jsonb;
  v_count int := 0;
  c_cap   constant bigint := 4 * 3600 * 1000;        -- 4 h of running time
  c_warn  constant bigint := c_cap - 10 * 60 * 1000;  -- warn 10 min of running time before
begin
  -- Warnings first: a session close to a cap gets one notice for the room and staff.
  for w in
    select ts.* from public.team_sessions ts
     where ts.status in ('running','paused') and ts.reap_warned_at is null
       and (public.team_active_ms_now(ts) >= c_warn
            or (ts.status = 'paused' and ts.pause_reason = 'manual'
                and coalesce(ts.paused_at, ts.started_at) < now() - interval '2 hours 50 minutes'))
     limit 50
  loop
    begin
      perform public.append_system_event(w.id, 'session.reap_warning', jsonb_build_object(
        'reason', case when public.team_active_ms_now(w) >= c_warn then 'active_cap' else 'long_pause' end,
        'active_ms', public.team_active_ms_now(w),
        'ends_in_ms', case when public.team_active_ms_now(w) >= c_warn
                           then greatest(0, c_cap - public.team_active_ms_now(w))
                           else greatest(0, floor(extract(epoch from (coalesce(w.paused_at, w.started_at) + interval '3 hours' - now())) * 1000)::bigint) end));
      update public.team_sessions set reap_warned_at = now() where id = w.id;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('reap_error', w.id, sqlerrm);
    end;
  end loop;

  for r in
    select ts.id from public.team_sessions ts
     where (ts.status = 'lobby' and ts.created_at < now() - interval '24 hours')       -- abandoned lobby (E-20)
        or (ts.status in ('running','paused')
       and (
         -- capped on ACTIVE time, and only after the warning had at least 4 minutes
         (public.team_active_ms_now(ts) >= c_cap and ts.reap_warned_at < now() - interval '4 minutes')
         or (ts.status = 'paused' and ts.pause_reason = 'manual'
             and coalesce(ts.paused_at, ts.started_at) < now() - interval '3 hours'
             and ts.reap_warned_at < now() - interval '4 minutes')                      -- long manual pause
         or ts.started_at < now() - interval '24 hours'                                -- wall-clock backstop
         or ((ts.status = 'running' or coalesce(ts.pause_reason, '') <> 'manual')
             and coalesce((select max(e.occurred_at) from public.session_events e
                            where e.session_id = ts.id and e.actor_id is not null), ts.started_at)
                 < now() - interval '30 minutes'                                      -- no human action
             and coalesce((select max(m.last_seen_at) from public.team_session_members m
                            where m.session_id = ts.id), '-infinity'::timestamptz)
                 < now() - interval '10 minutes')                                     -- nobody's heartbeat
       ))
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

-- ── 4. isolation approval ────────────────────────────────────────────────────
-- Same rule as isolationApprovers() in src/lib/team/isolationApproval.ts.
create or replace function public.team_isolation_can_approve(p_session uuid, p_user uuid, p_requester uuid)
returns boolean language plpgsql stable security definer set search_path = public as $$
declare
  v_role text;
  v_now  timestamptz := clock_timestamp();
begin
  if p_user is null or p_user = p_requester then return false; end if;
  select role into v_role from public.team_session_members
   where session_id = p_session and user_id = p_user and status <> 'left';
  if v_role is null then return false; end if;
  if v_role = 'instructor' then return true; end if;                -- staff override, always
  -- 1. a seated, active SOC Manager / Lead (the acting user counts as active)
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role in ('mgr','lead')
                and m.user_id is distinct from p_requester
                and (m.user_id = p_user or m.last_seen_at > v_now - interval '120 seconds')) then
    return v_role in ('mgr','lead');
  end if;
  -- 2. else a seated, active Tier-3 who is not the requester
  if exists (select 1 from public.team_session_members m
              where m.session_id = p_session and m.status <> 'left' and m.role = 't3'
                and m.user_id is distinct from p_requester
                and (m.user_id = p_user or m.last_seen_at > v_now - interval '120 seconds')) then
    return v_role = 't3';
  end if;
  -- 3. else staff only (handled above)
  return false;
end $$;

-- The host's own (private) address, from the rows written about it: the most frequent RFC 1918 src_ip.
create or replace function public.team_host_ips(p_session uuid, p_host text)
returns text[] language sql stable set search_path = public as $$
  select coalesce(array_agg(ip), '{}') from (
    select body->>'src_ip' as ip, count(*) as n from public.session_injects
     where session_id = p_session and channel = 'feed' and lower(body->>'hostname') = lower(p_host)
       and (body->>'src_ip') ~ '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
     group by 1 order by n desc, 1 limit 1) t
$$;

-- Hosts isolated right now, lower-cased, with their addresses.
create or replace function public.team_isolated_hosts(p_session uuid)
returns table(host text, ips text[]) language sql stable set search_path = public as $$
  select lower(x.host), coalesce(array(select jsonb_array_elements_text(coalesce(x.payload->'ips', '[]'::jsonb))), '{}')
    from (select distinct on (lower(e.payload->>'host')) e.payload->>'host' as host, e.type, e.payload
            from public.session_events e
           where e.session_id = p_session and e.type in ('edr.host_isolated','edr.host_released')
             and coalesce(e.payload->>'host', '') <> ''
           order by lower(e.payload->>'host'), e.seq desc) x
   where x.type = 'edr.host_isolated'
$$;

-- The isolated host a feed body is about (hostname, or src / dst address), or null.
create or replace function public.team_isolation_hit(p_body jsonb, p_hosts text[], p_ips text[])
returns text language sql immutable set search_path = public as $$
  select case
    when coalesce(array_length(p_hosts, 1), 0) = 0 then null
    when lower(coalesce(p_body->>'hostname', '')) = any(p_hosts) then lower(p_body->>'hostname')
    when coalesce(p_body->>'src_ip', '') <> '' and (p_body->>'src_ip') = any(p_ips) then p_body->>'src_ip'
    when coalesce(p_body->>'dst_ip', '') <> '' and (p_body->>'dst_ip') = any(p_ips) then p_body->>'dst_ip'
    else null end
$$;

-- An EDR status row for a host's containment (no answer key, no inject: system telemetry).
create or replace function public.team_containment_row(p_session uuid, p_host text, p_on boolean, p_seq bigint)
returns void language plpgsql security definer set search_path = public as $$
declare v_vendor text;
begin
  select coalesce(e.payload->>'vendor', 'EDR') into v_vendor from public.session_events e
   where e.session_id = p_session and e.type = 'feed.event' and e.payload->>'source' = 'edr'
   order by e.seq desc limit 1;
  perform public.team_insert_event(p_session, null, null, 'feed.event', jsonb_build_object(
    'id', 'iso-' || p_seq::text,
    'kind', 'containment_status',
    'ts', to_char(clock_timestamp() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'hostname', p_host, 'host', p_host,
    'source', 'edr', 'vendor', coalesce(v_vendor, 'EDR'),
    'event_type', 'network_containment', 'severity', 'informational',
    'containment', case when p_on then 'contained' else 'released' end,
    'description', case when p_on
      then 'Network containment active on ' || p_host || '. The host can reach only the EDR cloud.'
      else 'Network containment lifted on ' || p_host || '. The host is back on the network.' end));
end $$;

-- BEFORE INSERT: shape and approver checks for the isolation actions (player writes only).
create or replace function public.team_isolation_validate() returns trigger
  language plpgsql security definer set search_path = public as $$
declare
  v_host  text;
  v_txt   text;
  v_req   public.session_events;
  v_state text;
begin
  if NEW.actor_id is null then return NEW; end if;                 -- system writes pass
  if NEW.type = 'isolation.requested' then
    v_host := btrim(coalesce(NEW.payload->>'host', ''));
    if v_host = '' or length(v_host) > 128 or v_host !~ '^[A-Za-z0-9][A-Za-z0-9._-]*$' then
      raise exception 'invalid_payload: a valid host name is required';
    end if;
    v_txt := btrim(coalesce(NEW.payload->>'reason', ''));
    if v_txt = '' then raise exception 'invalid_payload: say why the host should be isolated'; end if;
    if length(v_txt) > 500 then raise exception 'invalid_payload: the reason is too long'; end if;
    if length(coalesce(NEW.payload->>'incident', '')) > 200 or length(coalesce(NEW.payload->>'case', '')) > 200 then
      raise exception 'invalid_payload: the incident reference is too long';
    end if;
    select type into v_state from public.session_events
     where session_id = NEW.session_id and type in ('edr.host_isolated','edr.host_released')
       and lower(payload->>'host') = lower(v_host)
     order by seq desc limit 1;
    if v_state = 'edr.host_isolated' then raise exception 'already_isolated: %', v_host; end if;
    if exists (select 1 from public.session_events q
                where q.session_id = NEW.session_id and q.type = 'isolation.requested'
                  and lower(q.payload->>'host') = lower(v_host)
                  and not exists (select 1 from public.session_events a
                                   where a.session_id = q.session_id and a.type in ('isolation.approved','isolation.denied')
                                     and a.payload->>'request_seq' = q.seq::text)) then
      raise exception 'isolation_pending: %', v_host;
    end if;
    NEW.payload := NEW.payload || jsonb_build_object('host', v_host, 'reason', v_txt);
  elsif NEW.type in ('isolation.approved','isolation.denied') then
    if coalesce(NEW.payload->>'request_seq', '') !~ '^[0-9]{1,12}$' then
      raise exception 'invalid_payload: request_seq is required';
    end if;
    select * into v_req from public.session_events
     where session_id = NEW.session_id and type = 'isolation.requested' and seq = (NEW.payload->>'request_seq')::bigint;
    if not found or exists (select 1 from public.session_events a
                             where a.session_id = NEW.session_id and a.type in ('isolation.approved','isolation.denied')
                               and a.payload->>'request_seq' = v_req.seq::text) then
      raise exception 'no_open_request: %', NEW.payload->>'request_seq';
    end if;
    if not public.team_isolation_can_approve(NEW.session_id, NEW.actor_id, v_req.actor_id) then
      raise exception 'not_approver';
    end if;
    if length(coalesce(NEW.payload->>'reason', '')) > 500 then raise exception 'invalid_payload: the reason is too long'; end if;
    NEW.payload := NEW.payload || jsonb_build_object('host', v_req.payload->>'host', 'requested_by', v_req.actor_id);
  end if;
  return NEW;
end $$;

-- AFTER INSERT: an approval isolates the host; any isolate / release posts the EDR status row.
create or replace function public.team_isolation_apply() returns trigger
  language plpgsql security definer set search_path = public as $$
declare
  v_req   public.session_events;
  v_iso   public.session_events;
  v_host  text;
begin
  if NEW.type = 'isolation.approved' then
    select * into v_req from public.session_events
     where session_id = NEW.session_id and type = 'isolation.requested' and seq = (NEW.payload->>'request_seq')::bigint;
    if not found then return NEW; end if;
    v_host := v_req.payload->>'host';
    v_iso := public.team_insert_event(NEW.session_id, v_req.actor_id, v_req.role, 'edr.host_isolated',
      jsonb_strip_nulls(jsonb_build_object(
        'host', v_host, 'request_seq', v_req.seq, 'approved_seq', NEW.seq,
        'approved_by', NEW.actor_id, 'approver_role', NEW.role,
        'reason', v_req.payload->>'reason', 'incident', v_req.payload->>'incident', 'case', v_req.payload->>'case',
        'ips', to_jsonb(public.team_host_ips(NEW.session_id, v_host)))));
    perform public.team_containment_row(NEW.session_id, v_host, true, v_iso.seq);
  elsif NEW.type = 'edr.host_released' and NEW.actor_id is not null then
    perform public.team_containment_row(NEW.session_id, NEW.payload->>'host', false, NEW.seq);
  end if;
  return NEW;
end $$;

drop trigger if exists session_events_isolation_validate on public.session_events;
create trigger session_events_isolation_validate before insert on public.session_events
  for each row when (NEW.type in ('isolation.requested','isolation.approved','isolation.denied'))
  execute function public.team_isolation_validate();
drop trigger if exists session_events_isolation_apply on public.session_events;
create trigger session_events_isolation_apply after insert on public.session_events
  for each row when (NEW.type in ('isolation.approved','edr.host_released'))
  execute function public.team_isolation_apply();

-- ── 5. promote: an isolated host leaves the exercise ─────────────────────────
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
  v_hosts text[];
  v_ips   text[];
  v_hit   text;
  v_count int := 0;
begin
  for s in
    select ts.id from public.team_sessions ts
     where ts.status = 'running'
       and exists (select 1 from public.session_injects i
                    where i.session_id = ts.id and i.status = 'pending'
                      and i.due_offset_ms <= floor(extract(epoch from (clock_timestamp() - ts.started_at)) * 1000)::bigint
                                             - coalesce(ts.paused_ms, 0))
     order by random()
     limit 100
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;
      select started_at, coalesce(paused_ms, 0) into v_start, v_pms
        from public.team_sessions where id = s.id and status = 'running';
      if not found then continue; end if;
      v_off := floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms;
      select coalesce(array_agg(h.host), '{}'), coalesce(array_agg(ip) filter (where ip is not null), '{}')
        into v_hosts, v_ips
        from public.team_isolated_hosts(s.id) h left join lateral unnest(h.ips) ip on true;
      for r in
        select i.* from public.session_injects i
         where i.session_id = s.id and i.status = 'pending' and i.due_offset_ms <= v_off
         order by i.due_offset_ms
         limit 200
         for update of i skip locked
      loop
        if r.channel is distinct from 'inject' then
          v_hit := public.team_isolation_hit(r.body, v_hosts, v_ips);
          if v_hit is not null then
            update public.session_injects set status = 'skipped', skip_reason = 'isolated:' || v_hit
             where id = r.id and status = 'pending';
            continue;
          end if;
        end if;
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

-- ── 4. the action gate (0103 verbatim, with the 0104 lines) ─────────────────
create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','session.paused','session.resumed','grade.assigned',
                    'hint.nudge','member.added','member.role_changed','member.removed','decision.expired','stakeholder.asked',
                    'presence.notice','session.end_scheduled','session.end_cancelled','session.reap_warning',
                    'edr.host_isolated') then false
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
    -- 0104: isolation is a request the shift senior approves (fine-grained check: team_isolation_validate);
    -- the server records edr.host_isolated itself. Release stays direct.
    when p_type = 'isolation.requested'      then p_role in ('t2','t3')    and p_status = 'running'
    when p_type in ('isolation.approved','isolation.denied') then p_role in ('mgr','lead','t3','instructor') and p_status = 'running'
    when p_type = 'edr.host_released'        then p_role in ('t2','t3','mgr','lead','instructor') and p_status = 'running'
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
    -- 0095: Tier-3 forensics (evidence collection, findings) and RTR actions from the EDR console
    when p_type in ('forensic.collected','forensic.finding','forensic.report') then p_role = 't3' and p_status = 'running'
    when p_type = 'rtr.action'               then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'coordination.nudge'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    when p_type = 'staff.inject'             then p_role = 'instructor'    and p_status = 'running'
    when p_type = 'ticket.answered'          then p_role = 't1'            and p_status = 'running'
    -- 0098: a written response to an inject in the role's Action-required box (a decoy, a twist,
    -- a management request when the team has no SOC Manager)
    when p_type = 'inject.responded'         then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type in ('sentinel.incident_updated','sentinel.comment_added','sentinel.bookmark_added','sentinel.task_set','sentinel.query_run')
      then p_role in ('t1','t2','t3','de','ti') and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then p_status in ('running','paused')
    else false
  end
$$;


-- ── 5. replenish (0084 verbatim, plus the isolation filter) ──────────────────
create or replace function public.replenish_feed()
 returns integer
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  s       record;
  r       record;
  v_start timestamptz;
  v_pms   bigint;
  v_off   bigint;
  v_gap   integer;
  v_jit   integer;
  v_hosts text[];
  v_ips   text[];
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
      select started_at, coalesce(paused_ms, 0), coalesce(feed_gap_ms, 12000), coalesce(feed_jitter_ms, 3500)
        into v_start, v_pms, v_gap, v_jit
        from public.team_sessions where id = s.id and status = 'running';
      if not found then continue; end if;
      if (select count(*) from public.session_injects
           where session_id = s.id and status = 'pending' and channel = 'feed') >= 4 then
        continue;
      end if;
      -- Resume from "now" on the pause-aware session clock (was ignoring paused_ms) —
      -- 0081: or after the last log still pending, whichever is later, so the refill
      -- never lands on top of logs that haven't arrived yet.
      v_off := greatest(
        0,
        floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms,
        coalesce((select max(due_offset_ms) from public.session_injects
                   where session_id = s.id and status = 'pending' and channel = 'feed'), 0));
      -- 0104: an isolated host has left the exercise: none of its rows are recycled.
      select coalesce(array_agg(h.host), '{}'), coalesce(array_agg(ip) filter (where ip is not null), '{}')
        into v_hosts, v_ips
        from public.team_isolated_hosts(s.id) h left join lateral unnest(h.ips) ip on true;
      for r in
        -- 0084: one row per distinct log (its body minus the per-copy id), the ones
        -- shown the FEWEST times first — random() alone kept drawing the same few
        -- logs from a small pool ("opened TradeFlow" ×7 in one shift).
        select c.body, c.expected_action from (
          select distinct on (k) i.body, i.expected_action, k from (
            select body, expected_action, md5((body - 'id')::text) as k from public.session_injects
             where session_id = s.id and status = 'fired' and channel = 'feed'   -- never recycle MSEL injects
               and coalesce(expected_action->>'expected_verdict', body->>'expected_verdict', '') not in ('tp','escalate')
               -- 0084: nor an FP decoy — the same 9.3 GB "approved backup" three times is
               -- noise that reads like a new incident, and each copy is graded again.
               and coalesce(expected_action->>'expected_verdict', body->>'expected_verdict', '') <> 'fp'
               and coalesce(expected_action->>'fp_explanation', body->>'fp_explanation', '') = ''
               -- 0073: pure noise only (story control steps / ITSM / inject support are benign too now)
               and not (coalesce(expected_action, '{}'::jsonb) ?| array['incident_id', 'supports_inject'])
               and coalesce(expected_action->>'origin', 'noise') = 'noise'
               and coalesce(expected_action->>'is_baseline', '') <> 'true'
               and public.team_isolation_hit(body, v_hosts, v_ips) is null
          ) i
          order by k
        ) c
        order by (select count(*) from public.session_injects j
                   where j.session_id = s.id and j.channel = 'feed' and md5((j.body - 'id')::text) = c.k) asc,
                 random()
        limit 6
      loop
        -- 0081: the session's own pace (set at /start from the team), not 3–7 s.
        v_off := v_off + v_gap + floor(random() * v_jit)::bigint;
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
end $function$;


revoke all on function public.replenish_feed() from public, anon, authenticated;
grant execute on function public.replenish_feed() to service_role;

-- ── grants: server-side only ─────────────────────────────────────────────────
revoke all on function public.team_transition(uuid, text, text, uuid, text)        from public, anon, authenticated;
revoke all on function public.team_schedule_end(uuid, uuid, integer)               from public, anon, authenticated;
revoke all on function public.team_cancel_end(uuid, uuid)                          from public, anon, authenticated;
revoke all on function public.team_lifecycle_tick()                                from public, anon, authenticated;
revoke all on function public.reap_stale_team_sessions()                           from public, anon, authenticated;
revoke all on function public.promote_due_injects()                                from public, anon, authenticated;
revoke all on function public.team_isolation_can_approve(uuid, uuid, uuid)         from public, anon, authenticated;
revoke all on function public.team_containment_row(uuid, text, boolean, bigint)    from public, anon, authenticated;
revoke all on function public.team_isolation_validate()                            from public, anon, authenticated;
revoke all on function public.team_isolation_apply()                               from public, anon, authenticated;
revoke all on function public.team_host_ips(uuid, text)                            from public, anon, authenticated;
revoke all on function public.team_isolated_hosts(uuid)                            from public, anon, authenticated;
revoke all on function public.team_active_ms_now(public.team_sessions)             from public, anon, authenticated;
grant execute on function public.team_transition(uuid, text, text, uuid, text)     to service_role;
grant execute on function public.team_schedule_end(uuid, uuid, integer)            to service_role;
grant execute on function public.team_cancel_end(uuid, uuid)                       to service_role;
grant execute on function public.team_lifecycle_tick()                             to service_role;
grant execute on function public.reap_stale_team_sessions()                        to service_role;
grant execute on function public.promote_due_injects()                             to service_role;
grant execute on function public.team_isolation_can_approve(uuid, uuid, uuid)      to service_role;
grant execute on function public.team_isolated_hosts(uuid)                         to service_role;
grant execute on function public.team_host_ips(uuid, text)                         to service_role;
