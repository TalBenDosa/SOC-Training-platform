-- HACK THE SOC :: 0072 — Team-SOC Phase 2 review fixes (2026-09-26)
-- ===========================================================================
-- Fixes confirmed by the independent review of 0071:
--  • Fairness: promote / replenish / lifecycle tick visited only the 50 OLDEST
--    live sessions (replenish keeps every session "pending" forever), so session
--    #51+ froze. Now: filter to sessions that actually need work, random order.
--  • replenish_feed no longer stamps a fresh "now" ts on recycled logs (their raw
--    timestamps stayed behind — a tell); ts stays on the synthetic base.
--  • team_transition start: a removed (status=left) member no longer blocks Start.
--  • team_seed_timeline(): seeding under the session lock — two concurrent
--    /start calls can no longer seed the timeline twice.
-- CREATE OR REPLACE keeps each function's existing grants (0071 revokes).
-- ===========================================================================

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
        and status not in ('ready','active','left');           -- a removed no-show never wedges Start
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
       and exists (select 1 from public.session_injects i
                    where i.session_id = ts.id and i.status = 'pending'
                      and i.due_offset_ms <= floor(extract(epoch from (clock_timestamp() - ts.started_at)) * 1000)::bigint
                                             - coalesce(ts.paused_ms, 0))           -- only sessions with something DUE
     order by random()                                                                -- fair: no session starves
     limit 100
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

-- ── Seed under the session lock (idempotent) ────────────────────────────────
create or replace function public.team_seed_timeline(p_session uuid, p_rows jsonb)
  returns int language plpgsql security definer set search_path = public as $$
declare v_n int;
begin
  perform public.team_lock_session(p_session);
  if not exists (select 1 from public.team_sessions where id = p_session and status = 'lobby') then
    return -1;                                               -- already started / gone
  end if;
  if exists (select 1 from public.session_injects where session_id = p_session) then
    return 0;                                                -- seeded by a concurrent /start
  end if;
  insert into public.session_injects(session_id, due_offset_ms, trigger, channel, body, expected_action, status)
  select p_session, r.due_offset_ms, jsonb_build_object('kind', 'at_time'), r.channel, r.body, r.expected_action, 'pending'
    from jsonb_to_recordset(p_rows) as r(due_offset_ms bigint, channel text, body jsonb, expected_action jsonb);
  get diagnostics v_n = row_count;
  return v_n;
end $$;
revoke execute on function public.team_seed_timeline(uuid, jsonb) from public, anon, authenticated;
grant  execute on function public.team_seed_timeline(uuid, jsonb) to service_role;
