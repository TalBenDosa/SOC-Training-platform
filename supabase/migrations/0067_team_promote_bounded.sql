-- HACK THE SOC :: 0067 — bound the promote tick (scale)
-- ===========================================================================
-- promote_due_injects() runs every 5s and, in one transaction, promotes EVERY
-- due inject across ALL running sessions. pg_cron starts the next tick on
-- schedule even if the previous run is still going, so if one tick's work ever
-- exceeds 5s (thousands of concurrent sessions, or many sessions started in
-- lockstep firing their bursts together) ticks overlap and compound, and two
-- concurrent promotes on the same session collide on unique(session_id, seq).
--
-- Bound each tick: take at most N most-overdue injects, oldest due-time first
-- (fair), and let the rest fall to the next tick 5s later — a due inject is at
-- most a few seconds late under extreme load instead of stampeding. N=500 at a
-- 5s cadence = up to 100 promotes/s, far above any realistic aggregate need.
-- Everything else (pause pacing 0064, per-inject seq retry 0065) is unchanged.
-- Idempotent.
-- ===========================================================================

create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0; v_type text; v_ok boolean;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval <= now()
    order by s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval asc
    limit 500
  loop
    v_type := case when r.channel = 'inject' then 'staff.inject' else 'feed.event' end;
    v_ok := false;
    for attempt in 1..8 loop
      select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.session_id;
      begin
        insert into public.session_events(session_id, seq, actor_id, role, type, payload)
          values (r.session_id, v_next, null, null, v_type, r.body || jsonb_build_object('inject_id', r.id));
        v_ok := true;
        exit;
      exception when unique_violation then
        if attempt = 8 then raise; end if;
      end;
    end loop;
    if v_ok then
      update public.session_injects set status = 'fired', fired_seq = v_next where id = r.id;
      update public.session_state set seq = v_next, updated_at = now() where session_id = r.session_id;
      v_count := v_count + 1;
    end if;
  end loop;
  return v_count;
end $$;
grant execute on function public.promote_due_injects() to authenticated;

-- Verification:
--   explain analyze select public.promote_due_injects();  -- bounded work per call
