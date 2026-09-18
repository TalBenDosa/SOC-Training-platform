-- HACK THE SOC :: 0064 — pause-aware inject pacing
-- ===========================================================================
-- A session can now be paused (0.x lifecycle). Promotion already skips a
-- non-running session (s.status = 'running'), so nothing fires while paused.
-- But injects are due at `started_at + due_offset_ms` — a fixed wall-clock
-- schedule — so every inject whose offset elapsed DURING a pause would burst
-- out the instant the session resumes, collapsing the pacing.
--
-- Fix: track how long a session has spent paused and shift the whole timeline
-- forward by that amount. due time becomes:
--     started_at + (paused_ms + due_offset_ms)
-- so a 10-minute pause pushes every remaining inject 10 minutes later, keeping
-- the gaps between them intact.
--
--   paused_at : when the CURRENT pause began (null while running)
--   paused_ms : total completed paused time, in milliseconds
-- The /pause route sets paused_at on pause and folds the elapsed time into
-- paused_ms on resume. Idempotent.
-- ===========================================================================

alter table public.team_sessions
  add column if not exists paused_at timestamptz,
  add column if not exists paused_ms bigint not null default 0;

create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0; v_type text;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval <= now()
    order by i.session_id, i.due_offset_ms
  loop
    v_type := case when r.channel = 'inject' then 'staff.inject' else 'feed.event' end;
    select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.session_id;
    insert into public.session_events(session_id, seq, actor_id, role, type, payload)
      values (r.session_id, v_next, null, null, v_type, r.body || jsonb_build_object('inject_id', r.id));
    update public.session_injects set status = 'fired', fired_seq = v_next where id = r.id;
    update public.session_state set seq = v_next, updated_at = now() where session_id = r.session_id;
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;
grant execute on function public.promote_due_injects() to authenticated;

-- Verification:
--   1) seed an inject with a small due_offset, start a session, pause it for a
--      minute, resume, and confirm the inject fires ~a minute later than it
--      would have (not immediately in a burst).
--   2) select paused_ms, paused_at from team_sessions where id = '<id>';
