-- HACK THE SOC :: 0066 — Team-SOC scale/index tuning
-- ===========================================================================
-- Keeps the feature cheap as concurrent sessions/users grow (infra review
-- 2026-09-18):
--
--  1. promote_due_injects() runs every 5s and filters session_injects by
--     status='pending'. The existing index session_injects_due_idx is
--     (session_id, status, due_offset_ms) — session_id-leading, so a cross-session
--     "all pending" scan can't use it well. A PARTIAL index on the pending rows
--     only, ordered by (session_id, due_offset_ms), matches the promote query and
--     stays tiny (fired/skipped rows are excluded).
--
--  2. session_events is the highest-write table. `unique (session_id, seq)` already
--     creates a backing index on exactly (session_id, seq); the separately-declared
--     session_events_session_seq_idx is redundant and just doubles index-maintenance
--     on every insert. Drop it (all lookups keep using the unique index).
--
--  3. The reaper and the promote join both care about status in ('running','paused').
--     A small partial index on those active rows avoids scanning the whole (growing)
--     team_sessions history.
--
--  4. reap_stale_team_sessions() computed max(occurred_at) per candidate session —
--     a per-session scan. seq is monotonic with time, so the newest event is the
--     max-seq row, which the unique(session_id,seq) index serves via ORDER BY seq
--     DESC LIMIT 1. Recreate the reaper to use that (index-backed, no occurred_at
--     index needed).
-- Idempotent.
-- ===========================================================================

-- 1. Pending-inject partial index (promote_due_injects hot path).
create index if not exists session_injects_pending_idx
  on public.session_injects (session_id, due_offset_ms)
  where status = 'pending';

-- 2. Drop the redundant (session_id, seq) index — the unique constraint covers it.
drop index if exists public.session_events_session_seq_idx;

-- 3. Active-session partial index (reaper + promote join filter).
create index if not exists team_sessions_active_idx
  on public.team_sessions (status)
  where status in ('running','paused');

-- 4. Reaper: index-backed latest-event lookup instead of max(occurred_at) scan.
create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_count int := 0; v_next bigint;
begin
  for r in
    select ts.id from public.team_sessions ts
    where ts.status in ('running','paused')
      and (
        ts.started_at < now() - interval '4 hours'  -- absolute safety cap
        or (
          coalesce((select e.occurred_at from public.session_events e
                     where e.session_id = ts.id order by e.seq desc limit 1), ts.started_at)
            < now() - interval '90 minutes'
          and not exists (select 1 from public.session_injects i where i.session_id = ts.id and i.status = 'pending')
        )
      )
  loop
    update public.team_sessions set status = 'ended', ended_at = now()
      where id = r.id and status in ('running','paused');
    select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.id;
    begin
      insert into public.session_events(session_id, seq, actor_id, role, type, payload)
        values (r.id, v_next, null, null, 'session.ended', jsonb_build_object('at', now(), 'reason', 'reaped'));
      update public.session_state set seq = v_next, updated_at = now() where session_id = r.id;
    exception when unique_violation then null;  -- a concurrent writer took the seq; the status flip stands
    end;
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;

-- Verification:
--   explain analyze select public.promote_due_injects();
--   select indexname from pg_indexes where indexname in
--     ('session_injects_pending_idx','team_sessions_active_idx');
--   select indexname from pg_indexes where indexname='session_events_session_seq_idx'; -- gone
