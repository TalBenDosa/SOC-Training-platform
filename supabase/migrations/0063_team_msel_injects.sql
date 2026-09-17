-- HACK THE SOC :: 0063 — MSEL injects: promote by channel (feed.event vs staff.inject)
-- ===========================================================================
-- promote_due_injects previously stamped EVERY due inject as a 'feed.event', so
-- the only thing the timeline could deliver was feed logs. To let a session carry
-- scripted MSEL curveballs (management pressure, a vishing help-desk ticket, an
-- announcement) on a timer — without a live facilitator typing them — the seeded
-- inject now carries a `channel`, and this promotes:
--     channel 'inject' → session_events.type 'staff.inject'  (shows in InjectFeed)
--     anything else     → 'feed.event'                        (a normal log)
-- The body for an 'inject' row is { kind, text } (same shape the instructor's
-- manual inject composer emits), so InjectFeed renders scripted and manual
-- injects identically. System-originated (actor_id null), exactly like feed events.
-- ===========================================================================

create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0; v_type text;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + (i.due_offset_ms || ' milliseconds')::interval <= now()
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

-- Verification: seed a session_injects row with channel 'inject' and a past
-- due_offset, run select public.promote_due_injects(); confirm a 'staff.inject'
-- session_event appears (and shows in the InjectFeed for every member).
