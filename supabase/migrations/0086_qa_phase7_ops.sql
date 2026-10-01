-- QA phase 7 (error handling) — operational hygiene.
--
-- E-20: lobbies were never reaped. A session created and never started stayed
--       in 'lobby' forever: it kept appearing in the staff "open sessions" list
--       and kept its members "in a session". The reaper now also ends lobbies
--       older than 24 h (team_transition already allows lobby → ended).
--       Running / paused rules are unchanged from 0071.

create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_res jsonb; v_count int := 0;
begin
  for r in
    select ts.id from public.team_sessions ts
     where (ts.status = 'lobby' and ts.created_at < now() - interval '24 hours')       -- abandoned lobby (E-20)
        or (ts.status in ('running','paused')
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
revoke all on function public.reap_stale_team_sessions() from public, anon, authenticated;
grant execute on function public.reap_stale_team_sessions() to service_role;
