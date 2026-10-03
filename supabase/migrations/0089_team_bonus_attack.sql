-- 0089 — Team-SOC bonus attack (Tal, 2026-10-03).
--
-- A team exercise may carry one more random attack story on top of the planned ones. /start
-- seeds its rows with channel = 'bonus' and due_offset_ms = BONUS_HOLD (1e15) + the row's own
-- relative offset, so promote_due_injects never reaches them and replenish_feed (channel 'feed'
-- only) never counts or recycles them. team_release_bonus() — every 10 s — releases them once the
-- team has CAUGHT every planned attack: for each planned story incident, at least one of its
-- attack rows (expected verdict tp / escalate) that reached the feed was dispositioned tp /
-- escalate or escalated. Released rows become ordinary feed rows due 30 s from now, at their own
-- pace. A session that ends first skips them with every other pending inject, and the report
-- only joins rows that reached the feed — an unreleased bonus is never counted as missed.

create or replace function public.team_release_bonus()
  returns int language plpgsql security definer set search_path = public as $$
declare
  s       record;
  v_off   bigint;
  v_rows  int;
  v_total int := 0;
begin
  for s in
    select ts.id, ts.started_at, coalesce(ts.paused_ms, 0) as pms
      from public.team_sessions ts
     where ts.status = 'running'
       and exists (select 1 from public.session_injects i
                    where i.session_id = ts.id and i.channel = 'bonus' and i.status = 'pending')
     limit 100
  loop
    begin
      if not public.team_try_lock_session(s.id) then continue; end if;   -- busy → next tick
      -- At least one planned incident, and none of them still uncaught.
      if not exists (
        select 1 from public.session_injects i
         where i.session_id = s.id and i.channel <> 'bonus'
           and i.expected_action->>'origin' = 'story'
           and coalesce(i.expected_action->>'bonus', 'false') <> 'true'
           and i.expected_action->>'expected_verdict' in ('tp', 'escalate')
      ) then continue; end if;
      if exists (
        select 1
          from (select distinct i.expected_action->>'incident_id' as inc
                  from public.session_injects i
                 where i.session_id = s.id and i.channel <> 'bonus'
                   and i.expected_action->>'origin' = 'story'
                   and coalesce(i.expected_action->>'bonus', 'false') <> 'true'
                   and i.expected_action->>'expected_verdict' in ('tp', 'escalate')
                   and i.expected_action->>'incident_id' is not null) planned
         where not exists (
           select 1
             from public.session_injects j
             join public.session_events e
               on e.session_id = s.id
              and e.payload->>'event_id' = j.body->>'id'
            where j.session_id = s.id and j.status = 'fired'
              and j.expected_action->>'incident_id' = planned.inc
              and j.expected_action->>'expected_verdict' in ('tp', 'escalate')
              and (e.type = 'escalation.requested'
                   or (e.type = 'disposition.set' and e.payload->>'verdict' in ('tp', 'escalate')))
         )
      ) then continue; end if;
      -- …and caught by judgement, not by flagging everything (expert review P0-6): the team's wrong
      -- positive calls (tp / escalate on rows that are benign or a false positive) may not
      -- outnumber its right ones.
      if (select count(*) filter (where j.expected_action->>'expected_verdict' not in ('tp', 'escalate'))
                 > count(*) filter (where j.expected_action->>'expected_verdict' in ('tp', 'escalate'))
            from public.session_events e
            join public.session_injects j on j.session_id = s.id and j.body->>'id' = e.payload->>'event_id'
           where e.session_id = s.id
             and (e.type = 'escalation.requested'
                  or (e.type = 'disposition.set' and e.payload->>'verdict' in ('tp', 'escalate')))) then
        continue;
      end if;
      v_off := floor(extract(epoch from (clock_timestamp() - s.started_at)) * 1000)::bigint - s.pms;
      update public.session_injects
         set channel = 'feed',
             due_offset_ms = v_off + 30000 + greatest(0, due_offset_ms - 1000000000000000)
       where session_id = s.id and channel = 'bonus' and status = 'pending';
      get diagnostics v_rows = row_count;
      v_total := v_total + v_rows;
      if v_rows > 0 then
        insert into public.team_ops_events(kind, session_id, detail) values ('bonus_released', s.id, v_rows || ' rows');
      end if;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('bonus_release_error', s.id, sqlerrm);
    end;
  end loop;
  return v_total;
end $$;

revoke all on function public.team_release_bonus() from public, anon, authenticated;
grant execute on function public.team_release_bonus() to service_role;

do $$
begin
  perform cron.unschedule('team-release-bonus') where exists (select 1 from cron.job where jobname = 'team-release-bonus');
  perform cron.schedule('team-release-bonus', '10 seconds', 'select public.team_release_bonus();');
end $$;
