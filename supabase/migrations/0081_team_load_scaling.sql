-- 0081_team_load_scaling.sql
--
-- Team exercise load sized to the team (Tal, 2026-09-30) — see src/lib/team/load.ts.
-- /start now seeds the feed at a pace set by the number of Tier-1 analysts and an
-- attack count set by the team size, and stores the pace on the session so the
-- DB refill keeps it.
--
-- The refill (replenish_feed) used to top the feed up with 6 recycled logs spaced
-- 3–7 s apart, starting from "now" even while logs were still pending — once the
-- seeded timeline ran low (the tail of every shift, until the instructor ended it)
-- the feed jumped to ~12 logs/min in bursts, far past what a Tier-1 can read.
-- It now follows the session's own pace and continues AFTER the last pending log.
--
-- replenish_feed is rebuilt from its live production definition (2026-09-30) with
-- only those two changes.

alter table public.team_sessions add column if not exists feed_gap_ms integer;
alter table public.team_sessions add column if not exists feed_jitter_ms integer;
alter table public.team_sessions drop constraint if exists team_sessions_feed_gap_bounds;
alter table public.team_sessions add constraint team_sessions_feed_gap_bounds
  check ((feed_gap_ms is null or feed_gap_ms between 2000 and 120000)
     and (feed_jitter_ms is null or feed_jitter_ms between 0 and 60000));

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
      for r in
        select body, expected_action from public.session_injects
         where session_id = s.id and status = 'fired' and channel = 'feed'   -- never recycle MSEL injects
           and coalesce(expected_action->>'expected_verdict', body->>'expected_verdict', '') not in ('tp','escalate')
           -- 0073: pure noise only (story control steps / ITSM / inject support are benign too now)
           and not (coalesce(expected_action, '{}'::jsonb) ?| array['incident_id', 'supports_inject'])
           and coalesce(expected_action->>'origin', 'noise') = 'noise'
           and coalesce(expected_action->>'is_baseline', '') <> 'true'
         order by random() limit 6
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
