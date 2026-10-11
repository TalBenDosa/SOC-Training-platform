-- 0084_team_feed_recycling.sql
--
-- Scenario review 2026-10-01, fix 7. Once a team shift's scripted logs run out,
-- replenish_feed keeps the feed alive by recycling earlier noise. In session
-- e90b31d5 the last ~28 minutes were the same few logs over and over (TradeFlow
-- ×7, svc-backup TGT ×4) and an FP decoy — r.williams' "approved" 9.3 GB USB copy —
-- three times, each one looking like a new incident and graded again.
--
--   - FP decoys are never recycled (expected_verdict fp / an fp_explanation);
--   - candidates are distinct logs, least-shown first (then random), so repeats
--     spread evenly across the pool instead of clumping.
--
-- replenish_feed is copied verbatim from 0081 with only the candidate query changed.

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
