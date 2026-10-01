-- 0085_dashboard_guard_no_reject.sql — QA phase 7, E-13 (a regression from 0083).
--
-- 0083's dashboard_session_guard RAISED on an out-of-range shift (a dashboard left
-- running > 6 h, an odd counter) and on the 31st shift in an hour. The browser
-- held the refused insert as "check your connection — your work is safe on this
-- device", replayed it forever, and the row was lost on reload. A refusal the user
-- can do nothing about must not be an error:
--   - out-of-range / negative values are CLAMPED into range (the shift is kept);
--   - beyond 30 shifts an hour the row is dropped silently (BEFORE INSERT → null) —
--     that volume is only ever a script, never a learner.
-- detect_rate stays derived from the counts; played_at stays now().

create or replace function public.dashboard_session_guard()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if auth.uid() is null then return new; end if;            -- service role: trusted
  if (select count(*) from public.dashboard_sessions
       where user_id = new.user_id and played_at > now() - interval '1 hour') >= 30 then
    return null;                                              -- flood: drop quietly
  end if;
  new.played_at := now();
  new.attacks_presented_count := least(greatest(coalesce(new.attacks_presented_count, 0), 0), 500);
  new.attacks_caught_count    := least(greatest(coalesce(new.attacks_caught_count, 0), 0), new.attacks_presented_count);
  new.fn_count                := least(greatest(coalesce(new.fn_count, 0), 0), 10000);
  new.events_opened_count     := least(greatest(coalesce(new.events_opened_count, 0), 0), 20000);
  new.duration_ms             := least(greatest(coalesce(new.duration_ms, 0), 0), 6 * 3600 * 1000);
  new.avg_catch_ms            := case when new.avg_catch_ms is null then null else least(greatest(new.avg_catch_ms, 0), 6 * 3600 * 1000) end;
  new.xp_earned               := least(greatest(coalesce(new.xp_earned, 0), 0), 5000);
  -- Derived from the counts, never taken from the client (0083).
  new.detect_rate := case when new.attacks_presented_count > 0
                          then round(100.0 * new.attacks_caught_count / new.attacks_presented_count)::int else 0 end;
  return new;
end;
$$;
