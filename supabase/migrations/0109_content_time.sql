-- HACK THE SOC :: 0109 — time spent on lessons and quizzes
-- ---------------------------------------------------------------------------
-- Org admins set a target time per learning-plan item (assignments.items[].target_minutes,
-- jsonb, no migration) and see the time actually spent beside it. Rooms (task telemetry)
-- and scenarios (time_taken) already record time; lessons and quizzes did not. This table
-- keeps one running total per learner and item, written ONLY by the server (POST
-- /api/progress/time, which validates the item and caps each beat), read by:
--   - the learner (their own rows, RLS),
--   - org staff through the service role (src/lib/plans/timeSpent.ts), pinned to their org.
--
-- Counted time is ACTIVE time: the page sends a beat while it is visible and the learner
-- has interacted in the last two minutes, at most 120 seconds per beat.
--
-- Org isolation: org_id references organizations with ON DELETE CASCADE, so purge_org
-- (which deletes the organization row, 0101) removes these rows too; a user deletion
-- cascades from auth.users.
--
-- NON-DESTRUCTIVE: a new, empty table and one function. Idempotent.

create table if not exists public.content_time (
  user_id     uuid not null references auth.users(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete cascade,
  kind        text not null check (kind in ('lesson', 'quiz')),
  item_id     text not null check (char_length(item_id) between 1 and 300),
  seconds     integer not null default 0 check (seconds >= 0 and seconds <= 3600000),
  updated_at  timestamptz not null default now(),
  primary key (user_id, kind, item_id)
);
create index if not exists content_time_org_idx on public.content_time (org_id, kind, item_id);

alter table public.content_time enable row level security;
drop policy if exists content_time_read_own on public.content_time;
create policy content_time_read_own on public.content_time
  for select to authenticated using (user_id = auth.uid());
revoke all on public.content_time from anon;
revoke insert, update, delete on public.content_time from authenticated;
grant select on public.content_time to authenticated;
grant select, insert, update on public.content_time to service_role;

-- Adds one beat atomically (no read-modify-write race between two open tabs).
create or replace function public.add_content_time(
  p_user uuid, p_org uuid, p_kind text, p_item text, p_seconds integer
) returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_add integer := greatest(0, least(coalesce(p_seconds, 0), 120));
  v_total integer;
begin
  if p_kind not in ('lesson', 'quiz') or p_item is null or char_length(p_item) not between 1 and 300 then
    raise exception 'invalid content';
  end if;
  insert into public.content_time (user_id, org_id, kind, item_id, seconds, updated_at)
  values (p_user, p_org, p_kind, p_item, v_add, now())
  on conflict (user_id, kind, item_id) do update
    set seconds = least(public.content_time.seconds + excluded.seconds, 3600000),
        org_id = coalesce(excluded.org_id, public.content_time.org_id),
        updated_at = now()
  returning seconds into v_total;
  return v_total;
end;
$$;
revoke all on function public.add_content_time(uuid, uuid, text, text, integer) from public, anon, authenticated;
grant execute on function public.add_content_time(uuid, uuid, text, text, integer) to service_role;
