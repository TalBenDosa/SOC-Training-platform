-- HACK THE SOC :: 0123 — presence: when a learner was really last on the platform
-- ---------------------------------------------------------------------------
-- (0118-0122 are taken by the development line; this one is numbered after them.)
--
-- The progress report said "last signed in 18 Nov" for a learner who worked on 24 Nov.
-- auth.users.last_sign_in_at moves only when a password (or SSO) sign-in creates a NEW
-- session; a learner who stays signed in keeps the same session for weeks and it is renewed
-- silently, so that column says when they last typed a password, not when they were last here.
--
-- Two things fix it:
--   1. org_member_last_seen(org): the last sign-in AND the last time each member's session was
--      renewed (auth.sessions), so the past is right from the day this is applied.
--   2. user_presence_days: one row per learner, environment and day, kept by the app itself
--      (POST /api/progress/presence, a beat a minute while the learner is active): first and
--      last moment seen, active seconds, and the number of visits that day.
--
-- Both are written and read ONLY by the server (service role), always pinned to the caller's
-- own organisation. Org isolation: org_id references organizations with ON DELETE CASCADE, so
-- purge_org removes these rows; a user deletion cascades from auth.users.
--
-- NON-DESTRUCTIVE: a new, empty table and two functions. Idempotent.

create table if not exists public.user_presence_days (
  user_id        uuid not null references auth.users(id) on delete cascade,
  org_id         uuid references public.organizations(id) on delete cascade,
  day            date not null,                       -- UTC day
  first_seen_at  timestamptz not null default now(),
  last_seen_at   timestamptz not null default now(),
  active_seconds integer not null default 0 check (active_seconds >= 0 and active_seconds <= 86400),
  visits         integer not null default 1 check (visits >= 1)
);
-- One row per learner, environment and day (a learner without an organisation has org_id null).
create unique index if not exists user_presence_days_key
  on public.user_presence_days (user_id, (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid)), day);
create index if not exists user_presence_days_org_idx on public.user_presence_days (org_id, day);

alter table public.user_presence_days enable row level security;
drop policy if exists user_presence_days_read_own on public.user_presence_days;
create policy user_presence_days_read_own on public.user_presence_days
  for select to authenticated using (user_id = auth.uid());
revoke all on public.user_presence_days from anon;
revoke insert, update, delete on public.user_presence_days from authenticated;
grant select on public.user_presence_days to authenticated;
grant select, insert, update on public.user_presence_days to service_role;

-- One beat. Atomic, so two open tabs cannot lose each other's seconds. A beat that arrives more
-- than 30 minutes after the previous one counts as a new visit. Seconds are capped per beat here
-- as well as in the route.
create or replace function public.record_presence(p_user uuid, p_org uuid, p_seconds integer)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_add integer := greatest(0, least(coalesce(p_seconds, 0), 120));
begin
  if p_user is null then raise exception 'user required'; end if;
  insert into public.user_presence_days (user_id, org_id, day, first_seen_at, last_seen_at, active_seconds, visits)
  values (p_user, p_org, (now() at time zone 'utc')::date, now(), now(), v_add, 1)
  on conflict (user_id, (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid)), day) do update
    set visits = public.user_presence_days.visits
                 + case when now() - public.user_presence_days.last_seen_at > interval '30 minutes' then 1 else 0 end,
        active_seconds = least(public.user_presence_days.active_seconds + excluded.active_seconds, 86400),
        last_seen_at = now();
end;
$$;
revoke all on function public.record_presence(uuid, uuid, integer) from public, anon, authenticated;
grant execute on function public.record_presence(uuid, uuid, integer) to service_role;

-- Last sign-in and last session renewal of every member of ONE organisation. Service role only,
-- like org_member_emails (0032): the org-scoped routes pass the caller's own org.
create or replace function public.org_member_last_seen(p_org uuid)
  returns table(user_id uuid, last_sign_in_at timestamptz, last_session_at timestamptz)
  language sql
  stable
  security definer set search_path = public, auth
as $$
  select om.user_id,
         u.last_sign_in_at,
         (select max(greatest(s.created_at, coalesce(s.updated_at, s.created_at)))
            from auth.sessions s where s.user_id = om.user_id) as last_session_at
  from public.org_members om
  join auth.users u on u.id = om.user_id
  where om.org_id = p_org;
$$;
revoke execute on function public.org_member_last_seen(uuid) from authenticated, anon, public;
grant execute on function public.org_member_last_seen(uuid) to service_role;
