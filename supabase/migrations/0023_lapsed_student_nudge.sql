-- ─────────────────────────────────────────────────────────────────────────────
-- 0023 — Lapsed-student re-engagement
-- ─────────────────────────────────────────────────────────────────────────────
-- There is no re-engagement channel at all. The streak/freeze mechanic is good
-- but entirely in-app: it only reaches a student who already opened the app that
-- day. A student who stops for a week has literally zero pull back, which makes
-- this the single biggest lever on long-term retention.
--
-- Two pieces:
--  1. `profiles.last_nudged_at` — so nobody is emailed twice in a cooldown
--     window. Without this a daily cron would mail the same lapsed student every
--     morning, which is how a re-engagement feature becomes a spam complaint.
--  2. `lapsed_students()` — one SECURITY DEFINER function holding the whole
--     "who counts as lapsed" definition, including the email lookup from
--     auth.users (which the client roles cannot read). Keeping this in SQL means
--     the cron route stays a thin caller and the rule lives in one place.
--
-- Deliberately excluded: students who never started at all. A "you've been away"
-- email to someone who never began reads as nonsense — onboarding is a different
-- problem and deserves a different message.
-- ─────────────────────────────────────────────────────────────────────────────

alter table public.profiles
  add column if not exists last_nudged_at timestamptz;

comment on column public.profiles.last_nudged_at is
  'When this learner was last sent a re-engagement email. Enforces the cooldown in lapsed_students().';

create or replace function public.lapsed_students(
  p_idle_days     int default 7,
  p_cooldown_days int default 14,
  p_limit         int default 200
)
returns table (
  user_id      uuid,
  email        text,
  display_name text,
  org_name     text,
  last_active  timestamptz
)
language sql
security definer
stable
set search_path = public
as $$
  with activity as (
    select p.id as user_id,
           greatest(
             coalesce(max(rp.updated_at),  'epoch'::timestamptz),
             coalesce(max(ds.played_at),   'epoch'::timestamptz),
             coalesce(max(sh.completed_at),'epoch'::timestamptz)
           ) as last_active
      from public.profiles p
      left join public.room_progress      rp on rp.user_id = p.id
      left join public.dashboard_sessions ds on ds.user_id = p.id
      left join public.scenario_history   sh on sh.user_id = p.id
     group by p.id
  )
  select p.id,
         u.email::text,
         coalesce(nullif(p.display_name, ''), p.handle),
         o.name,
         a.last_active
    from public.profiles p
    join activity a on a.user_id = p.id
    join auth.users u on u.id = p.id
    left join public.organizations o on o.id = p.org_id
   where u.email is not null
     -- Idle long enough to be worth a nudge …
     and a.last_active < now() - make_interval(days => p_idle_days)
     -- … but they DID start once; never-started is an onboarding problem.
     and a.last_active > 'epoch'::timestamptz
     -- … and we haven't already nudged them recently.
     and (p.last_nudged_at is null or p.last_nudged_at < now() - make_interval(days => p_cooldown_days))
     -- Don't chase students whose college licence has lapsed.
     and (o.id is null or o.status in ('trial', 'active'))
   order by a.last_active asc
   limit greatest(1, least(p_limit, 500));
$$;

-- Service-role only: this returns email addresses, so no client role may call it.
revoke all on function public.lapsed_students(int, int, int) from public, anon, authenticated;

comment on function public.lapsed_students(int, int, int) is
  'Learners idle for p_idle_days who started at least once and have not been nudged within p_cooldown_days. Returns email addresses — service-role only, called by /api/cron/nudge-lapsed.';

-- Verification:
--   select count(*) from public.lapsed_students(7, 14, 200);
