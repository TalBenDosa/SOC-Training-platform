-- HACK THE SOC :: 0037 — platform admins are invisible in per-org leaderboards
-- ---------------------------------------------------------------------------
-- A platform super-admin can enter any environment for oversight (enter-org sets
-- profiles.org_id to that tenant). But org_leaderboard (0018) ranks EVERY profile
-- whose org_id = current_org() — so the owner appeared in the leaderboard of
-- whichever environment they were currently viewing. That pollutes the tenant's
-- cohort with someone who isn't a student.
--
-- Fix: exclude platform admins from the leaderboard. Combined with the code-side
-- changes (enter-org no longer creates a membership; roster + analytics filter
-- is_platform_admin), the super-admin now traverses environments completely
-- invisible to each tenant's progress views. `create or replace` preserves the
-- existing grants from 0018 — only the query body changes.

create or replace function public.org_leaderboard(p_limit int default 20)
returns table (
  rank         bigint,
  display_name text,
  xp           integer,
  lvl          integer,
  is_me        boolean
)
language sql
security definer
stable
set search_path = public
as $$
  select
    rank() over (order by p.xp desc, p.created_at, p.id)   as rank,
    coalesce(nullif(p.display_name, ''), p.handle)         as display_name,
    p.xp,
    p.level                                                as lvl,
    (p.id = auth.uid())                                    as is_me
  from public.profiles p
  where public.current_org() is not null      -- caller has an org in their JWT …
    and p.org_id = public.current_org()        -- … and we only ever return that org
    and coalesce(p.is_platform_admin, false) = false   -- … and never the platform owner
  order by p.xp desc, p.created_at, p.id
  limit greatest(1, least(coalesce(p_limit, 20), 100));
$$;

-- Verification:
--   As a super-admin viewing an org, select * from public.org_leaderboard(20);
--   → the super-admin's own row is absent; students rank normally.
