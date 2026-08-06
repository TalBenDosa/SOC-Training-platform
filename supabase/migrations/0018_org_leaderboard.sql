-- ─────────────────────────────────────────────────────────────────────────────
-- 0018 — Class leaderboard, org-scoped and leak-proof
-- ─────────────────────────────────────────────────────────────────────────────
-- Students cannot read peers' profiles: RLS from 0011 ("profiles self read")
-- restricts SELECT to `id = auth.uid()`, and only org_admin/instructor may read
-- the wider roster. A per-cohort leaderboard therefore needs a purpose-built
-- accessor that returns ONLY leaderboard-safe columns (display name, xp, level,
-- rank) and ONLY for the caller's own org.
--
-- The old `public.leaderboard` VIEW was DROPPED in 0016 (finding C1): a PG15
-- view defaults to security_invoker = OFF, so it ran as its owner and bypassed
-- RLS, leaking every user in every org. This replaces it with a SECURITY DEFINER
-- *function* whose tenant boundary is a hard-coded `org_id = public.current_org()`
-- predicate. current_org() derives the org from the CALLER's JWT (auth.jwt() is
-- the caller's even inside a definer function), so the function can only ever
-- return the caller's own cohort — never another tenant's, and never anything
-- when the caller has no org.
-- ─────────────────────────────────────────────────────────────────────────────

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
  order by p.xp desc, p.created_at, p.id
  limit greatest(1, least(coalesce(p_limit, 20), 100));
$$;

-- Signed-in users only; the same-org predicate above is the tenant isolation.
revoke all     on function public.org_leaderboard(int) from public, anon;
grant  execute on function public.org_leaderboard(int) to authenticated;

comment on function public.org_leaderboard(int) is
  'Per-cohort leaderboard: safe columns only, hard-filtered to the caller''s own org via current_org(). Replaces the leaderboard view dropped in 0016 (C1).';

-- Manual verification:
--   -- as a student in org A: returns only org A rows, is_me = true on own row
--   select * from public.org_leaderboard(20);
--   -- a student in a single-seat org sees only themselves; a solo user (no org)
--   -- sees an empty set (current_org() is null).
