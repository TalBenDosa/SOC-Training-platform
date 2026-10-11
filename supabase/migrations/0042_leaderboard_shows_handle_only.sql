-- HACK THE SOC :: 0042 — the class leaderboard shows the USERNAME only
-- ---------------------------------------------------------------------------
-- A student must not be exposed to another student's registration details. The
-- leaderboard ranked peers by display_name, which falls back to the email
-- local-part when a student signs up without a name (handle_new_user), so a peer
-- could appear as "marganiti" / "yish555" — a fragment of their registration
-- email — and, for students who did set a real name, their full real name was
-- shown to the whole cohort. Both are registration details a classmate should
-- not see.
--
-- Fix: rank by the HANDLE (the pseudonymous username) instead. A handle never
-- contains an '@' and is the identifier the product already treats as public, so
-- peers see "@yish" rather than an email fragment or a real name. This is the DB
-- fix point — /api/leaderboard and the LeaderboardCard already render only this
-- one column and need no change. (The org-admin roster in /manage still shows
-- full emails, correctly: it is staff-only, gated by requireOrgAdmin.)
--
-- `create or replace` preserves the grants from 0018; only the projected
-- identity column changes. The 0037 platform-admin exclusion is kept verbatim.

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
    -- Username only — never display_name (real name) or the email-derived
    -- fallback. The column is still called display_name for API/UI compatibility.
    coalesce(nullif(p.handle, ''), 'analyst')              as display_name,
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
--   select display_name from public.org_leaderboard(20);
--   → every value is a handle (no '@', no real names, no email fragments).
