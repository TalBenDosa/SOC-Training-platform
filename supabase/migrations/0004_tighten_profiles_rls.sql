-- HACK THE SOC :: 0004 — tighten profiles read RLS (fixes an info-disclosure)
-- ---------------------------------------------------------------------------
-- 0001_init.sql shipped:  create policy "profiles read" ... for select using (true);
-- That makes EVERY row of public.profiles world-readable through the anon key —
-- a live PT confirmed an unauthenticated caller could read every user's id,
-- handle, and `role` (including which account is 'admin'). That enables user
-- enumeration and hands an attacker the admin's user id.
--
-- Fix: a user may read only their OWN profile row. Nothing user-facing depends
-- on reading other people's profiles today. If a public leaderboard is added
-- later, expose ONLY safe columns (handle, display_name, xp) through a dedicated
-- SECURITY DEFINER view or a column-scoped policy — never re-open the base table,
-- and never expose `role`.

alter table public.profiles enable row level security;

drop policy if exists "profiles read" on public.profiles;
create policy "profiles read own" on public.profiles
  for select using (auth.uid() = id);

-- (the owner-only update policy from 0001 is already correct and is left as-is)
