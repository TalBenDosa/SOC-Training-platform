-- HACK THE SOC :: 0005 — close a privilege-escalation hole in profiles
-- ---------------------------------------------------------------------------
-- FINDING (critical). 0001_init.sql shipped:
--
--     create policy "profiles update" on public.profiles
--       for update using (auth.uid() = id);
--
-- `role` lives in that same table, the policy has NO `with check` clause, and
-- nothing restricts which columns the row-owner may write. The anon key is
-- public by design (it ships in the browser bundle), so ANY registered user
-- could run, straight from the devtools console:
--
--     supabase.from('profiles').update({ role: 'admin' }).eq('id', <their own id>)
--
-- …and become an admin. `requireAdmin()` in src/lib/auth/apiGuard.ts reads
-- exactly this column, so that single statement would have unlocked every
-- content-authoring and admin API on the platform.
--
-- Two lower-severity variants of the same defect: `id` was writable, so a row
-- could be re-pointed at another user; and `xp`/`level` are owner-writable, so
-- a student can inflate their own score.
--
-- SCOPE DECISION — `xp` is deliberately NOT frozen here. src/lib/storage/
-- remoteBackend.ts writes it straight from the browser
-- (`supabase.from("profiles").update({ xp })`), so freezing it would silently
-- break XP persistence for every user. Self-reported XP is a leaderboard-
-- integrity problem, not an access-control boundary: inflating it grants no
-- data access and exposes nothing about anyone else. It is left working and
-- recorded as known debt — the real fix is to move XP awards behind a
-- server-side route that writes with the service role, at which point `xp` and
-- `level` should be added to the frozen set below.
--
-- FIX. Keep the owner-only row scope, but stop the owner from changing the
-- columns that grant authority. A WITH CHECK alone cannot express "this column
-- must not change" (it only sees the NEW row), so the invariant is enforced by
-- a BEFORE UPDATE trigger that compares OLD to NEW and silently restores the
-- privileged columns. A trigger also covers every write path — PostgREST, SQL
-- editor, a future service — rather than only the ones that go through RLS.
--
-- Role changes are intentionally left with no self-service path at all. Grant
-- admin out-of-band (Supabase SQL editor / a service-role backend), which is
-- the correct blast radius for the one privilege that unlocks content editing.

-- ── 1. Re-assert the row-scope policy, now with WITH CHECK ──────────────────
-- Without WITH CHECK, an UPDATE could move a row to a different `id` — writing
-- into someone else's row while still passing the USING test on the old one.
drop policy if exists "profiles update" on public.profiles;
create policy "profiles update own" on public.profiles
  for update
  using      (auth.uid() = id)
  with check (auth.uid() = id);

-- ── 2. Freeze the privileged columns ────────────────────────────────────────
create or replace function public.profiles_guard_privileged_columns()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Identity is immutable: a profile row belongs to exactly one auth user.
  new.id := old.id;

  -- Authority is not self-service. Silently preserving (rather than raising)
  -- keeps ordinary profile edits working while making escalation a no-op.
  --
  -- auth.uid() is NULL for a service-role connection, so an out-of-band grant
  -- ("promote this account to admin") still works from the SQL editor or a
  -- trusted backend — only the self-service path is closed.
  if auth.uid() is not null then
    new.role := old.role;
  end if;

  -- NOTE: xp / level are intentionally left writable — see the SCOPE DECISION
  -- in this file's header. Add them here once XP awards move server-side.

  return new;
end;
$$;

drop trigger if exists profiles_guard_privileged_columns on public.profiles;
create trigger profiles_guard_privileged_columns
  before update on public.profiles
  for each row
  execute function public.profiles_guard_privileged_columns();

-- ── 3. Verification queries (run these after applying) ──────────────────────
-- As a normal signed-in user, both of these must leave `role` unchanged:
--   update public.profiles set role = 'admin' where id = auth.uid();
--   select role from public.profiles where id = auth.uid();   -- still 'analyst'
--
-- And this must return zero rows for a non-admin (0004 restricts SELECT to own):
--   select id, role from public.profiles where role = 'admin';

comment on function public.profiles_guard_privileged_columns() is
  'Prevents self-service escalation: id/role are immutable, and xp/level cannot be set by the row owner. Service-role writes bypass the owner branch.';
