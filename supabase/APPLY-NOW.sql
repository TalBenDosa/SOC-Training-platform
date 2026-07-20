-- ═══════════════════════════════════════════════════════════════════════════
--  RUN THIS ONCE, IN THE SUPABASE SQL EDITOR
--  Dashboard -> your project -> SQL Editor -> New query -> paste -> Run
-- ═══════════════════════════════════════════════════════════════════════════
--
--  It does two things:
--    1. Applies migration 0005 — closes the privilege-escalation hole.
--    2. Grants admin to your account.
--
--  Order matters and is deliberate: the trigger from step 1 blocks role
--  changes made by a signed-in user, but NOT by the SQL editor (which runs
--  as a service role, where auth.uid() is null). That is the whole design —
--  granting admin stays possible here, and nowhere else. Step 2 works fine
--  after step 1.
--
--  Safe to run more than once.
-- ═══════════════════════════════════════════════════════════════════════════


-- ── 1. Row scope, now with WITH CHECK ───────────────────────────────────────
-- Without WITH CHECK an UPDATE could re-point a row at a different id —
-- writing into someone else's profile while still passing the USING test
-- against the old one.
drop policy if exists "profiles update" on public.profiles;
drop policy if exists "profiles update own" on public.profiles;
create policy "profiles update own" on public.profiles
  for update
  using      (auth.uid() = id)
  with check (auth.uid() = id);


-- ── 2. Freeze the privileged columns ────────────────────────────────────────
-- A WITH CHECK alone cannot express "this column must not change" — it only
-- sees the NEW row. So the invariant is a BEFORE UPDATE trigger comparing OLD
-- to NEW. A trigger also covers every write path (PostgREST, SQL editor, a
-- future service), not only the ones that happen to go through RLS.
create or replace function public.profiles_guard_privileged_columns()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- Identity is immutable: a profile row belongs to exactly one auth user.
  new.id := old.id;

  -- Authority is not self-service. Silently preserving rather than raising
  -- keeps ordinary profile edits working while making escalation a no-op.
  --
  -- auth.uid() is NULL for a service-role connection, so an out-of-band grant
  -- from this editor still works — only the self-service path is closed.
  if auth.uid() is not null then
    new.role := old.role;
  end if;

  -- xp / level are intentionally left writable: src/lib/storage/remoteBackend.ts
  -- writes them straight from the browser, so freezing them would break XP
  -- persistence for everyone. Self-reported XP is a leaderboard-integrity
  -- problem, not an access boundary — it grants no data access and exposes
  -- nothing about anyone else. Add them here once XP awards move server-side.
  return new;
end;
$$;

drop trigger if exists profiles_guard_privileged_columns on public.profiles;
create trigger profiles_guard_privileged_columns
  before update on public.profiles
  for each row
  execute function public.profiles_guard_privileged_columns();

comment on function public.profiles_guard_privileged_columns() is
  'Prevents self-service escalation: id and role are immutable to the row owner. Service-role writes bypass the owner branch.';


-- ── 3. Grant admin to Tal ───────────────────────────────────────────────────
-- Fails loudly if the id does not exist, rather than reporting success after
-- updating zero rows.
do $$
declare
  target_id uuid := 'd0b9928b-1d0a-4635-95b4-de70c4f1329a';
  hit       int;
begin
  update public.profiles set role = 'admin' where id = target_id;
  get diagnostics hit = row_count;

  if hit = 0 then
    raise exception
      'No profile with id %. Check the id — run: select p.id, u.email from public.profiles p join auth.users u on u.id = p.id;',
      target_id;
  end if;

  raise notice 'Granted admin to %', target_id;
end;
$$;


-- ── 4. Verify ───────────────────────────────────────────────────────────────
-- Expect exactly one row, role = admin, with your email.
select p.id, p.role, u.email
from public.profiles p
join auth.users u on u.id = p.id
where p.role = 'admin';
