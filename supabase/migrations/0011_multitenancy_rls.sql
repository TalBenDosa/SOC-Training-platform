-- HACK THE SOC :: 0011 — Multi-tenancy RLS cut-over
-- ===========================================================================
-- Phase 0, part 2 of 2. This REPLACES the per-user RLS policies with
-- per-ORG isolation. It relies on the access-token hook from 0010 stamping
-- `org_id`/`org_role` into the JWT.
--
-- ⚠️ DO NOT RUN until:
--   1. 0010 has been applied, AND
--   2. the Custom Access Token Hook is enabled in the dashboard, AND
--   3. a FRESH login has been verified to carry org_id
--      (`select auth.jwt() ->> 'org_id'` returns the org uuid).
-- Running it before the claim exists makes current_org() return NULL and every
-- policy fail closed → users see zero rows until they re-login. See the runbook
-- (docs/phase-0-plan.md) for the exact sequence and the forced re-login step.
--
-- After this migration, isolation is enforced at the DATABASE: a query carrying
-- org A's JWT cannot read or write org B's rows, regardless of app-layer bugs.

-- ── 1. Freeze org_id + privilege columns on profiles ────────────────────────
-- Extends the 0005 guard: a signed-in user must not change their own id, role,
-- org_id, or platform-admin flag. Those move only via service-role / SQL.
create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql
as $$
begin
  if auth.uid() is not null then
    new.id                := old.id;
    new.role              := old.role;
    new.org_id            := old.org_id;
    new.is_platform_admin := old.is_platform_admin;
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_guard_privileged_columns on public.profiles;
create trigger profiles_guard_privileged_columns
  before update on public.profiles
  for each row execute function public.guard_profile_privileged_columns();

-- ── 2. profiles — self read/update + org-staff read ─────────────────────────
drop policy if exists "profiles read own"   on public.profiles;
drop policy if exists "profiles update own" on public.profiles;
drop policy if exists "profiles self read"       on public.profiles;
drop policy if exists "profiles self update"     on public.profiles;
drop policy if exists "profiles org staff read"  on public.profiles;

create policy "profiles self read" on public.profiles
  for select using (id = auth.uid());

create policy "profiles self update" on public.profiles
  for update using (id = auth.uid()) with check (id = auth.uid());

-- org_admin / instructor may read every profile in THEIR org (for the roster
-- and cohort-progress views) — never another org's.
create policy "profiles org staff read" on public.profiles
  for select using (
    org_id = public.current_org()
    and public.current_org_role() in ('org_admin','instructor')
  );

-- ── 3. Learner tables — per-org isolation + org-staff read ──────────────────
-- Replaces the "<t> own select" / "<t> own write" policies from 0002.
do $$
declare t text;
begin
  foreach t in array array[
    'user_progress','room_progress','dashboard_sessions','scenario_history','ai_usage'
  ] loop
    execute format('drop policy if exists %I on public.%I', t || ' own select', t);
    execute format('drop policy if exists %I on public.%I', t || ' own write',  t);
    execute format('drop policy if exists %I on public.%I', t || ' org self',   t);
    execute format('drop policy if exists %I on public.%I', t || ' org staff read', t);

    -- The learner: only their own rows, only inside their active org. The
    -- WITH CHECK also pins every INSERT/UPDATE to current_org(), so a row can
    -- never be written into a different org than the caller's JWT.
    execute format($f$
      create policy %I on public.%I for all
      using       (user_id = auth.uid() and org_id = public.current_org())
      with check  (user_id = auth.uid() and org_id = public.current_org())
    $f$, t || ' org self', t);

    -- org_admin / instructor: read the whole org's rows (cohort dashboards).
    execute format($f$
      create policy %I on public.%I for select
      using (org_id = public.current_org()
             and public.current_org_role() in ('org_admin','instructor'))
    $f$, t || ' org staff read', t);
  end loop;
end $$;

-- ── 4. Handle uniqueness becomes per-org ────────────────────────────────────
-- Two different colleges may each have a "nightowl". Uniqueness is scoped to
-- the org. (handle_available() still checks globally in Phase 0 — harmlessly
-- stricter; it gains an org_id parameter in Phase 2 enrollment.)
alter table public.profiles drop constraint if exists profiles_handle_key;
create unique index if not exists profiles_org_handle_uidx
  on public.profiles (org_id, lower(handle));

-- ── 5. Org tables — client reads scoped to own org; writes service-role only ─
-- Without this, PostgREST would expose every organization/org_members row to any
-- authenticated user (a cross-tenant leak of names, seats, rosters). Members may
-- READ only their own org; all writes go through the service-role console.
alter table public.organizations enable row level security;
drop policy if exists "organizations read own" on public.organizations;
create policy "organizations read own" on public.organizations
  for select using (id = public.current_org());

alter table public.org_members enable row level security;
drop policy if exists "org_members read own org" on public.org_members;
create policy "org_members read own org" on public.org_members
  for select using (org_id = public.current_org());

-- Invitations are handled entirely by SECURITY DEFINER functions (resolve /
-- signup trigger) and the service-role console — no direct client access.
alter table public.invitations enable row level security;
revoke all on public.invitations from anon, authenticated;

-- ── 6. audit_log stays deny-all-client (0007) — service-role only. ──────────
-- org_id (added in 0010) is used only for per-tenant filtering in the
-- super-admin console, which runs with the service role.

-- ── 6. Verify (run manually, as a signed-in NON-admin user of some org) ─────
-- select count(*) from public.room_progress;                 -- only your org's own rows
-- update public.profiles set org_id = gen_random_uuid();      -- must be a no-op (guard)
-- Attempt to read another org's row by id → expect 0 rows (see tenant_isolation_test.sql).
