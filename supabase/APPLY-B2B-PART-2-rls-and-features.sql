-- ═══════════════════════════════════════════════════════════════════════
-- HACK THE SOC :: APPLY B2B — PART 2 (RLS cut-over + Phases 1-5)
-- Run ONLY AFTER PART 1 is applied, the access-token hook is enabled, and
-- a fresh login shows: select auth.jwt() ->> 'org_id';  → a uuid.
-- Concatenates migrations 0011 → 0015 in order.
-- ═══════════════════════════════════════════════════════════════════════

-- ─────────────────────────────────────────────────────────────────────
-- 0011_multitenancy_rls.sql
-- ─────────────────────────────────────────────────────────────────────
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


-- ─────────────────────────────────────────────────────────────────────
-- 0012_multitenancy_phase1.sql
-- ─────────────────────────────────────────────────────────────────────
-- HACK THE SOC :: 0012 — Multi-tenancy Phase 1 (provisioning + license support)
-- ===========================================================================
-- Server-side support for the super-admin console: the access-token hook now
-- also stamps whether the org's license is currently ACTIVE (so middleware can
-- lock out an expired/suspended college), an ATOMIC seat-capped member-attach
-- function, and an expiry sweep the cron route calls.
--
-- Additive. Run after 0010/0011. Safe to run before the console ships — nothing
-- calls these until the Phase 1 code is deployed. Claude cannot run it.

-- ── 1. Access-token hook — add org_active (supersedes the 0010 version) ─────
-- Same org_id/org_role/is_platform_admin as before, PLUS org_active: true only
-- when the org's status is active/trial AND it hasn't expired. Middleware reads
-- this to redirect a locked-out college to /license instead of showing empty
-- data.
create or replace function public.custom_access_token_hook(event jsonb)
  returns jsonb
  language plpgsql
  stable
as $$
declare
  v_claims jsonb := event->'claims';
  v_org    uuid;
  v_role   text;
  v_status text;
  v_exp    timestamptz;
  v_active boolean := true;
  v_admin  boolean;
begin
  select om.org_id, om.role, o.status, o.expires_at
    into v_org, v_role, v_status, v_exp
  from public.org_members om
  join public.organizations o on o.id = om.org_id
  where om.user_id = (event->>'user_id')::uuid
    and om.status = 'active'
  order by om.joined_at
  limit 1;

  select coalesce(p.is_platform_admin, false) into v_admin
  from public.profiles p
  where p.id = (event->>'user_id')::uuid;

  if v_org is not null then
    v_active := (v_status in ('active','trial')) and (v_exp is null or v_exp > now());
    v_claims := jsonb_set(v_claims, '{org_id}',     to_jsonb(v_org::text));
    v_claims := jsonb_set(v_claims, '{org_role}',   to_jsonb(v_role));
    v_claims := jsonb_set(v_claims, '{org_active}', to_jsonb(v_active));
  end if;
  v_claims := jsonb_set(v_claims, '{is_platform_admin}', to_jsonb(coalesce(v_admin, false)));

  return jsonb_set(event, '{claims}', v_claims);
end;
$$;

grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;

-- ── 2. Atomic, seat-capped member attach ────────────────────────────────────
-- Adds (or re-activates) a member only if a seat is free. seat_limit = 0 means
-- unmetered (the internal org). Runs as definer via the service-role console
-- route; auth.uid() is null there, so the 0011 org_id-freeze guard is skipped
-- and profiles.org_id can be set. Raises 'seat_limit_reached' when full.
create or replace function public.attach_member_if_seat_available(
  p_org uuid, p_user uuid, p_role text
) returns text
  language plpgsql
  security definer set search_path = public
as $$
declare
  v_limit int;
  v_used  int;
begin
  if p_role not in ('org_admin','instructor','student') then
    raise exception 'invalid_role';
  end if;

  select seat_limit into v_limit from public.organizations where id = p_org;
  if v_limit is null then raise exception 'org_not_found'; end if;

  -- Already a member → just update the role, no seat consumed.
  if exists (select 1 from public.org_members where org_id = p_org and user_id = p_user) then
    update public.org_members set role = p_role, status = 'active'
    where org_id = p_org and user_id = p_user;
    update public.profiles set org_id = p_org where id = p_user;
    return 'updated';
  end if;

  select count(*) into v_used from public.org_members
  where org_id = p_org and status = 'active';

  if v_limit > 0 and v_used >= v_limit then
    raise exception 'seat_limit_reached';
  end if;

  insert into public.org_members (org_id, user_id, role, status)
  values (p_org, p_user, p_role, 'active');
  update public.profiles set org_id = p_org where id = p_user;
  return 'added';
end;
$$;

revoke execute on function public.attach_member_if_seat_available(uuid, uuid, text) from anon, authenticated, public;

-- ── 3. Expiry sweep — flip due orgs to 'expired' (called by the cron route) ──
create or replace function public.expire_due_orgs() returns integer
  language plpgsql
  security definer set search_path = public
as $$
declare v_count int;
begin
  update public.organizations
  set status = 'expired'
  where status in ('active','trial')
    and expires_at is not null
    and expires_at < now();
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

revoke execute on function public.expire_due_orgs() from anon, authenticated, public;

-- ── 4. Resolve a user id by email (super-admin member-attach) ───────────────
-- PostgREST does not expose auth.users, so the console route resolves an email
-- to a user id through this definer function (service-role only).
create or replace function public.find_user_id_by_email(p_email text) returns uuid
  language sql
  security definer set search_path = public, auth
as $$
  select id from auth.users where lower(email) = lower(trim(p_email)) limit 1
$$;

revoke execute on function public.find_user_id_by_email(text) from anon, authenticated, public;

-- ── Verify ──────────────────────────────────────────────────────────────────
-- After a fresh login: select auth.jwt() ->> 'org_active';   -- 'true' for an active org
-- select public.expire_due_orgs();                            -- count of orgs just expired


-- ─────────────────────────────────────────────────────────────────────
-- 0013_enrollment.sql
-- ─────────────────────────────────────────────────────────────────────
-- HACK THE SOC :: 0013 — Phase 2 enrollment (self-service onboarding)
-- ===========================================================================
-- Lets students join their college's environment on their own: via an
-- invitation token, or by signing up with an email on the org's allowed domain.
-- The signup trigger resolves the org from those signals (never from raw client
-- input choosing an arbitrary org), enforces the seat cap, and marks the invite
-- accepted. Additive; run after 0010–0012. Claude cannot run it.

-- Email-domain allowlist for auto-assignment (e.g. {'sapir.ac.il'}).
alter table public.organizations
  add column if not exists allowed_domains text[] not null default '{}';

-- A generic class-wide invite link has no specific recipient, so email becomes
-- optional (roster invites still set it).
alter table public.invitations alter column email drop not null;

-- ── Resolve an invitation for the /join page (pre-signup, so anon-callable) ──
-- Returns the org NAME (so the invitee sees who invited them) and validity.
-- Exposing the name by token is fine — you must already hold the token.
create or replace function public.resolve_invitation(p_token text)
returns table (org_id uuid, org_name text, role text, email text, valid boolean)
  language sql
  security definer set search_path = public
  stable
as $$
  select i.org_id, o.name, i.role, i.email,
         (i.accepted_at is null and i.expires_at > now()) as valid
  from public.invitations i
  join public.organizations o on o.id = i.org_id
  where i.token = p_token
$$;

grant execute on function public.resolve_invitation(text) to anon, authenticated;

-- ── Signup trigger — resolve org from invitation token, then domain, then default ─
-- Supersedes 0010's version. Order of precedence:
--   1. a valid invitation_token in the signup metadata → its org + role,
--   2. else the email's domain matches an org's allowed_domains → that org, student,
--   3. else the bootstrap/internal org.
-- Seat cap is enforced: a token to a FULL org fails the signup (explicit intent);
-- a domain match to a full org falls back to the internal org rather than block.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  chosen        text;
  full_name     text;
  base_handle   text;
  final_handle  text;
  display       text;
  v_org         uuid := 'd0d0d0d0-0000-4000-8000-000000000000';
  v_role        text := 'student';
  v_token       text;
  v_inv         record;
  v_match       uuid;
  v_domain      text;
  v_limit       int;
  v_used        int;
  v_from_token  boolean := false;
begin
  chosen    := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));
  full_name := trim(coalesce(new.raw_user_meta_data->>'full_name', ''));
  v_token   := trim(coalesce(new.raw_user_meta_data->>'invitation_token', ''));
  if length(full_name) > 60 then full_name := substr(full_name, 1, 60); end if;

  -- 1. Invitation token
  if v_token <> '' then
    select * into v_inv from public.invitations
    where token = v_token and accepted_at is null and expires_at > now();
    if found then
      v_org := v_inv.org_id;
      v_role := v_inv.role;
      v_from_token := true;
      update public.invitations set accepted_at = now() where id = v_inv.id;
    end if;
  end if;

  -- 2. Domain allowlist (only if not already resolved via a token)
  if not v_from_token then
    v_domain := lower(split_part(new.email, '@', 2));
    if v_domain <> '' then
      select id into v_match from public.organizations
      where v_domain = any(allowed_domains) and status in ('active','trial')
      order by created_at limit 1;
      if v_match is not null then v_org := v_match; v_role := 'student'; end if;
    end if;
  end if;

  -- Seat cap (0 = unmetered internal org)
  select seat_limit into v_limit from public.organizations where id = v_org;
  if coalesce(v_limit, 0) > 0 then
    select count(*) into v_used from public.org_members where org_id = v_org and status = 'active';
    if v_used >= v_limit then
      if v_from_token then
        raise exception 'seat_limit_reached';           -- explicit invite → fail clearly
      else
        v_org := 'd0d0d0d0-0000-4000-8000-000000000000'; -- domain match full → fall back
        v_role := 'student';
      end if;
    end if;
  end if;

  -- Handle
  if chosen <> '' and public.handle_available(chosen) then
    final_handle := chosen;
  else
    base_handle := lower(regexp_replace(split_part(new.email, '@', 1), '[^a-zA-Z0-9_]', '', 'g'));
    if base_handle is null or base_handle = '' then base_handle := 'analyst'; end if;
    final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);
  end if;

  display := coalesce(nullif(full_name, ''), nullif(chosen, ''), split_part(new.email, '@', 1));

  insert into public.profiles (id, handle, display_name, org_id)
  values (new.id, final_handle, display, v_org)
  on conflict (id) do nothing;

  insert into public.org_members (org_id, user_id, role, status)
  values (v_org, new.id, v_role, 'active')
  on conflict (org_id, user_id) do nothing;

  insert into public.user_progress (user_id, org_id)
  values (new.id, v_org)
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── Verify ──────────────────────────────────────────────────────────────────
-- select * from public.resolve_invitation('<token>');   -- org_name + valid=true
-- Sign up with metadata { invitation_token: '<token>' } → the new profile lands in that org.


-- ─────────────────────────────────────────────────────────────────────
-- 0014_branding.sql
-- ─────────────────────────────────────────────────────────────────────
-- HACK THE SOC :: 0014 — Phase 4 per-tenant branding
-- ===========================================================================
-- Adds the org NAME to the access-token claims so the app can show "<College>"
-- in the top bar and print it on rank certificates without an extra fetch. The
-- richer branding (accent colour, logo URL) lives in organizations.branding
-- (already present since 0010) and is fetched on demand — too large for a JWT.
-- Additive. Run after 0010–0013. Claude cannot run it.

create or replace function public.custom_access_token_hook(event jsonb)
  returns jsonb
  language plpgsql
  stable
as $$
declare
  v_claims jsonb := event->'claims';
  v_org    uuid;
  v_name   text;
  v_role   text;
  v_status text;
  v_exp    timestamptz;
  v_active boolean := true;
  v_admin  boolean;
begin
  select om.org_id, om.role, o.name, o.status, o.expires_at
    into v_org, v_role, v_name, v_status, v_exp
  from public.org_members om
  join public.organizations o on o.id = om.org_id
  where om.user_id = (event->>'user_id')::uuid
    and om.status = 'active'
  order by om.joined_at
  limit 1;

  select coalesce(p.is_platform_admin, false) into v_admin
  from public.profiles p
  where p.id = (event->>'user_id')::uuid;

  if v_org is not null then
    v_active := (v_status in ('active','trial')) and (v_exp is null or v_exp > now());
    v_claims := jsonb_set(v_claims, '{org_id}',     to_jsonb(v_org::text));
    v_claims := jsonb_set(v_claims, '{org_role}',   to_jsonb(v_role));
    v_claims := jsonb_set(v_claims, '{org_name}',   to_jsonb(coalesce(v_name, '')));
    v_claims := jsonb_set(v_claims, '{org_active}', to_jsonb(v_active));
  end if;
  v_claims := jsonb_set(v_claims, '{is_platform_admin}', to_jsonb(coalesce(v_admin, false)));

  return jsonb_set(event, '{claims}', v_claims);
end;
$$;

grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;

-- ── Verify ──────────────────────────────────────────────────────────────────
-- After a fresh login: select auth.jwt() ->> 'org_name';


-- ─────────────────────────────────────────────────────────────────────
-- 0015_hardening.sql
-- ─────────────────────────────────────────────────────────────────────
-- HACK THE SOC :: 0015 — Phase 5 hardening
-- ===========================================================================
-- 1. Drop the speculative 0001 tables the app never used (they carry RLS and
--    attack surface for no benefit — verified unreferenced in src/).
-- 2. purge_org(): atomic offboarding — delete a college's learner data, re-home
--    its accounts to the internal org (so logins survive), then delete the org.
-- Run after 0010–0014, and AFTER exporting any org you intend to purge. Claude
-- cannot run it.

-- ── 1. Remove unused scaffold (app uses only the 0002 tables + profiles) ────
drop view  if exists public.leaderboard cascade;
drop table if exists public.ai_messages          cascade;
drop table if exists public.ai_conversations     cascade;
drop table if exists public.xp_events            cascade;
drop table if exists public.user_badges          cascade;
drop table if exists public.badges               cascade;
drop table if exists public.detections           cascade;
drop table if exists public.hunts                cascade;
drop table if exists public.investigation_notes  cascade;
drop table if exists public.investigations       cascade;
drop table if exists public.telemetry_events     cascade;
drop table if exists public.alerts               cascade;
drop table if exists public.scenario_runs        cascade;
drop table if exists public.lesson_progress      cascade;
drop table if exists public.lessons              cascade;
drop table if exists public.modules              cascade;
drop table if exists public.learning_paths       cascade;
drop table if exists public.scenarios            cascade;   -- 0001 reference table; app scenarios live in code

-- ── 2. Atomic org offboarding ───────────────────────────────────────────────
create or replace function public.purge_org(p_org uuid) returns void
  language plpgsql
  security definer set search_path = public
as $$
begin
  if p_org = 'd0d0d0d0-0000-4000-8000-000000000000' then
    raise exception 'cannot_purge_internal';
  end if;

  delete from public.room_progress     where org_id = p_org;
  delete from public.dashboard_sessions where org_id = p_org;
  delete from public.scenario_history   where org_id = p_org;
  delete from public.ai_usage           where org_id = p_org;
  delete from public.user_progress      where org_id = p_org;

  -- Re-home the accounts to the internal org so their NOT NULL org_id FK stays
  -- valid and they can still sign in (as unaffiliated users) after the college
  -- leaves. Their college progress above is gone (export first).
  update public.profiles set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id = p_org;

  delete from public.org_members  where org_id = p_org;
  delete from public.invitations  where org_id = p_org;
  delete from public.organizations where id = p_org;
end;
$$;

revoke execute on function public.purge_org(uuid) from anon, authenticated, public;

-- ── Verify ──────────────────────────────────────────────────────────────────
-- select count(*) from information_schema.tables where table_name = 'ai_messages'; -- 0

