-- ═══════════════════════════════════════════════════════════════════════
-- HACK THE SOC :: APPLY B2B — PART 1 (Foundations)
-- Paste-and-run in the Supabase SQL editor. This is migration 0010:
-- additive only (org tables, org_id + backfill, the access-token hook
-- function, org-assigning trigger). It does NOT change RLS, so the app
-- keeps working. After running: enable the hook in the dashboard, verify
-- the JWT carries org_id, THEN run PART 2.
-- ═══════════════════════════════════════════════════════════════════════

-- HACK THE SOC :: 0010 — Multi-tenancy foundations (ADDITIVE, non-breaking)
-- ===========================================================================
-- Phase 0, part 1 of 2. This migration is DELIBERATELY additive: it creates the
-- org model, adds an org_id to every per-tenant table (with a DEFAULT so the
-- running app does not break the instant NOT NULL lands), backfills existing
-- data into a single "Internal" org, installs the JWT org-claim hook function,
-- and updates the signup trigger to assign an org. It does NOT touch RLS — the
-- existing `auth.uid() = user_id` policies stay in force, so the app keeps
-- working exactly as before while this lands.
--
-- The RLS cut-over lives in 0011, run ONLY AFTER the access-token hook is
-- enabled in the dashboard and a fresh login is confirmed to carry `org_id`.
-- See docs/phase-0-plan.md for the exact execution order.
--
-- SAFETY: idempotent (if-exists / if-not-exists throughout). Review on STAGING
-- before production. Claude cannot run this — it is delivered to be run by Tal.

-- Sentinel id for the bootstrap org that all existing users are migrated into.
-- (A fixed uuid so later statements can reference it without a lookup.)
--   Internal / Default org = 'd0d0d0d0-0000-4000-8000-000000000000'

-- ── 1. Org model ────────────────────────────────────────────────────────────
create table if not exists public.organizations (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  slug        text not null unique,
  seat_limit  integer not null default 0,          -- 0 = unmetered (internal)
  starts_at   timestamptz,
  expires_at  timestamptz,                          -- null = no expiry
  status      text not null default 'trial'
              check (status in ('trial','active','suspended','expired')),
  branding    jsonb not null default '{}'::jsonb,   -- logo/color (Phase 4)
  created_at  timestamptz not null default now()
);

create table if not exists public.org_members (
  org_id    uuid not null references public.organizations(id) on delete cascade,
  user_id   uuid not null references auth.users(id) on delete cascade,
  role      text not null default 'student'
            check (role in ('org_admin','instructor','student')),
  status    text not null default 'active'
            check (status in ('active','invited','removed')),
  joined_at timestamptz not null default now(),
  primary key (org_id, user_id)
);
create index if not exists org_members_user_idx on public.org_members (user_id);

create table if not exists public.invitations (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations(id) on delete cascade,
  email       text not null,
  role        text not null default 'student' check (role in ('org_admin','instructor','student')),
  token       text not null unique,
  expires_at  timestamptz not null,
  accepted_at timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists invitations_org_idx on public.invitations (org_id);

-- Seed the bootstrap org (unmetered, active) that existing users migrate into.
insert into public.organizations (id, name, slug, seat_limit, status, starts_at)
values ('d0d0d0d0-0000-4000-8000-000000000000', 'Internal / Default', 'internal', 0, 'active', now())
on conflict (id) do nothing;

-- ── 2. Platform-admin flag (super-admin is NOT an org role) ──────────────────
alter table public.profiles add column if not exists is_platform_admin boolean not null default false;
-- Tal is the platform super-admin.
update public.profiles set is_platform_admin = true
where id = 'd0b9928b-1d0a-4635-95b4-de70c4f1329a';

-- ── 3. Add org_id to every per-tenant table ─────────────────────────────────
-- DEFAULT bootstrap-org so inserts from the not-yet-updated app keep working
-- the moment NOT NULL is enforced. 0011's RLS WITH CHECK (org_id = current_org())
-- makes this default harmless once the cut-over lands: a real tenant user whose
-- current_org differs from the default is REJECTED, forcing the app to set it.
-- Drop the default in Phase 1 once the app reliably sets org_id.
do $$
declare t text;
begin
  foreach t in array array[
    'profiles','user_progress','room_progress','dashboard_sessions','scenario_history','ai_usage','audit_log'
  ] loop
    execute format(
      'alter table public.%I add column if not exists org_id uuid '
      || 'references public.organizations(id) default ''d0d0d0d0-0000-4000-8000-000000000000''', t);
  end loop;
end $$;

-- ── 4. Backfill existing rows into the bootstrap org ────────────────────────
update public.profiles          set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.user_progress     set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.room_progress     set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.dashboard_sessions set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.scenario_history  set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.ai_usage          set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;
update public.audit_log         set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id is null;

-- Backfill org_members from existing profiles (platform admins → org_admin).
insert into public.org_members (org_id, user_id, role, status)
select 'd0d0d0d0-0000-4000-8000-000000000000', id,
       case when is_platform_admin then 'org_admin' else 'student' end, 'active'
from public.profiles
on conflict (org_id, user_id) do nothing;

-- Enforce NOT NULL on the learner tables (audit_log stays nullable — some
-- system events have no org context).
alter table public.profiles           alter column org_id set not null;
alter table public.user_progress       alter column org_id set not null;
alter table public.room_progress       alter column org_id set not null;
alter table public.dashboard_sessions  alter column org_id set not null;
alter table public.scenario_history    alter column org_id set not null;
alter table public.ai_usage            alter column org_id set not null;

-- ── 5. Indexes for RLS performance (org_id first) ───────────────────────────
create index if not exists profiles_org_idx           on public.profiles (org_id);
create index if not exists user_progress_org_idx       on public.user_progress (org_id, user_id);
create index if not exists room_progress_org_idx        on public.room_progress (org_id, user_id);
create index if not exists dashboard_sessions_org_idx   on public.dashboard_sessions (org_id, user_id);
create index if not exists scenario_history_org_idx     on public.scenario_history (org_id, user_id);
create index if not exists ai_usage_org_idx             on public.ai_usage (org_id, user_id);
create index if not exists audit_log_org_idx            on public.audit_log (org_id);

-- ── 6. JWT-claim helpers (read the org context set by the access-token hook) ─
create or replace function public.current_org() returns uuid
  language sql stable as $$
  select nullif(auth.jwt() ->> 'org_id', '')::uuid
$$;

create or replace function public.current_org_role() returns text
  language sql stable as $$
  select auth.jwt() ->> 'org_role'
$$;

-- ── 7. Custom Access Token Hook — injects org_id/org_role/is_platform_admin ──
-- Supabase calls this on every access-token issuance/refresh. It reads the
-- user's ACTIVE org membership and stamps the claims the RLS policies rely on.
-- MUST be enabled in the dashboard (Auth ▸ Hooks ▸ Custom Access Token) AFTER
-- this migration and verified BEFORE running 0011. See the runbook.
create or replace function public.custom_access_token_hook(event jsonb)
  returns jsonb
  language plpgsql
  stable
as $$
declare
  v_claims jsonb := event->'claims';
  v_org    uuid;
  v_role   text;
  v_admin  boolean;
begin
  -- One org per user in Phase 0; the earliest active membership wins. Phase 2's
  -- multi-org users will pick an "active org" here.
  select om.org_id, om.role into v_org, v_role
  from public.org_members om
  where om.user_id = (event->>'user_id')::uuid
    and om.status = 'active'
  order by om.joined_at
  limit 1;

  select coalesce(p.is_platform_admin, false) into v_admin
  from public.profiles p
  where p.id = (event->>'user_id')::uuid;

  if v_org is not null then
    v_claims := jsonb_set(v_claims, '{org_id}',   to_jsonb(v_org::text));
    v_claims := jsonb_set(v_claims, '{org_role}', to_jsonb(v_role));
  end if;
  v_claims := jsonb_set(v_claims, '{is_platform_admin}', to_jsonb(coalesce(v_admin, false)));

  return jsonb_set(event, '{claims}', v_claims);
end;
$$;

-- The auth server (supabase_auth_admin) must be able to run the hook and read
-- the tables it needs; no one else should be able to invoke it.
grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;
grant usage on schema public to supabase_auth_admin;
grant select on public.org_members, public.profiles to supabase_auth_admin;

-- ── 8. Signup trigger — assign an org so new accounts are never orphaned ─────
-- Supersedes 0009's handle_new_user(). Same handle/full-name logic; adds org
-- assignment. In Phase 0 there is no enrollment yet, so a fresh signup joins the
-- bootstrap org as a student. Phase 2 replaces this branch with invitation-based
-- org resolution (reads org_id + role from a validated invitation token).
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  chosen       text;
  full_name    text;
  base_handle  text;
  final_handle text;
  display      text;
  v_org        uuid := 'd0d0d0d0-0000-4000-8000-000000000000';  -- Phase 2: from invitation
begin
  chosen    := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));
  full_name := trim(coalesce(new.raw_user_meta_data->>'full_name', ''));
  if length(full_name) > 60 then full_name := substr(full_name, 1, 60); end if;

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
  values (v_org, new.id, 'student', 'active')
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

-- ── 9. Verify (run manually after applying) ─────────────────────────────────
-- select count(*) from public.organizations;                      -- >= 1
-- select count(*) filter (where org_id is null) from public.profiles; -- 0
-- select id, is_platform_admin from public.profiles where id = 'd0b9928b-1d0a-4635-95b4-de70c4f1329a'; -- true
-- After enabling the hook + a FRESH login:
--   select auth.jwt() ->> 'org_id';   -- should return the bootstrap org uuid
