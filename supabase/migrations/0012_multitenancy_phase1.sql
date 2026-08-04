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
