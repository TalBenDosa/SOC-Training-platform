-- HACK THE SOC :: 0016 — Backend security-audit fixes
-- ===========================================================================
-- Closes the gaps found by the end-to-end backend audit (see
-- docs/backend-e2e-audit.md). Every item here was CONFIRMED by running the
-- real migrations in PGlite (scripts/test-backend-e2e.mjs), not just reviewed.
--
-- SAFETY: idempotent, additive, no data loss. `create or replace function`
-- swaps bodies without touching triggers. Review on the live project, then run.
-- Claude cannot run this — deliver to Tal to paste-and-run in the SQL editor.
--
-- Ordered by severity: C1 (critical) → H1 → M3 → M1/M2 → H2 → L1/L2.
-- ===========================================================================

-- ── C1 (CRITICAL) — leaderboard view leaked every user in every org ─────────
-- A PG15+ view defaults to security_invoker=OFF, so `public.leaderboard` ran as
-- its owner and bypassed the profiles RLS; Supabase's default grants let even
-- anon SELECT it. CONFIRMED: anon read returned cross-org rows (id + handle).
-- The view is unused by the app (0004 locked profiles to owner-only precisely to
-- stop enumeration). 0015 would drop it, but 0015 is deferred — drop it now.
drop view if exists public.leaderboard;

-- ── H1 (HIGH) — 0001 content tables had no RLS + intact anon DML grants ──────
-- learning_paths / modules / lessons / scenarios / badges never had RLS enabled
-- and kept their default anon/authenticated grants. CONFIRMED: RLS=false and an
-- anon INSERT passed the permission gate (failed only on NOT NULL). They are
-- app-unused (the app reads src/data/*), so lock them down. Guarded with
-- to_regclass so this is a no-op once 0015 eventually drops the tables.
do $$
declare t text;
begin
  foreach t in array array['learning_paths','modules','lessons','scenarios','badges'] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
      execute format('revoke all on public.%I from anon, authenticated', t);
    end if;
  end loop;
end $$;

-- ── M3 (MEDIUM) — any student could read the full org roster via org_members ──
-- The old policy was `using (org_id = current_org())` with no role gate, so a
-- student could enumerate every classmate's user_id + role. Tighten to match the
-- profiles policy: org staff read the whole roster; a student reads only their
-- own membership row. (The hook and the org-admin console read org_members via
-- SECURITY DEFINER / service-role, so both bypass RLS and are unaffected.)
drop policy if exists "org_members read own org" on public.org_members;
create policy "org_members read own org" on public.org_members
  for select using (
    org_id = public.current_org()
    and (public.current_org_role() in ('org_admin','instructor') or user_id = auth.uid())
  );

-- ── M1 + M2 (MEDIUM) — seat-cap race + reactivation bypass ───────────────────
-- M1: count-then-insert with no lock → concurrent signups to the same org can
--     both pass the check and overflow seat_limit. Take a row lock on the org
--     first so seat accounting serialises.
-- M2: the "already a member" branch flipped status to 'active' with NO seat
--     check → a previously-removed member could be re-added to a full org.
create or replace function public.attach_member_if_seat_available(
  p_org uuid, p_user uuid, p_role text
) returns text
  language plpgsql
  security definer set search_path = public
as $$
declare
  v_limit    int;
  v_used     int;
  v_existing text;
begin
  if p_role not in ('org_admin','instructor','student') then
    raise exception 'invalid_role';
  end if;

  -- M1: serialise seat accounting for this org across concurrent callers.
  perform 1 from public.organizations where id = p_org for update;
  select seat_limit into v_limit from public.organizations where id = p_org;
  if v_limit is null then raise exception 'org_not_found'; end if;

  select status into v_existing from public.org_members
  where org_id = p_org and user_id = p_user;

  if found then
    -- M2: reactivating a non-active member consumes a seat again → re-check cap.
    if v_existing <> 'active' and v_limit > 0 then
      select count(*) into v_used from public.org_members
      where org_id = p_org and status = 'active';
      if v_used >= v_limit then raise exception 'seat_limit_reached'; end if;
    end if;
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

-- M1 (signup path): the trigger has the same count-then-insert race when a class
-- hits one invite link / domain at once. Recreate with the same org row lock.
-- (Body identical to 0013 except the `for update` lock before the seat check.)
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

  -- Seat cap (0 = unmetered internal org). M1: lock the org row first so
  -- concurrent signups to the same org can't both slip past the count.
  perform 1 from public.organizations where id = v_org for update;
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

-- ── H2 (LOW/latent) — purge_org couldn't delete an org that had audit_log rows ─
-- audit_log.org_id references organizations with ON DELETE NO ACTION, and
-- purge_org never cleared it → the terminal DELETE raises foreign_key_violation
-- and the whole purge rolls back. NOT triggerable today (logAudit never stamps a
-- tenant org_id — rows default to the internal org, which purge refuses anyway),
-- but the moment audit gains a real org dimension, offboarding breaks. Re-home
-- audit rows to NULL (the column is nullable) before deleting the org, so the
-- audit record survives without a dangling tenant reference.
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

  -- Preserve the audit trail but drop the tenant FK (nullable) so the org delete
  -- below can't be blocked by audit_log_org_id_fkey.
  update public.audit_log set org_id = null where org_id = p_org;

  -- Re-home the accounts to the internal org so their NOT NULL org_id FK stays
  -- valid and they can still sign in after the college leaves.
  update public.profiles set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id = p_org;

  delete from public.org_members  where org_id = p_org;
  delete from public.invitations  where org_id = p_org;
  delete from public.organizations where id = p_org;
end;
$$;
revoke execute on function public.purge_org(uuid) from anon, authenticated, public;

-- ── L1 (LOW) — defense-in-depth grant for the access-token hook ──────────────
-- The final hook (0014) joins organizations; it works today only because it's
-- SECURITY DEFINER (runs as owner). Grant SELECT so token issuance still works
-- if anyone ever reverts the hook to INVOKER.
grant select on public.organizations to supabase_auth_admin;

-- ── L2 (LOW) — pin search_path on the RLS/guard helpers ──────────────────────
-- These run inside every RLS check / profile UPDATE; fix their search_path to
-- match the rest of the codebase and remove a future footgun. Bodies unchanged.
create or replace function public.current_org() returns uuid
  language sql stable set search_path = public as $$
  select nullif(auth.jwt() ->> 'org_id', '')::uuid
$$;

create or replace function public.current_org_role() returns text
  language sql stable set search_path = public as $$
  select auth.jwt() ->> 'org_role'
$$;

create or replace function public.guard_profile_privileged_columns()
returns trigger
language plpgsql set search_path = public
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

-- ── Verify (run after applying) ──────────────────────────────────────────────
-- select to_regclass('public.leaderboard');                          -- NULL (dropped)
-- select relrowsecurity from pg_class where relname='scenarios';     -- t
-- select public.purge_org('<test-org-with-audit-rows>');             -- succeeds
