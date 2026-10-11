-- HACK THE SOC :: 0028 — org affiliation codes: the new student entry model
-- ===========================================================================
-- Spec (Tal, 2026-08-11), implemented exactly:
--
--   * The super-admin provisions a college and names its admin. The admin gets
--     ONE emailed /join?token link (existing flow, unchanged by this file).
--   * The ORG ADMIN can generate an org affiliation code (קוד שיוך). A student
--     registers with their email + that code. WITHOUT A CODE (or an explicit
--     invitation link) THERE IS NO WAY TO REGISTER — open signup is closed.
--   * A code is usable for 24 HOURS from generation; the admin can generate a
--     fresh one each day (rate-limited in the API, not here).
--   * The AFFILIATION a code grants lasts 100 DAYS. After that the student
--     must enter a then-current code to renew — enforced by the app gate
--     reading org_members.affiliation_expires_at.
--   * The super-admin sees every org's codes and can generate for any org.
--
-- CONSEQUENCE, deliberate: the domain-allowlist auto-enrollment path and the
-- "fall through to the internal org" default are REMOVED from handle_new_user.
-- Both admitted students without a code, which the spec forbids ("ללא קוד לא
-- תהיה אפשרות להיכנס"). Existing accounts are untouched — this governs NEW
-- signups only.

-- ── 1. The codes themselves ─────────────────────────────────────────────────
create table if not exists public.org_codes (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid not null references public.organizations(id) on delete cascade,
  -- Stored uppercase; compared uppercase+trimmed in the trigger, so students
  -- can type it sloppily. 8 chars from an unambiguous alphabet (API-side).
  code        text not null unique,
  created_by  uuid references public.profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  -- The 24-hour usable window. Generating a new code expires the previous one
  -- early (API does that), so at most one code per org is ever live.
  expires_at  timestamptz not null default now() + interval '24 hours'
);

create index if not exists org_codes_org_active
  on public.org_codes (org_id, expires_at desc);

alter table public.org_codes enable row level security;

-- The org's admins/instructors may READ their own org's codes (to display in
-- /manage). Nobody writes from the client: generation is a service-role API
-- operation, where the 24h rate limit and the revoke-previous step live.
drop policy if exists org_codes_select_admin on public.org_codes;
create policy org_codes_select_admin on public.org_codes
  for select to authenticated
  using (
    exists (
      select 1 from public.org_members m
      where m.org_id = org_codes.org_id
        and m.user_id = auth.uid()
        and m.role in ('org_admin', 'instructor')
        and m.status = 'active'
    )
  );
revoke insert, update, delete on public.org_codes from authenticated, anon;

-- ── 2. The 100-day affiliation clock ────────────────────────────────────────
alter table public.org_members
  add column if not exists affiliation_expires_at timestamptz;

-- Existing STUDENTS start a fresh 100-day clock at migration time — they never
-- entered a code, and expiring them retroactively would lock out every current
-- class the moment this lands. Admins/instructors have no clock (null).
update public.org_members
set affiliation_expires_at = now() + interval '100 days'
where role = 'student'
  and affiliation_expires_at is null
  and org_id <> 'd0d0d0d0-0000-4000-8000-000000000000';

-- ── 3. Renewal (SECURITY DEFINER, called via API with the user's id) ────────
-- Same-org only: a code from another college cannot be used to hop tenants
-- through the renewal door — transfers stay a super-admin operation.
create or replace function public.renew_affiliation(p_user uuid, p_code text)
returns void
language plpgsql
security definer set search_path = public
as $$
declare
  v_member record;
  v_code   record;
begin
  select * into v_member from public.org_members
  where user_id = p_user and status = 'active' and role = 'student'
  limit 1;
  if not found then
    raise exception 'not_an_org_student';
  end if;

  select * into v_code from public.org_codes
  where upper(trim(code)) = upper(trim(p_code)) and expires_at > now();
  if not found then
    raise exception 'org_code_invalid';
  end if;
  if v_code.org_id <> v_member.org_id then
    raise exception 'org_code_wrong_org';
  end if;

  update public.org_members
  set affiliation_expires_at = now() + interval '100 days'
  where org_id = v_member.org_id and user_id = p_user;
end;
$$;
revoke execute on function public.renew_affiliation(uuid, text) from anon, authenticated, public;

-- ── 4. handle_new_user: code-or-invitation, nothing else ────────────────────
-- Supersedes 0026. The invitation-token path (email binding, loud failures)
-- and the seat-cap locking are carried over verbatim; the domain allowlist and
-- the internal-org fallback are removed per the spec note above.
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
  v_org         uuid;
  v_role        text := 'student';
  v_token       text;
  v_code        text;
  v_inv         record;
  v_oc          record;
  v_limit       int;
  v_used        int;
  v_affil       timestamptz := null;
begin
  chosen    := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));
  full_name := trim(coalesce(new.raw_user_meta_data->>'full_name', ''));
  v_token   := trim(coalesce(new.raw_user_meta_data->>'invitation_token', ''));
  v_code    := trim(coalesce(new.raw_user_meta_data->>'org_code', ''));
  if length(full_name) > 60 then full_name := substr(full_name, 1, 60); end if;

  -- 1. Invitation token (org-admin links, roster invites) — verbatim from 0026.
  if v_token <> '' then
    select * into v_inv from public.invitations
    where token = v_token and accepted_at is null and expires_at > now();
    if not found then
      raise exception 'invitation_invalid';
    end if;
    if v_inv.email is not null
       and lower(trim(v_inv.email)) <> lower(trim(coalesce(new.email, ''))) then
      raise exception 'invitation_email_mismatch';
    end if;
    v_org := v_inv.org_id;
    v_role := v_inv.role;
    update public.invitations set accepted_at = now() where id = v_inv.id;

  -- 2. Org affiliation code (the student path).
  elsif v_code <> '' then
    select * into v_oc from public.org_codes
    where upper(trim(code)) = upper(v_code) and expires_at > now();
    if not found then
      raise exception 'org_code_invalid';
    end if;
    perform 1 from public.organizations
    where id = v_oc.org_id and status in ('active', 'trial');
    if not found then
      raise exception 'org_code_invalid';   -- org suspended/expired → same outward error
    end if;
    v_org := v_oc.org_id;
    v_role := 'student';

  -- 3. Neither → registration is closed. This is the line that closes open
  --    signup; the UI maps it to "you need an invitation or a class code".
  else
    raise exception 'signup_requires_code';
  end if;

  -- Students carry the 100-day affiliation clock regardless of entry door, so
  -- a roster-invited student renews on the same cycle as a code-joined one.
  if v_role = 'student' then
    v_affil := now() + interval '100 days';
  end if;

  -- Seat cap (0 = unmetered). Lock the org row so concurrent signups can't
  -- both slip past the count — carried from 0016/0026.
  perform 1 from public.organizations where id = v_org for update;
  select seat_limit into v_limit from public.organizations where id = v_org;
  if coalesce(v_limit, 0) > 0 then
    select count(*) into v_used from public.org_members where org_id = v_org and status = 'active';
    if v_used >= v_limit then
      raise exception 'seat_limit_reached';
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

  insert into public.org_members (org_id, user_id, role, status, affiliation_expires_at)
  values (v_org, new.id, v_role, 'active', v_affil)
  on conflict (org_id, user_id) do nothing;

  insert into public.user_progress (user_id, org_id)
  values (new.id, v_org)
  on conflict (user_id) do nothing;

  return new;
end;
$$;

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. No code, no token → signup RAISES signup_requires_code.
-- 2. insert into org_codes (org_id, code) values ('<org>', 'TESTCODE');
--    signup with metadata {org_code:'testcode '} (sloppy case/space) → joins
--    <org> as student, org_members.affiliation_expires_at ≈ now()+100 days.
-- 3. update org_codes set expires_at = now() - interval '1 minute' where code='TESTCODE';
--    signup with it → RAISES org_code_invalid.
-- 4. select renew_affiliation('<user>', '<current code>') → clock resets;
--    with another org's code → RAISES org_code_wrong_org.
