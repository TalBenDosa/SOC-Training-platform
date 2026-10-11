-- HACK THE SOC :: 0029 — students enter via affiliation code ONLY
-- ===========================================================================
-- 0028 closed open signup but left one student door that bypasses the class
-- code: GENERIC student invitations (email is null — the 0013 "class link"
-- shape). Worse, org provisioning auto-created one per org with a licence-long
-- lifetime, so every college had a standing year-long bypass link.
--
-- Tal's model, stated twice and now enforced everywhere: each environment has
-- its own affiliation code; the admin distributes it; THAT is how students
-- join. Invitation links remain for NAMED people (org admins, instructors,
-- and email-bound roster invites) — a link addressed to a specific person is
-- an admin's explicit act, not an anonymous door.
--
-- Three layers close here:
--   SQL (this file): the trigger rejects generic student invitations, and all
--     outstanding ones are expired.
--   API: org provisioning stops minting the standing class link.
--   UI: the class-link generators are gone; the code takes their place.

-- 1. Expire every outstanding generic student invitation, including the
--    auto-minted per-org ones. Named invites and admin invites are untouched.
update public.invitations
set expires_at = now()
where role = 'student'
  and email is null
  and accepted_at is null
  and expires_at > now();

-- 2. Trigger: a generic student invitation is no longer honoured even if a
--    token survives somewhere (a forwarded link, an old screenshot). Distinct
--    error so the UI can say "ask for today's class code" rather than a
--    generic invalid-invite message.
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

  -- 1. Invitation token — NAMED people and staff roles.
  if v_token <> '' then
    select * into v_inv from public.invitations
    where token = v_token and accepted_at is null and expires_at > now();
    if not found then
      raise exception 'invitation_invalid';
    end if;

    -- 0029: a student-role invitation must name its recipient. The anonymous
    -- class-link shape is the code's job now.
    if v_inv.role = 'student' and v_inv.email is null then
      raise exception 'student_invite_requires_code';
    end if;

    if v_inv.email is not null
       and lower(trim(v_inv.email)) <> lower(trim(coalesce(new.email, ''))) then
      raise exception 'invitation_email_mismatch';
    end if;
    v_org := v_inv.org_id;
    v_role := v_inv.role;
    update public.invitations set accepted_at = now() where id = v_inv.id;

  -- 2. Org affiliation code — the student path.
  elsif v_code <> '' then
    select * into v_oc from public.org_codes
    where upper(trim(code)) = upper(v_code) and expires_at > now();
    if not found then
      raise exception 'org_code_invalid';
    end if;
    perform 1 from public.organizations
    where id = v_oc.org_id and status in ('active', 'trial');
    if not found then
      raise exception 'org_code_invalid';
    end if;
    v_org := v_oc.org_id;
    v_role := 'student';

  -- 3. Neither → registration is closed.
  else
    raise exception 'signup_requires_code';
  end if;

  if v_role = 'student' then
    v_affil := now() + interval '100 days';
  end if;

  perform 1 from public.organizations where id = v_org for update;
  select seat_limit into v_limit from public.organizations where id = v_org;
  if coalesce(v_limit, 0) > 0 then
    select count(*) into v_used from public.org_members where org_id = v_org and status = 'active';
    if v_used >= v_limit then
      raise exception 'seat_limit_reached';
    end if;
  end if;

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
-- 1. select count(*) from invitations where role='student' and email is null
--      and expires_at > now();                          -- must be 0
-- 2. Sign up with a surviving generic student token → student_invite_requires_code.
-- 3. Named student invite (email set, matching) → still enrolls.
-- 4. org_admin invite → unchanged.
