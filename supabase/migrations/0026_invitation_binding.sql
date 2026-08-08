-- HACK THE SOC :: 0026 — bind an invitation to the person it was issued to
-- ===========================================================================
-- Two problems with enrollment, both found while wiring the student invite flow.
--
-- 1. AN INVITE WAS NOT BOUND TO ITS RECIPIENT.
--    handle_new_user() accepted any non-expired token regardless of who was
--    signing up:
--        select * from invitations where token = v_token and accepted_at is null
--    A roster invite issued to student@college.ac.il could therefore be
--    redeemed by ANYONE who obtained the link — a forwarded email, a shared
--    class chat, a screenshot — using any address they liked. They would land
--    inside that college's tenant, consume one of its paid seats, and appear on
--    its roster and leaderboard. For a per-seat B2B product sold to colleges
--    that is both a security and a billing problem.
--
--    Fixed below: when an invitation names an email, the signup email must
--    match it (case-insensitively, trimmed). A generic class-wide link
--    (email is null — see 0013) keeps working for anyone, which is the whole
--    point of that shape.
--
-- 2. A BAD TOKEN FAILED SILENTLY.
--    If the token was expired, already accepted, or simply wrong, the `if
--    found` branch was skipped and the trigger fell through to the domain
--    allowlist and then to the internal default org. The student saw a normal
--    "account created" screen and only discovered later that they were not in
--    their college's course at all — no error, nothing to act on, and an
--    org-admin left wondering why their student never appeared.
--
--    Fixed below: supplying a token that cannot be honoured now RAISES, so the
--    signup fails loudly and the UI can tell them to ask for a fresh link.
--    Supplying NO token is unchanged (domain allowlist, then default org).
--
-- Supersedes 0016's handle_new_user(). Everything else in that function —
-- seat-cap locking (M1), handle generation, display name, the profiles /
-- org_members / user_progress inserts — is carried over verbatim.

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

  -- 1. Invitation token ------------------------------------------------------
  if v_token <> '' then
    select * into v_inv from public.invitations
    where token = v_token and accepted_at is null and expires_at > now();

    -- A token was explicitly presented but is wrong/expired/already used.
    -- Fail loudly (see note 2 above) instead of quietly enrolling them nowhere.
    if not found then
      raise exception 'invitation_invalid';
    end if;

    -- Bind the invite to its recipient (see note 1 above). A null email is a
    -- deliberately shareable class-wide link and stays open to anyone.
    if v_inv.email is not null
       and lower(trim(v_inv.email)) <> lower(trim(coalesce(new.email, ''))) then
      raise exception 'invitation_email_mismatch';
    end if;

    v_org := v_inv.org_id;
    v_role := v_inv.role;
    v_from_token := true;
    update public.invitations set accepted_at = now() where id = v_inv.id;
  end if;

  -- 2. Domain allowlist (only if not already resolved via a token) -----------
  if not v_from_token then
    v_domain := lower(split_part(new.email, '@', 2));
    if v_domain <> '' then
      select id into v_match from public.organizations
      where v_domain = any(allowed_domains) and status in ('active','trial')
      order by created_at limit 1;
      if v_match is not null then v_org := v_match; v_role := 'student'; end if;
    end if;
  end if;

  -- Seat cap (0 = unmetered internal org). Lock the org row first so
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

-- ── Verification (run after applying) ────────────────────────────────────────
-- 1. Generic class link (email is null) still admits anyone:
--      insert into invitations (org_id, email, role, token, expires_at)
--      values ('<org>', null, 'student', 'tok-generic', now() + interval '7 days');
--      -- sign up with any address + metadata {invitation_token:'tok-generic'} → joins <org>
--
-- 2. Roster invite is bound to its recipient:
--      insert into invitations (org_id, email, role, token, expires_at)
--      values ('<org>', 'student@college.ac.il', 'student', 'tok-named', now() + interval '7 days');
--      -- signing up as someone.else@gmail.com with that token → ERROR invitation_email_mismatch
--      -- signing up as student@college.ac.il                  → joins <org>
--
-- 3. A dud token no longer fails silently:
--      -- sign up with metadata {invitation_token:'does-not-exist'} → ERROR invitation_invalid
--      -- (signing up with NO token is unaffected: domain allowlist, then default org)
