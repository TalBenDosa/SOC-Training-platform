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
