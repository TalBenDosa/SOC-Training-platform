-- ═══════════════════════════════════════════════════════════════════════════
--  RUN THIS ONCE, IN THE SUPABASE SQL EDITOR
--  Dashboard -> your project -> SQL Editor -> New query -> paste -> Run
-- ═══════════════════════════════════════════════════════════════════════════
--
--  Until this runs, the Nickname field on the signup form is inert: the
--  availability check returns 404, the form treats that as "unknown" rather
--  than "available" so it never blocks anyone, and the existing trigger
--  simply ignores the chosen name and derives one from the email as before.
--  Nothing breaks — the feature is just dormant.
--
--  Safe to run more than once.
-- ═══════════════════════════════════════════════════════════════════════════

-- HACK THE SOC :: 0006 — let a user choose their own handle at signup
-- ---------------------------------------------------------------------------
-- Until now `handle` was always derived: email local-part plus a six-character
-- suffix from the user id, so it read like "tal14997_d0b992" and nobody would
-- ever choose it. This lets someone pick a nickname, keeps the derived value as
-- the fallback, and — the part that needs care — lets the signup form tell them
-- a name is taken BEFORE the account is created rather than failing afterwards.
--
-- WHY A FUNCTION AND NOT A SELECT. Migration 0004 restricted profiles SELECT to
-- the row owner, precisely so one user cannot enumerate others. An availability
-- check therefore cannot be a client-side query. This exposes a security
-- definer function that returns ONE BOOLEAN and nothing else: no id, no email,
-- no profile fields, and no distinction between "taken" and "reserved".
--
-- TRADE-OFF, STATED PLAINLY: any handle picker is a handle oracle. Someone can
-- probe names to learn which exist. That is inherent to the feature — every
-- signup form that says "already taken" has it — and the mitigation is that a
-- handle is not a credential and reveals nothing beyond its own existence.
-- Email addresses, which ARE the login identifier, remain unenumerable.

-- ── 1. Availability check ───────────────────────────────────────────────────
create or replace function public.handle_available(candidate text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  normalised text;
begin
  normalised := lower(trim(coalesce(candidate, '')));

  -- Same rules the form enforces, re-checked here. A client-side rule is a
  -- convenience; this is the one that actually holds.
  if normalised = '' or length(normalised) < 3 or length(normalised) > 20 then
    return false;
  end if;
  if normalised !~ '^[a-z0-9_]+$' then
    return false;
  end if;

  -- Names that would be confusing or misleading to hold.
  if normalised in ('admin', 'administrator', 'root', 'system', 'support',
                    'moderator', 'staff', 'security', 'hackthesoc', 'soc') then
    return false;
  end if;

  return not exists (select 1 from public.profiles where lower(handle) = normalised);
end;
$$;

comment on function public.handle_available(text) is
  'Returns true when a handle is free and well-formed. Deliberately returns only a boolean: profiles SELECT is owner-only (0004) and this must not become a way to read other users.';

-- Anonymous callers need this — the check runs on the signup form, before any
-- account exists.
grant execute on function public.handle_available(text) to anon, authenticated;

-- ── 2. Use the chosen handle when one was supplied ──────────────────────────
-- Supersedes 0003's version. Same collision-proof fallback; the only change is
-- that a handle passed through signUp options.data is preferred when it is
-- valid and still free at insert time.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  chosen       text;
  base_handle  text;
  final_handle text;
begin
  chosen := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));

  -- Re-validate rather than trusting the client. raw_user_meta_data is
  -- user-supplied and reaches us unverified, so a caller could otherwise
  -- register any string — including 'admin' — straight into the profile.
  if chosen <> '' and public.handle_available(chosen) then
    final_handle := chosen;
  else
    base_handle := lower(regexp_replace(split_part(new.email, '@', 1), '[^a-zA-Z0-9_]', '', 'g'));
    if base_handle is null or base_handle = '' then base_handle := 'analyst'; end if;
    -- Unchanged fallback: a deterministic suffix so two people whose email
    -- local-parts match on different domains never collide.
    final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);
  end if;

  insert into public.profiles (id, handle, display_name)
  values (new.id, final_handle, coalesce(nullif(chosen, ''), split_part(new.email, '@', 1)))
  on conflict (id) do nothing;

  insert into public.user_progress (user_id)
  values (new.id)
  on conflict (user_id) do nothing;

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ── 3. Verify ───────────────────────────────────────────────────────────────
-- select public.handle_available('someone_new');  -- expect true
-- select public.handle_available('admin');        -- expect false (reserved)
-- select public.handle_available('ab');           -- expect false (too short)
