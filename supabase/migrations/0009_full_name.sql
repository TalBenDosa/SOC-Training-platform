-- HACK THE SOC :: 0009 — carry a chosen full name onto the profile
-- ---------------------------------------------------------------------------
-- The signup form now offers an OPTIONAL "full name". A rank-up certificate is
-- a public, shareable artefact, so it should be able to print the learner's
-- real name rather than a nickname or an email fragment.
--
-- This supersedes 0006's handle_new_user() with ONE behavioural change:
-- display_name is now sourced from `full_name` when supplied, falling back to
-- the chosen handle and then the email local part — exactly the old fallback,
-- one rung richer. Handle selection and the security re-validation are
-- unchanged. The column already exists (0001), so there is no schema change and
-- accounts created before this migration keep whatever display_name they had.
--
-- SECURITY. Like `handle`, `full_name` arrives in raw_user_meta_data unverified.
-- It is not an identifier and is only ever rendered as text the user chose about
-- themselves, so the handling here is a trim and a length cap — enough to keep a
-- pathological value from bloating the row — not validation of "a real name",
-- which is not a meaningful thing to enforce.

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
begin
  chosen    := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));
  full_name := trim(coalesce(new.raw_user_meta_data->>'full_name', ''));

  -- Cap length so a hostile client cannot store an oversized blob. The form
  -- already limits to 60; this is the rule that actually holds.
  if length(full_name) > 60 then
    full_name := substr(full_name, 1, 60);
  end if;

  -- Re-validate the handle rather than trusting the client (see 0006): a caller
  -- could otherwise register any string — including 'admin' — into the profile.
  if chosen <> '' and public.handle_available(chosen) then
    final_handle := chosen;
  else
    base_handle := lower(regexp_replace(split_part(new.email, '@', 1), '[^a-zA-Z0-9_]', '', 'g'));
    if base_handle is null or base_handle = '' then base_handle := 'analyst'; end if;
    final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);
  end if;

  -- Prefer the real name, then the chosen handle, then the email local part.
  display := coalesce(
    nullif(full_name, ''),
    nullif(chosen, ''),
    split_part(new.email, '@', 1)
  );

  insert into public.profiles (id, handle, display_name)
  values (new.id, final_handle, display)
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

-- ── Verify ───────────────────────────────────────────────────────────────────
-- After a signup with options.data = { handle: 'nightowl', full_name: 'Tal Ben Dosa' }:
--   select handle, display_name from public.profiles order by created_at desc limit 1;
--   -- expect handle='nightowl', display_name='Tal Ben Dosa'
