-- HACK THE SOC :: 0003 — signup trigger (supersedes 0001's, fixes a real bug)
-- ---------------------------------------------------------------------------
-- 0001_init.sql already ships a handle_new_user() trigger, but it has TWO
-- problems this migration fixes:
--   1. It sets profiles.handle = split_part(email,'@',1). Since `handle` is
--      `unique not null`, the SECOND user whose email local-part collides
--      (e.g. a@x.com after a@y.com) hits a unique-violation → signup 500s.
--      This version appends a short deterministic suffix from the user id so
--      handles never collide.
--   2. It predates the user_progress table (added in 0002), so it never seeds
--      that row. This version creates it too.
-- Because both use `create or replace function` + `drop trigger if exists`,
-- running this AFTER 0001 cleanly replaces 0001's version. Run order: 0001 → 0002 → 0003.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  base_handle text;
  final_handle text;
begin
  base_handle := lower(regexp_replace(split_part(new.email, '@', 1), '[^a-zA-Z0-9_]', '', 'g'));
  if base_handle is null or base_handle = '' then base_handle := 'analyst'; end if;
  -- Append a short, deterministic suffix from the user id so two people with
  -- the same email local-part (different domains) never collide on `handle`.
  final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);

  insert into public.profiles (id, handle, display_name)
  values (new.id, final_handle, split_part(new.email, '@', 1))
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
