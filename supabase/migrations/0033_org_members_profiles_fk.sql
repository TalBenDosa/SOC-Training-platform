-- 0033 — restore the org_members → profiles foreign key (fixes empty rosters)
--
-- BUG: org_members.user_id had NO foreign key. Every org-admin/super-admin view
-- that reads members with an embedded profile —
--   admin.from("org_members").select("...profiles(handle, display_name, xp)")
-- — relies on PostgREST resolving the org_members→profiles relationship from a
-- FK. With no FK, PostgREST returns PGRST200 "Could not find a relationship …",
-- the route's `(rows ?? [])` swallows it, and the roster / analytics / global
-- student list / per-student drill-down all came back EMPTY even though the
-- members plainly existed. (A student registered into a college and the admin
-- couldn't see them.)
--
-- FIX: add the missing FK. profiles.id is 1:1 with auth.users.id, so this is
-- the correct target and lets the embed resolve. ON DELETE CASCADE matches the
-- existing behaviour (deleting a user removes their memberships). Idempotent.

do $$
begin
  if not exists (
    select 1 from information_schema.table_constraints
    where table_schema = 'public' and table_name = 'org_members'
      and constraint_name = 'org_members_user_id_profiles_fkey'
  ) then
    alter table public.org_members
      add constraint org_members_user_id_profiles_fkey
      foreign key (user_id) references public.profiles(id) on delete cascade;
  end if;
end $$;

-- tell PostgREST to pick up the new relationship immediately
notify pgrst, 'reload schema';
