-- 0032 — expose member emails to the org-admin roster
--
-- The roster shows display name + handle but the org-admin asked to see each
-- student's EMAIL too. Email lives in auth.users, which PostgREST doesn't
-- expose, so a SECURITY DEFINER helper returns (user_id, email) for a given
-- org's members. Execute is granted to service_role ONLY — the org-scoped API
-- routes (which already gate on requireOrgAdmin and pass the caller's own org)
-- are the sole callers; it is NOT reachable by ordinary authenticated clients,
-- so it can't be turned into a cross-org email harvester.

create or replace function public.org_member_emails(p_org uuid)
  returns table(user_id uuid, email text)
  language sql
  stable
  security definer set search_path = public, auth
as $$
  select om.user_id, u.email::text
  from public.org_members om
  join auth.users u on u.id = om.user_id
  where om.org_id = p_org;
$$;

revoke execute on function public.org_member_emails(uuid) from authenticated, anon, public;
grant execute on function public.org_member_emails(uuid) to service_role;
