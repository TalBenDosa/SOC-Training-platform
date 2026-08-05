-- HACK THE SOC :: HOTFIX — make the access-token hook SECURITY DEFINER
-- ===========================================================================
-- The hook was created SECURITY INVOKER, so it ran as `supabase_auth_admin`,
-- which is subject to RLS on `profiles` (owner-only SELECT) and could not read
-- the caller's is_platform_admin / org membership → it returned empty claims.
--
-- Recreating it as SECURITY DEFINER makes it run as the owner (bypassing RLS on
-- the tables it reads), which is the correct pattern for an auth hook that reads
-- your own tables. It still only ever returns claims for the user in the event.
--
-- Paste-and-run in the Supabase SQL editor (project "Hack The SOC Real"), then
-- sign out and back in. This matches the final (0014) hook body.

create or replace function public.custom_access_token_hook(event jsonb)
  returns jsonb
  language plpgsql
  stable
  security definer set search_path = public
as $$
declare
  v_claims jsonb := event->'claims';
  v_org    uuid;
  v_name   text;
  v_role   text;
  v_status text;
  v_exp    timestamptz;
  v_active boolean := true;
  v_admin  boolean;
begin
  select om.org_id, om.role, o.name, o.status, o.expires_at
    into v_org, v_role, v_name, v_status, v_exp
  from public.org_members om
  join public.organizations o on o.id = om.org_id
  where om.user_id = (event->>'user_id')::uuid
    and om.status = 'active'
  order by om.joined_at
  limit 1;

  select coalesce(p.is_platform_admin, false) into v_admin
  from public.profiles p
  where p.id = (event->>'user_id')::uuid;

  if v_org is not null then
    v_active := (v_status in ('active','trial')) and (v_exp is null or v_exp > now());
    v_claims := jsonb_set(v_claims, '{org_id}',     to_jsonb(v_org::text));
    v_claims := jsonb_set(v_claims, '{org_role}',   to_jsonb(v_role));
    v_claims := jsonb_set(v_claims, '{org_name}',   to_jsonb(coalesce(v_name, '')));
    v_claims := jsonb_set(v_claims, '{org_active}', to_jsonb(v_active));
  end if;
  v_claims := jsonb_set(v_claims, '{is_platform_admin}', to_jsonb(coalesce(v_admin, false)));

  return jsonb_set(event, '{claims}', v_claims);
end;
$$;

grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;

-- Verify (run as a signed-in user AFTER re-login): select auth.jwt() ->> 'is_platform_admin';
