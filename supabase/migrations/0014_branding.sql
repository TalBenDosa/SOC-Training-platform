-- HACK THE SOC :: 0014 — Phase 4 per-tenant branding
-- ===========================================================================
-- Adds the org NAME to the access-token claims so the app can show "<College>"
-- in the top bar and print it on rank certificates without an extra fetch. The
-- richer branding (accent colour, logo URL) lives in organizations.branding
-- (already present since 0010) and is fetched on demand — too large for a JWT.
-- Additive. Run after 0010–0013. Claude cannot run it.

create or replace function public.custom_access_token_hook(event jsonb)
  returns jsonb
  language plpgsql
  stable
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

-- ── Verify ──────────────────────────────────────────────────────────────────
-- After a fresh login: select auth.jwt() ->> 'org_name';
