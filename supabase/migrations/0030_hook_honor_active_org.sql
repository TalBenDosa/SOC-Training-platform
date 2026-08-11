-- 0030 — access-token hook honours the SELECTED active org (profiles.org_id)
--
-- Bug: the hook picked the active-org claim with `order by joined_at limit 1`,
-- i.e. always the EARLIEST membership. For a single-org student that's fine
-- (their only membership). But the super-admin — present in every environment
-- via /superadmin/enter-org and the environment switcher — was stuck: switching
-- sets profiles.org_id, which the hook never read, so the claim always resolved
-- to their oldest membership (Internal / Default) and every "enter/switch"
-- bounced back to Default.
--
-- Fix: prefer the membership whose org_id equals profiles.org_id (the chosen
-- active context that enter-org / join-environment / attach_member all set),
-- falling back to the earliest membership when it doesn't match one. Fully
-- backward-compatible: a student whose profiles.org_id IS their single
-- membership still resolves to it; anyone whose profiles.org_id matches nothing
-- active falls back to the previous joined_at behaviour.

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
  left join public.profiles p on p.id = om.user_id
  where om.user_id = (event->>'user_id')::uuid
    and om.status = 'active'
  -- chosen context first (profiles.org_id), then earliest membership.
  order by (om.org_id = p.org_id) desc nulls last, om.joined_at
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
