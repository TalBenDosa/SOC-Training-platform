-- QA phase 7 (error handling) — operational hygiene.
--
-- E-20: lobbies were never reaped. A session created and never started stayed
--       in 'lobby' forever: it kept appearing in the staff "open sessions" list
--       and kept its members "in a session". The reaper now also ends lobbies
--       older than 24 h (team_transition already allows lobby → ended).
--       Running / paused rules are unchanged from 0071.

create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_res jsonb; v_count int := 0;
begin
  for r in
    select ts.id from public.team_sessions ts
     where (ts.status = 'lobby' and ts.created_at < now() - interval '24 hours')       -- abandoned lobby (E-20)
        or (ts.status in ('running','paused')
       and (
         ts.started_at < now() - interval '4 hours'                                   -- absolute cap
         or (ts.status = 'paused' and ts.pause_reason = 'manual'
             and coalesce(ts.paused_at, ts.started_at) < now() - interval '3 hours')   -- long manual pause
         or ((ts.status = 'running' or coalesce(ts.pause_reason, '') <> 'manual')
             and coalesce((select max(e.occurred_at) from public.session_events e
                            where e.session_id = ts.id and e.actor_id is not null), ts.started_at)
                 < now() - interval '30 minutes'                                      -- no human action
             and coalesce((select max(m.last_seen_at) from public.team_session_members m
                            where m.session_id = ts.id), '-infinity'::timestamptz)
                 < now() - interval '10 minutes')                                     -- nobody's heartbeat
       ))
     limit 50
  loop
    begin
      v_res := public.team_transition(r.id, 'ended', 'reaped', null, null);
      if coalesce((v_res->>'ok')::boolean, false) and not coalesce((v_res->>'noop')::boolean, false) then
        v_count := v_count + 1;
      end if;
    exception when others then
      insert into public.team_ops_events(kind, session_id, detail) values ('reap_error', r.id, sqlerrm);
    end;
  end loop;
  return v_count;
end $$;
revoke all on function public.reap_stale_team_sessions() from public, anon, authenticated;
grant execute on function public.reap_stale_team_sessions() to service_role;

-- Info (auth hook): body identical to 0030 plus an exception guard — a failure
-- here used to block all sign-ins.
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
exception when others then
  -- QA phase 7 (info): an error in this hook made GoTrue refuse EVERY sign-in
  -- and token refresh. Fail closed on privileges instead — no org / admin
  -- claims (the app treats the user as having no organisation) — but let the
  -- person sign in. The warning lands in the Postgres log.
  raise warning 'custom_access_token_hook failed for %: %', event->>'user_id', sqlerrm;
  return jsonb_set(event, '{claims}',
    ((event->'claims') - 'org_id' - 'org_role' - 'org_name' - 'org_active')
      || jsonb_build_object('is_platform_admin', false));
end;
$$;

grant execute on function public.custom_access_token_hook to supabase_auth_admin;
revoke execute on function public.custom_access_token_hook from authenticated, anon, public;
