-- 0080_qa_phase4_db.sql
--
-- QA audit PHASE 4 (database) — fixes approved by Tal 2026-09-30.
-- Every function below that already existed is rebuilt from its LIVE production
-- definition (pg_get_functiondef, 2026-09-30) with only the noted change.
--
--   P4-03  claim_task_attempt(): atomic per-task attempt numbers (parallel
--          submissions no longer all grade as "first try").
--   P4-05  org_resources: storage_key unique + must live under the org's prefix;
--          no client writes (every write goes through /api/org/media).
--   P4-08  reactivate_member(): reactivation under the org-row lock.
--   P4-09  org_seats_used(): the platform admin's memberships don't use seats.
--   P4-10  handle_new_user: an invitation can be consumed only once.
--   P4-11  renew_affiliation: renews the membership of the CODE's college.
--   P4-12  lapsed_students: per-table maxima (no join fan-out) + quiz, lesson
--          and team activity count as activity.
--   P4-13  purge_org: also removes quiz/lesson progress and task attempts.
--   P4-14  attach_member_if_seat_available: sets the affiliation expiry in the
--          same transaction (optional p_affiliation_expires).
--   P4-15  issue_org_code(): cooldown + revoke-previous + insert under one lock.
--   P4-17  recompute_user_xp / resolve_invitation: not callable by clients.
--   P4-18  session_clicks: bounded per player per session.
--   P4-19  handle_new_user: a same-handle signup race falls back to a suffixed
--          handle instead of failing the signup.
--   P4-21  indexes on audit_log.actor_id and session_events.actor_id.
--   P4-22  missing foreign keys (quiz/lesson progress org_id, session_clicks.user_id).
--   P4-24  team cron jobs skip their work when no session is live.

-- ── P4-03 ── atomic attempt numbers ───────────────────────────────────────────
create table if not exists public.task_attempt_counters (
  user_id   uuid    not null references auth.users(id) on delete cascade,
  room_id   text    not null,
  task_id   text    not null,
  qidx      integer not null default -1,          -- log_analysis sub-question, -1 = whole task
  n         integer not null,
  primary key (user_id, room_id, task_id, qidx)
);
alter table public.task_attempt_counters enable row level security;
revoke all on public.task_attempt_counters from anon, authenticated;
grant select, insert, update on public.task_attempt_counters to service_role;

-- Returns this submission's attempt number. The first claim seeds from the
-- attempts already recorded; concurrent first claims resolve through the
-- primary key (one inserts, the other takes the ON CONFLICT increment).
create or replace function public.claim_task_attempt(p_user uuid, p_room text, p_task text, p_qidx integer default null)
returns integer
language sql
security definer set search_path = public
as $$
  insert into public.task_attempt_counters as c (user_id, room_id, task_id, qidx, n)
  values (p_user, p_room, p_task, coalesce(p_qidx, -1),
          (select count(*)::int from public.task_attempts a
            where a.user_id = p_user and a.room_id = p_room and a.task_id = p_task
              and coalesce(a.question_index, -1) = coalesce(p_qidx, -1)) + 1)
  on conflict (user_id, room_id, task_id, qidx) do update set n = c.n + 1
  returning n
$$;
revoke all on function public.claim_task_attempt(uuid, text, text, integer) from public, anon, authenticated;
grant execute on function public.claim_task_attempt(uuid, text, text, integer) to service_role;

-- ── P4-05 ── org_resources.storage_key ─────────────────────────────────────────
alter table public.org_resources drop constraint if exists org_resources_storage_key_key;
alter table public.org_resources add constraint org_resources_storage_key_key unique (storage_key);
alter table public.org_resources drop constraint if exists org_resources_storage_key_prefix;
alter table public.org_resources add constraint org_resources_storage_key_prefix
  check (storage_key like org_id::text || '/%');
revoke insert, update, delete, truncate on public.org_resources from anon, authenticated;

-- ── P4-09 ── seats ────────────────────────────────────────────────────────────
create or replace function public.org_seats_used(p_org uuid)
returns integer
language sql
stable security definer set search_path = public
as $$
  select count(*)::int from public.org_members m
   where m.org_id = p_org and m.status = 'active'
     and not exists (select 1 from public.profiles p where p.id = m.user_id and p.is_platform_admin)
$$;
revoke all on function public.org_seats_used(uuid) from public, anon, authenticated;
grant execute on function public.org_seats_used(uuid) to service_role;

-- ── P4-09 + P4-10 + P4-19 ── handle_new_user ───────────────────────────────────
create or replace function public.handle_new_user()
 returns trigger
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  chosen        text;
  full_name     text;
  base_handle   text;
  final_handle  text;
  display       text;
  v_org         uuid;
  v_role        text := 'student';
  v_token       text;
  v_code        text;
  v_inv         record;
  v_oc          record;
  v_limit       int;
  v_used        int;
  v_affil       timestamptz := null;
begin
  chosen    := lower(trim(coalesce(new.raw_user_meta_data->>'handle', '')));
  full_name := trim(coalesce(new.raw_user_meta_data->>'full_name', ''));
  v_token   := trim(coalesce(new.raw_user_meta_data->>'invitation_token', ''));
  v_code    := trim(coalesce(new.raw_user_meta_data->>'org_code', ''));
  if length(full_name) > 60 then full_name := substr(full_name, 1, 60); end if;

  -- 1. Invitation token — NAMED people and staff roles.
  if v_token <> '' then
    select * into v_inv from public.invitations
    where token = v_token and accepted_at is null and expires_at > now();
    if not found then
      raise exception 'invitation_invalid';
    end if;

    -- 0029: a student-role invitation must name its recipient. The anonymous
    -- class-link shape is the code's job now.
    if v_inv.role = 'student' and v_inv.email is null then
      raise exception 'student_invite_requires_code';
    end if;

    if v_inv.email is not null
       and lower(trim(v_inv.email)) <> lower(trim(coalesce(new.email, ''))) then
      raise exception 'invitation_email_mismatch';
    end if;
    v_org := v_inv.org_id;
    v_role := v_inv.role;
    -- 0080 (P4-10): consume the invitation only if still unconsumed. Two signups
    -- racing on one generic staff link both passed the check above; the second
    -- UPDATE now matches nothing (re-checked after the first commits) and fails.
    update public.invitations set accepted_at = now() where id = v_inv.id and accepted_at is null;
    if not found then
      raise exception 'invitation_invalid';
    end if;

  -- 2. Org affiliation code — the student path.
  elsif v_code <> '' then
    select * into v_oc from public.org_codes
    where upper(trim(code)) = upper(v_code) and expires_at > now();
    if not found then
      raise exception 'org_code_invalid';
    end if;
    perform 1 from public.organizations
    where id = v_oc.org_id and status in ('active', 'trial');
    if not found then
      raise exception 'org_code_invalid';
    end if;
    v_org := v_oc.org_id;
    v_role := 'student';

  -- 3. Neither → registration is closed.
  else
    raise exception 'signup_requires_code';
  end if;

  if v_role = 'student' then
    v_affil := now() + interval '100 days';
  end if;

  perform 1 from public.organizations where id = v_org for update;
  select seat_limit into v_limit from public.organizations where id = v_org;
  if coalesce(v_limit, 0) > 0 then
    v_used := public.org_seats_used(v_org);                 -- 0080 (P4-09)
    if v_used >= v_limit then
      raise exception 'seat_limit_reached';
    end if;
  end if;

  base_handle := lower(regexp_replace(split_part(new.email, '@', 1), '[^a-zA-Z0-9_]', '', 'g'));
  if base_handle is null or base_handle = '' then base_handle := 'analyst'; end if;
  if chosen <> '' and public.handle_available(chosen) then
    final_handle := chosen;
  else
    final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);
  end if;

  display := coalesce(nullif(full_name, ''), nullif(chosen, ''), split_part(new.email, '@', 1));

  begin
    insert into public.profiles (id, handle, display_name, org_id)
    values (new.id, final_handle, display, v_org)
    on conflict (id) do nothing;
  exception when unique_violation then
    -- 0080 (P4-19): someone took this handle between the availability check and
    -- now (same org). Fall back to the always-unique suffixed form.
    final_handle := base_handle || '_' || substr(replace(new.id::text, '-', ''), 1, 6);
    insert into public.profiles (id, handle, display_name, org_id)
    values (new.id, final_handle, display, v_org)
    on conflict (id) do nothing;
  end;

  insert into public.org_members (org_id, user_id, role, status, affiliation_expires_at)
  values (v_org, new.id, v_role, 'active', v_affil)
  on conflict (org_id, user_id) do nothing;

  insert into public.user_progress (user_id, org_id)
  values (new.id, v_org)
  on conflict (user_id) do nothing;

  return new;
end;
$function$;

-- ── P4-09 + P4-14 ── attach_member_if_seat_available ───────────────────────────
-- New optional last parameter → drop the 3-argument form first (callers using
-- named arguments p_org/p_user/p_role keep working through the default).
drop function if exists public.attach_member_if_seat_available(uuid, uuid, text);
create or replace function public.attach_member_if_seat_available(p_org uuid, p_user uuid, p_role text, p_affiliation_expires timestamptz default null)
 returns text
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  v_limit    int;
  v_used     int;
  v_existing text;
begin
  if p_role not in ('org_admin','instructor','student') then
    raise exception 'invalid_role';
  end if;

  -- M1: serialise seat accounting for this org across concurrent callers.
  perform 1 from public.organizations where id = p_org for update;
  select seat_limit into v_limit from public.organizations where id = p_org;
  if v_limit is null then raise exception 'org_not_found'; end if;

  select status into v_existing from public.org_members
  where org_id = p_org and user_id = p_user;

  if found then
    -- M2: reactivating a non-active member consumes a seat again → re-check cap.
    if v_existing <> 'active' and v_limit > 0 then
      v_used := public.org_seats_used(p_org);               -- 0080 (P4-09)
      if v_used >= v_limit then raise exception 'seat_limit_reached'; end if;
    end if;
    update public.org_members set role = p_role, status = 'active',
           affiliation_expires_at = coalesce(p_affiliation_expires, affiliation_expires_at)   -- 0080 (P4-14)
    where org_id = p_org and user_id = p_user;
    update public.profiles set org_id = p_org where id = p_user;
    return 'updated';
  end if;

  v_used := public.org_seats_used(p_org);                   -- 0080 (P4-09)
  if v_limit > 0 and v_used >= v_limit then
    raise exception 'seat_limit_reached';
  end if;

  insert into public.org_members (org_id, user_id, role, status, affiliation_expires_at)
  values (p_org, p_user, p_role, 'active', p_affiliation_expires);   -- 0080 (P4-14)
  update public.profiles set org_id = p_org where id = p_user;
  return 'added';
end;
$function$;
revoke all on function public.attach_member_if_seat_available(uuid, uuid, text, timestamptz) from public, anon, authenticated;
grant execute on function public.attach_member_if_seat_available(uuid, uuid, text, timestamptz) to service_role;

-- ── P4-08 ── reactivation under the org lock ───────────────────────────────────
-- Unlike attach, this only flips an existing membership back to active — it does
-- not move the student's active context (they may be working in another college).
create or replace function public.reactivate_member(p_org uuid, p_user uuid)
returns text
language plpgsql
security definer set search_path = public
as $$
declare
  v_limit    int;
  v_existing text;
begin
  perform 1 from public.organizations where id = p_org for update;
  select seat_limit into v_limit from public.organizations where id = p_org;
  if v_limit is null then raise exception 'org_not_found'; end if;

  select status into v_existing from public.org_members where org_id = p_org and user_id = p_user;
  if not found then return 'not_member'; end if;
  if v_existing = 'active' then return 'already_active'; end if;

  if v_limit > 0 and public.org_seats_used(p_org) >= v_limit then
    raise exception 'seat_limit_reached';
  end if;
  update public.org_members set status = 'active' where org_id = p_org and user_id = p_user;
  return 'reactivated';
end;
$$;
revoke all on function public.reactivate_member(uuid, uuid) from public, anon, authenticated;
grant execute on function public.reactivate_member(uuid, uuid) to service_role;

-- ── P4-11 ── renew_affiliation ─────────────────────────────────────────────────
create or replace function public.renew_affiliation(p_user uuid, p_code text)
 returns void
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
declare
  v_member record;
  v_code   record;
begin
  select * into v_code from public.org_codes
  where upper(trim(code)) = upper(trim(p_code)) and expires_at > now();
  if not found then
    raise exception 'org_code_invalid';
  end if;

  -- 0080 (P4-11): the membership renewed is the one in the CODE's college. It
  -- used to pick an arbitrary student membership (limit 1), so a student in two
  -- colleges could be told "wrong college" by their own college's code.
  select * into v_member from public.org_members
  where user_id = p_user and org_id = v_code.org_id and status = 'active' and role = 'student';
  if not found then
    if exists (select 1 from public.org_members where user_id = p_user and status = 'active' and role = 'student') then
      raise exception 'org_code_wrong_org';
    end if;
    raise exception 'not_an_org_student';
  end if;

  update public.org_members
  set affiliation_expires_at = now() + interval '100 days'
  where org_id = v_member.org_id and user_id = p_user;
end;
$function$;

-- ── P4-15 ── class codes: one live code per org, cooldown, under one lock ─────
create or replace function public.issue_org_code(p_org uuid, p_created_by uuid, p_code text, p_expires_at timestamptz, p_cooldown_hours integer default 0)
returns table (code text, created_at timestamptz, expires_at timestamptz)
language plpgsql
security definer set search_path = public
as $$
begin
  perform 1 from public.organizations where id = p_org for update;
  if not found then raise exception 'org_not_found'; end if;
  if coalesce(p_cooldown_hours, 0) > 0 and exists (
       select 1 from public.org_codes c
        where c.org_id = p_org and c.created_at > now() - make_interval(hours => p_cooldown_hours)) then
    raise exception 'code_cooldown';
  end if;
  -- Revoke-previous: a student typing yesterday's code gets "invalid", not a second door.
  update public.org_codes c set expires_at = now() where c.org_id = p_org and c.expires_at > now();
  return query
    insert into public.org_codes as c (org_id, code, created_by, expires_at)
    values (p_org, p_code, p_created_by, p_expires_at)
    returning c.code, c.created_at, c.expires_at;
end;
$$;
revoke all on function public.issue_org_code(uuid, uuid, text, timestamptz, integer) from public, anon, authenticated;
grant execute on function public.issue_org_code(uuid, uuid, text, timestamptz, integer) to service_role;

-- ── P4-12 ── lapsed_students ────────────────────────────────────────────────────
create or replace function public.lapsed_students(p_idle_days integer default 7, p_cooldown_days integer default 14, p_limit integer default 200)
 returns table(user_id uuid, email text, display_name text, org_name text, last_active timestamp with time zone)
 language sql
 stable security definer
 set search_path to 'public'
as $function$
  -- 0080 (P4-12): one max() per source instead of joining them all (which
  -- multiplied rows: rooms × sessions × runs per user), and quiz / lesson / team
  -- work now counts as activity so an active learner isn't nudged as "lapsed".
  with activity as (
    select p.id as user_id,
           greatest(
             coalesce((select max(rp.updated_at)        from public.room_progress      rp where rp.user_id = p.id), 'epoch'::timestamptz),
             coalesce((select max(ds.played_at)         from public.dashboard_sessions ds where ds.user_id = p.id), 'epoch'::timestamptz),
             coalesce((select max(sh.completed_at)      from public.scenario_history   sh where sh.user_id = p.id), 'epoch'::timestamptz),
             coalesce((select max(qp.last_completed_at) from public.quiz_progress      qp where qp.user_id = p.id), 'epoch'::timestamptz),
             coalesce((select max(lp.updated_at)        from public.lesson_progress    lp where lp.user_id = p.id), 'epoch'::timestamptz),
             coalesce((select max(se.occurred_at)       from public.session_events     se where se.actor_id = p.id), 'epoch'::timestamptz)
           ) as last_active
      from public.profiles p
  )
  select p.id,
         u.email::text,
         coalesce(nullif(p.display_name, ''), p.handle),
         o.name,
         a.last_active
    from public.profiles p
    join activity a on a.user_id = p.id
    join auth.users u on u.id = p.id
    left join public.organizations o on o.id = p.org_id
   where u.email is not null
     -- Idle long enough to be worth a nudge …
     and a.last_active < now() - make_interval(days => p_idle_days)
     -- … but they DID start once; never-started is an onboarding problem.
     and a.last_active > 'epoch'::timestamptz
     -- … and we haven't already nudged them recently.
     and (p.last_nudged_at is null or p.last_nudged_at < now() - make_interval(days => p_cooldown_days))
     -- Don't chase students whose college licence has lapsed.
     and (o.id is null or o.status in ('trial', 'active'))
   order by a.last_active asc
   limit greatest(1, least(p_limit, 500));
$function$;

-- ── P4-13 ── purge_org ──────────────────────────────────────────────────────────
create or replace function public.purge_org(p_org uuid)
 returns void
 language plpgsql
 security definer
 set search_path to 'public'
as $function$
begin
  if p_org = 'd0d0d0d0-0000-4000-8000-000000000000' then
    raise exception 'cannot_purge_internal';
  end if;

  delete from public.room_progress     where org_id = p_org;
  delete from public.dashboard_sessions where org_id = p_org;
  delete from public.scenario_history   where org_id = p_org;
  delete from public.ai_usage           where org_id = p_org;
  delete from public.user_progress      where org_id = p_org;
  -- 0080 (P4-13): the rest of the learner data earned in this college.
  delete from public.quiz_progress      where org_id = p_org;
  delete from public.lesson_progress    where org_id = p_org;
  delete from public.task_attempts      where org_id = p_org;

  -- Preserve the audit trail but drop the tenant FK (nullable) so the org delete
  -- below can't be blocked by audit_log_org_id_fkey.
  update public.audit_log set org_id = null where org_id = p_org;

  -- Re-home the accounts to the internal org so their NOT NULL org_id FK stays
  -- valid and they can still sign in after the college leaves.
  update public.profiles set org_id = 'd0d0d0d0-0000-4000-8000-000000000000' where org_id = p_org;

  delete from public.org_members  where org_id = p_org;
  delete from public.invitations  where org_id = p_org;
  delete from public.organizations where id = p_org;
end;
$function$;

-- ── P4-17 ── functions clients must not call ───────────────────────────────────
-- (Supabase grants EXECUTE on new public functions to anon/authenticated by
-- default; both are only ever called by the server with the service role.)
revoke execute on function public.recompute_user_xp(uuid) from public, anon, authenticated;
grant  execute on function public.recompute_user_xp(uuid) to service_role;
revoke execute on function public.resolve_invitation(text) from public, anon, authenticated;
grant  execute on function public.resolve_invitation(text) to service_role;

-- ── P4-18 ── session_clicks bounded per player per session ─────────────────────
create or replace function public.session_clicks_cap()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  -- Click telemetry is analytics, not state: past a generous cap per player per
  -- session, further opens are dropped silently (the action itself still succeeds).
  if (select count(*) from public.session_clicks c
       where c.session_id = new.session_id and c.user_id = new.user_id) >= 5000 then
    return null;
  end if;
  return new;
end;
$$;
drop trigger if exists session_clicks_cap on public.session_clicks;
create trigger session_clicks_cap before insert on public.session_clicks
  for each row execute function public.session_clicks_cap();

-- ── P4-21 ── indexes ────────────────────────────────────────────────────────────
create index if not exists audit_log_actor_idx on public.audit_log (actor_id);
create index if not exists session_events_actor_idx on public.session_events (actor_id, occurred_at desc);

-- ── P4-22 ── missing foreign keys (0 orphans in production, checked 2026-09-30) ─
alter table public.quiz_progress drop constraint if exists quiz_progress_org_id_fkey;
alter table public.quiz_progress add constraint quiz_progress_org_id_fkey
  foreign key (org_id) references public.organizations(id) on delete set null;
alter table public.lesson_progress drop constraint if exists lesson_progress_org_id_fkey;
alter table public.lesson_progress add constraint lesson_progress_org_id_fkey
  foreign key (org_id) references public.organizations(id) on delete set null;
alter table public.session_clicks drop constraint if exists session_clicks_user_id_fkey;
alter table public.session_clicks add constraint session_clicks_user_id_fkey
  foreign key (user_id) references auth.users(id) on delete cascade;

-- ── P4-24 ── team cron jobs idle when no session is live ───────────────────────
-- They ran every 5–10 s around the clock (~45k runs per 2.6 days) even with no
-- exercise in progress. The guard is a single indexed existence check.
select cron.alter_job(j.jobid, command := $cmd$ select public.promote_due_injects() where exists (select 1 from public.team_sessions where status in ('lobby','running','paused')); $cmd$)
  from cron.job j where j.jobname = 'team-promote-injects';
select cron.alter_job(j.jobid, command := $cmd$ select public.replenish_feed() where exists (select 1 from public.team_sessions where status in ('lobby','running','paused')); $cmd$)
  from cron.job j where j.jobname = 'team-replenish-feed';
select cron.alter_job(j.jobid, command := $cmd$ select public.team_lifecycle_tick() where exists (select 1 from public.team_sessions where status in ('lobby','running','paused')); $cmd$)
  from cron.job j where j.jobname = 'team-lifecycle-tick';
