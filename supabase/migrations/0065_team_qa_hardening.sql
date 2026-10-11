-- HACK THE SOC :: 0065 — Team-SOC QA hardening (wave 2)
-- ===========================================================================
-- Addresses the 2026-09-18 QA audit (docs/team-review/QA-2026-09-18-team-lifecycle):
--   S3  cap the action payload size (DoS) + constrain message.sent to running/paused
--   C11 gate a distinct elevation.acknowledged action (t2/t3) so "take the hunt"
--       no longer masquerades as an escalation.acknowledged
--   S6  promote_due_injects retries a per-inject seq collision instead of aborting
--       the whole tick
--   S5  a partial unique index enforcing the single-seat roles (mgr/t3)
--   C9  reap_stale_team_sessions() + a pg_cron sweep to close orphaned sessions
--       (all clients gone → nothing left to fire the client-side auto-close)
-- Idempotent.
-- ===========================================================================

-- ── S3 + C11: the role×phase gate ───────────────────────────────────────────
create or replace function public.session_action_allowed(p_type text, p_role text, p_status text)
  returns boolean language sql immutable set search_path = public as $$
  select case
    when p_type in ('feed.event','inject.fired','session.started','session.ended','session.paused','session.resumed','grade.assigned') then false
    when p_type in ('member.ready','member.unready') then p_status = 'lobby'
    when p_type = 'disposition.set'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'escalation.requested'     then p_role = 't1'            and p_status = 'running'
    when p_type in ('alert.claimed','alert.released') then p_role = 't1'   and p_status = 'running'
    when p_type = 'escalation.acknowledged'  then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.bounced'       then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'escalation.resolved'      then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'elevation.requested'      then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'elevation.acknowledged'   then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'report.submitted'         then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.requested'    then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'containment.approved'     then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.denied'       then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'containment.executed'     then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'hunt.logged'              then p_role = 't3'            and p_status = 'running'
    when p_type in ('rule.published','rule.tuned') then p_role = 'de'      and p_status = 'running'
    when p_type = 'intel.published'          then p_role = 'ti'            and p_status = 'running'
    when p_type = 'handover.noted'           then p_role in ('mgr','lead') and p_status = 'running'
    when p_type = 'decision.logged'          then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'sitrep.sent'              then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'evidence.pinned'          then p_role in ('t1','t2','t3','de','ti','mgr','lead') and p_status = 'running'
    when p_type = 'case.status_set'          then p_role in ('t2','t3','lead','mgr') and p_status = 'running'
    when p_type = 'case.assigned'            then p_role in ('lead','mgr') and p_status = 'running'
    when p_type = 'scope.set'                then p_role in ('t2','t3')    and p_status = 'running'
    when p_type = 'scope.confirmed'          then p_role = 't3'            and p_status = 'running'
    when p_type = 'staff.inject'             then p_role = 'instructor'    and p_status = 'running'
    when p_type = 'ticket.answered'          then p_role = 't1'            and p_status = 'running'
    when p_type = 'note.added'               then p_status = 'running'
    when p_type = 'event.opened'             then p_status = 'running'
    when p_type = 'message.sent'             then p_status in ('running','paused')  -- S3: not in lobby/ended
    else false   -- deny-by-default
  end
$$;

-- ── S3: apply_session_action + a 16 KiB payload cap (recreated from 0062) ────
create or replace function public.apply_session_action(
  p_session uuid, p_type text, p_payload jsonb default '{}'::jsonb,
  p_expected_seq bigint default null, p_idempotency_key text default null
) returns public.session_events
  language plpgsql security definer set search_path = public as $$
declare
  v_uid    uuid := auth.uid();
  v_role   text;
  v_status text;
  v_next   bigint;
  v_row    public.session_events;
  v_prior  public.session_events;
  v_ok     boolean := false;
begin
  if v_uid is null then raise exception 'auth_required'; end if;

  -- S3: bound the payload so a member can't store/broadcast a huge blob to the team.
  if pg_column_size(coalesce(p_payload, '{}'::jsonb)) > 16384 then
    raise exception 'payload_too_large';
  end if;

  select role into v_role from public.team_session_members
    where session_id = p_session and user_id = v_uid;
  if v_role is null then raise exception 'not_a_member'; end if;

  select status into v_status from public.team_sessions where id = p_session;
  if v_status is null then raise exception 'no_such_session'; end if;

  if p_idempotency_key is not null then
    select * into v_prior from public.session_events
      where session_id = p_session and actor_id = v_uid and idempotency_key = p_idempotency_key;
    if found then return v_prior; end if;
  end if;

  if not public.session_action_allowed(p_type, v_role, v_status) then
    raise exception 'action_not_allowed: % for role % in status %', p_type, v_role, v_status;
  end if;

  for i in 1..8 loop
    select coalesce(max(seq), 0) into v_next from public.session_events where session_id = p_session;
    if p_expected_seq is not null and p_expected_seq <> v_next then
      raise exception 'seq_conflict: expected % but head is %', p_expected_seq, v_next;
    end if;
    v_next := v_next + 1;
    begin
      insert into public.session_events(session_id, seq, actor_id, role, type, payload, idempotency_key)
        values (p_session, v_next, v_uid, v_role, p_type, coalesce(p_payload, '{}'::jsonb), p_idempotency_key)
        returning * into v_row;
      v_ok := true;
      exit;
    exception when unique_violation then
      if p_expected_seq is not null then raise; end if;
      if i = 8 then raise; end if;
    end;
  end loop;

  if not v_ok then raise exception 'seq_insert_failed after retries'; end if;

  insert into public.session_state(session_id, seq) values (p_session, v_next)
    on conflict (session_id) do update set seq = greatest(public.session_state.seq, excluded.seq), updated_at = now();

  if p_type = 'member.ready' then
    update public.team_session_members
      set status = 'ready', ready_at = now(), confirmed_entry_at = coalesce(confirmed_entry_at, now())
      where session_id = p_session and user_id = v_uid;
  elsif p_type = 'member.unready' then
    update public.team_session_members set status = 'invited', ready_at = null
      where session_id = p_session and user_id = v_uid;
  end if;

  return v_row;
end $$;
grant execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) to authenticated;

-- ── S6: promote_due_injects with a per-inject seq retry (keeps 0064 pacing) ──
create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0; v_type text; v_ok boolean;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval <= now()
    order by i.session_id, i.due_offset_ms
  loop
    v_type := case when r.channel = 'inject' then 'staff.inject' else 'feed.event' end;
    v_ok := false;
    for attempt in 1..8 loop
      select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.session_id;
      begin
        insert into public.session_events(session_id, seq, actor_id, role, type, payload)
          values (r.session_id, v_next, null, null, v_type, r.body || jsonb_build_object('inject_id', r.id));
        v_ok := true;
        exit;
      exception when unique_violation then
        if attempt = 8 then raise; end if;  -- give up after 8 tries on this inject
      end;
    end loop;
    if v_ok then
      update public.session_injects set status = 'fired', fired_seq = v_next where id = r.id;
      update public.session_state set seq = v_next, updated_at = now() where session_id = r.session_id;
      v_count := v_count + 1;
    end if;
  end loop;
  return v_count;
end $$;
grant execute on function public.promote_due_injects() to authenticated;

-- ── S5: single-seat invariant (mgr/t3 hold at most one non-left occupant) ────
-- Note: if legacy data already has two live holders of a single-seat role, this
-- index creation will fail — dedupe first, then re-run.
create unique index if not exists team_session_single_seat
  on public.team_session_members (session_id, role)
  where role in ('mgr','t3') and status <> 'left';

-- ── C9: reap orphaned sessions (all clients gone → no one to auto-close) ─────
create or replace function public.reap_stale_team_sessions()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_count int := 0; v_next bigint;
begin
  for r in
    select ts.id from public.team_sessions ts
    where ts.status in ('running','paused')
      and (
        ts.started_at < now() - interval '4 hours'  -- absolute safety cap
        or (
          coalesce((select max(occurred_at) from public.session_events e where e.session_id = ts.id), ts.started_at)
            < now() - interval '90 minutes'
          and not exists (select 1 from public.session_injects i where i.session_id = ts.id and i.status = 'pending')
        )
      )
  loop
    update public.team_sessions set status = 'ended', ended_at = now()
      where id = r.id and status in ('running','paused');
    select coalesce(max(seq), 0) + 1 into v_next from public.session_events where session_id = r.id;
    begin
      insert into public.session_events(session_id, seq, actor_id, role, type, payload)
        values (r.id, v_next, null, null, 'session.ended', jsonb_build_object('at', now(), 'reason', 'reaped'));
      update public.session_state set seq = v_next, updated_at = now() where session_id = r.id;
    exception when unique_violation then null;  -- a concurrent writer took the seq; the status flip stands
    end;
    v_count := v_count + 1;
  end loop;
  return v_count;
end $$;

do $$
begin perform cron.unschedule('team-reap-stale'); exception when others then null; end $$;
-- pg_cron only special-cases 'N seconds'; use standard cron syntax for minutes.
select cron.schedule('team-reap-stale', '*/5 * * * *', $$ select public.reap_stale_team_sessions(); $$);

-- Verification:
--   select public.session_action_allowed('elevation.acknowledged','t3','running'); -- t
--   select public.session_action_allowed('message.sent','t1','lobby');             -- f
--   select public.reap_stale_team_sessions();                                      -- int (0 normally)
--   select indexname from pg_indexes where indexname='team_session_single_seat';
