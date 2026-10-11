-- HACK THE SOC :: 0062 — apply_session_action: retry on concurrent seq collision
-- ===========================================================================
-- The append path computed the next seq as max(seq)+1 and inserted. Two writers
-- racing (a pg_cron feed promote landing at the same instant as a player action)
-- could read the same max and collide on unique(session_id, seq) — surfaced to a
-- user as a transient "duplicate key value violates session_events_session_id_seq_key"
-- toast. This recreates the RPC with a small retry loop around the insert: on a
-- unique_violation it recomputes the head and tries again (up to 8 times).
--
-- The optimistic-concurrency contract is preserved: a caller that PINS the head
-- with p_expected_seq still gets a `seq_conflict` (its intent is "write only if
-- the head is exactly X"), and a unique_violation for a pinned caller is re-raised
-- rather than silently retried. Only unpinned writes (pg_cron promotes + most UI
-- actions, which pass p_expected_seq = null) retry.
-- ===========================================================================

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

  select role into v_role from public.team_session_members
    where session_id = p_session and user_id = v_uid;
  if v_role is null then raise exception 'not_a_member'; end if;

  select status into v_status from public.team_sessions where id = p_session;
  if v_status is null then raise exception 'no_such_session'; end if;

  -- idempotency: a retried action (same key) returns the original result
  if p_idempotency_key is not null then
    select * into v_prior from public.session_events
      where session_id = p_session and actor_id = v_uid and idempotency_key = p_idempotency_key;
    if found then return v_prior; end if;
  end if;

  if not public.session_action_allowed(p_type, v_role, v_status) then
    raise exception 'action_not_allowed: % for role % in status %', p_type, v_role, v_status;
  end if;

  -- Compute head + insert, retrying on a concurrent seq collision (unpinned only).
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
      -- a pinned caller wanted an exact head → surface it; otherwise recompute + retry
      if p_expected_seq is not null then raise; end if;
      if i = 8 then raise; end if;
    end;
  end loop;

  if not v_ok then raise exception 'seq_insert_failed after retries'; end if;

  insert into public.session_state(session_id, seq) values (p_session, v_next)
    on conflict (session_id) do update set seq = greatest(public.session_state.seq, excluded.seq), updated_at = now();

  -- lobby ready-check side effects (§13.11): the "I'm ready" click also = ROE ack
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

-- Verification (manual): fire two concurrent unpinned actions on one session and
-- confirm both land with consecutive seqs and no duplicate-key error surfaces.
