-- HACK THE SOC :: 0069 — Team-SOC security hardening (audit 2026-09-26, Phase 0)
-- ===========================================================================
-- S1  Every team SECURITY DEFINER function was executable by `anon` AND
--     `authenticated` (Postgres' default PUBLIC grant + Supabase's default
--     privileges; no team migration ever revoked). The system functions have NO
--     app caller — pg_cron runs them as `postgres` (their owner) — so a student
--     (or anyone holding the public anon key) could fire promote/replenish/reap
--     at will, or seed_session_timeline() a lobby session with 12 fake rows so
--     the real timeline is never seeded. → revoke from public, anon, authenticated.
--     The RLS/realtime helpers MUST stay executable by `authenticated` (policies
--     evaluate them as the querying role) — only `anon`/`public` is revoked.
-- S2  realtime.messages write policy allowed `broadcast`, so any member could
--     inject forged session_event broadcasts (fake "session.ended", huge seq that
--     blinds the gap-fill pull, fake actors). The app never sends broadcasts —
--     only the SECURITY DEFINER trigger does (as `postgres`, which bypasses RLS).
--     → members may only track PRESENCE.
-- S6  promote_due_injects() had no row lock and no pending guard, so concurrent
--     runs could promote the same inject twice. → FOR UPDATE SKIP LOCKED + guard.
-- Idempotent. Verification queries at the bottom.
-- ===========================================================================

-- ── S6: race-safe promote (logic otherwise identical to 0067) ──────────────
create or replace function public.promote_due_injects()
  returns int language plpgsql security definer set search_path = public as $$
declare r record; v_next bigint; v_count int := 0; v_type text; v_ok boolean;
begin
  for r in
    select i.* from public.session_injects i
    join public.team_sessions s on s.id = i.session_id
    where i.status = 'pending' and s.status = 'running'
      and s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval <= now()
    order by s.started_at + ((s.paused_ms + i.due_offset_ms) || ' milliseconds')::interval asc
    limit 500
    for update of i skip locked   -- a concurrent run skips rows this one holds
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
        if attempt = 8 then raise; end if;
      end;
    end loop;
    if v_ok then
      update public.session_injects set status = 'fired', fired_seq = v_next
        where id = r.id and status = 'pending';
      update public.session_state set seq = v_next, updated_at = now() where session_id = r.session_id;
      v_count := v_count + 1;
    end if;
  end loop;
  return v_count;
end $$;

-- ── S1: system functions — cron/service only ───────────────────────────────
revoke execute on function public.promote_due_injects()          from public, anon, authenticated;
revoke execute on function public.replenish_feed()               from public, anon, authenticated;
revoke execute on function public.reap_stale_team_sessions()     from public, anon, authenticated;
revoke execute on function public.seed_session_timeline(uuid)    from public, anon, authenticated;
revoke execute on function public.start_team_session(uuid)       from public, anon, authenticated;
grant  execute on function public.promote_due_injects()          to service_role;
grant  execute on function public.replenish_feed()               to service_role;
grant  execute on function public.reap_stale_team_sessions()     to service_role;

-- ── S1: player RPC + RLS/realtime helpers — signed-in users only ───────────
revoke execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) from public, anon;
revoke execute on function public.is_team_member(uuid, uuid)     from public, anon;
revoke execute on function public.is_session_staff(uuid)         from public, anon;
revoke execute on function public.team_topic_session(text)       from public, anon;
grant  execute on function public.apply_session_action(uuid, text, jsonb, bigint, text) to authenticated;
grant  execute on function public.is_team_member(uuid, uuid)     to authenticated;
grant  execute on function public.is_session_staff(uuid)         to authenticated;
grant  execute on function public.team_topic_session(text)       to authenticated;

-- ── S2: members may track presence, never send broadcasts ──────────────────
drop policy if exists "team session realtime write" on realtime.messages;
create policy "team session realtime write" on realtime.messages
  for insert to authenticated
  with check (
    extension = 'presence'
    and public.is_team_member(public.team_topic_session(realtime.topic()), auth.uid())
  );

-- Verification (expected):
--   select has_function_privilege('anon','public.promote_due_injects()','execute');          -- f
--   select has_function_privilege('authenticated','public.seed_session_timeline(uuid)','execute'); -- f
--   select has_function_privilege('authenticated','public.apply_session_action(uuid,text,jsonb,bigint,text)','execute'); -- t
--   select has_function_privilege('anon','public.apply_session_action(uuid,text,jsonb,bigint,text)','execute');          -- f
--   select has_function_privilege('authenticated','public.is_team_member(uuid,uuid)','execute'); -- t
--   select with_check from pg_policies where tablename='messages' and policyname='team session realtime write'; -- presence only
