-- 0114: containment before the scope is known brings the attacker back (T3 interface spec, stage D).
--
-- Until now the scope the Tier-3 confirmed had no effect on the exercise: the scripted twist fired on
-- the clock whatever the team did. From 0114, the moment a host is isolated (edr.host_isolated), the
-- server checks the scope. If a host the attack has already reached is neither isolated nor confirmed
-- in the Tier-3 scope register (0112), the attacker comes back FROM THAT HOST: one of its own attack
-- logs is queued again a minute later, as new activity. A complete scope blocks it.
--
--   * medium and hard sessions only (easy teaches the loop without the consequence);
--   * at most once per session;
--   * the queued row is a copy of a real attack log from the missed host (same native format), with a
--     new id; its staff-only answer is the original's plus { recompromise: <host> } so the report can
--     say "the attacker returned from X". Nothing about it is visible to players beyond the new log.
--
-- "Infected" = a host with an attack log (expected_verdict tp / escalate) that has already fired.
-- "Confirmed" = the register's latest state for the host is confirmed (t3.scope.entity, or a Tier-3
-- host_status finding of compromised), exactly as src/lib/team/t3Case.ts buildRegister reads it.
--
-- Idempotent: create or replace, drop trigger if exists.

begin;

create or replace function public.team_t3_recompromise() returns trigger
  language plpgsql security definer set search_path = public as $$
declare
  v_diff   text;
  v_start  timestamptz;
  v_pms    bigint;
  v_off    bigint;
  v_missed text;
  v_row    public.session_injects;
begin
  select difficulty, started_at, coalesce(paused_ms, 0) into v_diff, v_start, v_pms
    from public.team_sessions where id = NEW.session_id and status = 'running';
  if not found or v_diff = 'easy' or v_start is null then return NEW; end if;
  if exists (select 1 from public.session_injects where session_id = NEW.session_id and expected_action ? 'recompromise') then
    return NEW;
  end if;

  with attack as (
    select lower(split_part(i.body->>'hostname', '.', 1)) as k, count(*) as n
      from public.session_injects i
     where i.session_id = NEW.session_id and i.channel = 'feed' and i.status = 'fired'
       and coalesce(i.expected_action->>'expected_verdict', i.body->>'expected_verdict', '') in ('tp', 'escalate')
       and coalesce(i.body->>'hostname', '') <> ''
     group by 1
  ), isolated as (
    select distinct lower(split_part(h.host, '.', 1)) as k from public.team_isolated_hosts(NEW.session_id) h
    union select lower(split_part(NEW.payload->>'host', '.', 1))
  ), latest as (
    select distinct on (k) k, st from (
      select lower(split_part(e.payload->>'entity', '.', 1)) as k, e.payload->>'state' as st, e.seq
        from public.session_events e
       where e.session_id = NEW.session_id and e.type = 't3.scope.entity'
         and coalesce(e.payload->>'entity_kind', 'host') <> 'account'
      union all
      select lower(split_part(e.payload->>'host', '.', 1)),
             case e.payload->>'status' when 'compromised' then 'confirmed' when 'not_compromised' then 'cleared' end, e.seq
        from public.session_events e
       where e.session_id = NEW.session_id and e.type = 'forensic.finding' and e.payload->>'kind' = 'host_status'
    ) x where k <> '' and st is not null
    order by k, seq desc
  )
  select a.k into v_missed
    from attack a
   where a.k not in (select k from isolated where k is not null)
     and a.k not in (select k from latest where st = 'confirmed')
   order by a.n desc, a.k
   limit 1;
  if v_missed is null then return NEW; end if;

  select i.* into v_row
    from public.session_injects i
   where i.session_id = NEW.session_id and i.channel = 'feed' and i.status = 'fired'
     and coalesce(i.expected_action->>'expected_verdict', i.body->>'expected_verdict', '') in ('tp', 'escalate')
     and lower(split_part(i.body->>'hostname', '.', 1)) = v_missed
   order by i.due_offset_ms desc
   limit 1;
  if v_row.id is null then return NEW; end if;

  v_off := floor(extract(epoch from (clock_timestamp() - v_start)) * 1000)::bigint - v_pms;
  insert into public.session_injects (session_id, due_offset_ms, channel, body, expected_action, status)
  values (NEW.session_id, v_off + 60000, 'feed',
          (v_row.body - 'id') || jsonb_build_object('id', coalesce(v_row.body->>'id', v_row.id::text) || '-rc'),
          coalesce(v_row.expected_action, '{}'::jsonb) || jsonb_build_object('recompromise', v_missed),
          'pending');
  return NEW;
end $$;

drop trigger if exists session_events_t3_recompromise on public.session_events;
create trigger session_events_t3_recompromise after insert on public.session_events
  for each row when (NEW.type = 'edr.host_isolated')
  execute function public.team_t3_recompromise();

revoke all on function public.team_t3_recompromise() from public, anon, authenticated;

commit;
