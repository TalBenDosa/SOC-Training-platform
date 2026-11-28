-- 0124: a shift can hold several reported incidents (Tal, 2026-11-28).
--
-- The SOC Manager now reports a chosen case to management (incident.declared carries
-- payload.case.event_id). Until here a second incident.declared was refused outright, so a
-- second, unrelated attack could only join the first incident. The rule becomes:
--   * the first report is accepted as before (with or without a case);
--   * a further report must name a case, and that case must not be reported already.
--
-- The validation function is long and is the dev line's as well, so this migration patches
-- the one rule in the stored definition instead of restating the whole function. It is
-- idempotent, and it fails loudly if the old rule is not found.
--
-- Verify (staging): declare with case A -> ok; declare with case A again -> refused;
-- declare with no case -> refused ("already declared"); declare with case B -> ok.

do $mig$
declare
  v_def text;
  v_new text;
begin
  select pg_get_functiondef('public.team_validate_action(uuid, uuid, text, jsonb)'::regprocedure) into v_def;
  if position('this case is already reported' in v_def) > 0 then
    raise notice '0124: already applied';
    return;
  end if;
  v_new := regexp_replace(
    v_def,
    $re$if exists \(select 1 from public\.session_events where session_id = p_session and type = 'incident\.declared'\) then\s+raise exception 'invalid_payload: the incident is already declared';\s+end if;$re$,
    $new$if exists (select 1 from public.session_events where session_id = p_session and type = 'incident.declared') then
      if coalesce(p_payload->'case'->>'event_id', '') = '' then
        raise exception 'invalid_payload: the incident is already declared';
      end if;
      if exists (select 1 from public.session_events
                  where session_id = p_session
                    and ((type = 'incident.declared' and payload->'case'->>'event_id' = p_payload->'case'->>'event_id')
                      or (type = 'decision.logged' and payload->>'kind' = 'incident_case' and payload->>'event_id' = p_payload->'case'->>'event_id'))) then
        raise exception 'invalid_payload: this case is already reported';
      end if;
    end if;$new$);
  if v_new = v_def then
    raise exception '0124: the incident.declared rule was not found in team_validate_action';
  end if;
  execute v_new;
end
$mig$;

-- privileges unchanged (create or replace keeps them); restated as in 0097
revoke execute on function public.team_validate_action(uuid, uuid, text, jsonb) from public, anon, authenticated;
grant  execute on function public.team_validate_action(uuid, uuid, text, jsonb) to service_role;
