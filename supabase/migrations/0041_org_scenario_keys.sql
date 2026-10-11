-- 0041_org_scenario_keys.sql
--
-- Two-projection answer-key split for org-authored SCENARIOS (Phase 2).
--
-- Unlike lessons/quizzes, a scenario's answer material (per-question answer +
-- explanation, the true verdict via attack_kind, the IOC truth list, narrative,
-- learning objectives, kill-chain) IS the whole exercise. content_scenarios is
-- RLS-readable (status='published') by any member of the org, so if that answer
-- material lived in content_scenarios.content, any student could read it with a
-- one-line browser query. It therefore must NOT live there.
--
-- content_scenarios.content holds ONLY the client-safe projection (briefing,
-- events to investigate, questions WITHOUT answers, derived alerts). The answer
-- material lives here, in a table the browser physically cannot read:
--   * RLS enabled, NO policy  -> deny-by-default for every client role
--   * revoke all from anon, authenticated -> no grant to subtract a policy from
-- Only the service role (which bypasses RLS) reads it — the scenario resolver
-- and the grade route recombine the two projections in server memory. This is
-- the DB equivalent of rooms.ts being server-only.
--
-- id 1:1 with content_scenarios(id), cascade-deleted with the parent row.

create table if not exists public.content_scenario_keys (
  id          text primary key references public.content_scenarios(id) on delete cascade,
  org_id      uuid references public.organizations(id) on delete cascade,
  answer_key  jsonb not null,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

drop trigger if exists content_scenario_keys_touch on public.content_scenario_keys;
create trigger content_scenario_keys_touch
  before update on public.content_scenario_keys
  for each row execute function public.touch_updated_at();

-- Deny-by-default: RLS on, no policy -> no client role can select/insert/update/
-- delete. The service role bypasses RLS and is the only reader/writer.
alter table public.content_scenario_keys enable row level security;

-- Belt-and-suspenders alongside the empty policy set: strip every client grant so
-- there is nothing for a future stray policy to act on.
revoke all on public.content_scenario_keys from anon, authenticated;
