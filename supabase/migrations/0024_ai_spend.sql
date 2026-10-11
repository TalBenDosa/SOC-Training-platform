-- ─────────────────────────────────────────────────────────────────────────────
-- 0024 — AI spend visibility
-- ─────────────────────────────────────────────────────────────────────────────
-- `ai_usage` has existed since 0002 with columns for input_tokens, output_tokens
-- and cost_usd — and nothing has ever written to it. The table is schema-only.
-- The practical consequence: rate limiting caps request VOLUME, but nobody can
-- see actual dollar spend until the provider's bill arrives, and a runaway loop
-- (or a burst of long generations from many students at once) has no ceiling.
--
-- This migration adds the read side. The write side is application code
-- (src/lib/ai/usage.ts), which records every LLM call.
--
-- `ai_spend_usd()` is SECURITY DEFINER because the spend check runs before an
-- LLM call on behalf of a student, who must not be able to read the whole org's
-- usage table. It returns a single number, never rows.
-- ─────────────────────────────────────────────────────────────────────────────

-- Sum-by-time-window is the only access pattern; created_at leads the index.
create index if not exists ai_usage_created_idx     on public.ai_usage (created_at desc);
create index if not exists ai_usage_org_created_idx on public.ai_usage (org_id, created_at desc);

create or replace function public.ai_spend_usd(
  p_org  uuid default null,
  p_days int  default 30
)
returns numeric
language sql
security definer
stable
set search_path = public
as $$
  select coalesce(sum(cost_usd), 0)::numeric
    from public.ai_usage
   where created_at >= now() - make_interval(days => greatest(1, least(p_days, 365)))
     and (p_org is null or org_id = p_org);
$$;

-- Service-role only: this aggregates across every tenant when p_org is null.
revoke all on function public.ai_spend_usd(uuid, int) from public, anon, authenticated;

comment on function public.ai_spend_usd(uuid, int) is
  'Total LLM spend in USD over the last p_days, optionally scoped to one org. Service-role only (a null p_org aggregates across all tenants). Used by the pre-call budget check in src/lib/ai/usage.ts.';

-- Verification:
--   select public.ai_spend_usd(null, 30) as spend_30d_all_orgs;
