import "server-only";
/**
 * LLM spend: metering + a pre-call budget check.
 *
 * Two problems this solves, both flagged in the technical audit:
 *  1. `ai_usage` existed since migration 0002 and nothing ever wrote to it — so
 *     real spend was invisible until the provider's bill arrived.
 *  2. Rate limiting caps request VOLUME, not dollars. A burst of long
 *     generations (max_tokens 8000 on the lesson route) from many students at
 *     once had no ceiling at all.
 *
 * The kill-switch is cheap to implement here because every LLM call site in this
 * codebase already has a deterministic fallback — grading is computed by rubric
 * first and the model only adds prose. So "over budget" degrades to exactly the
 * same experience as a deployment with no API key: it still works, it just isn't
 * personalised. Nothing breaks for the student.
 *
 * Failure policy: metering must never break a request. Every function here
 * swallows its own errors — a usage row that can't be written is logged, not
 * thrown, and a budget check that can't run FAILS OPEN (an outage in the meter
 * must not take the product's AI features down with it).
 */
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * USD per million tokens. Keep in sync with the provider's pricing page —
 * these are used for reporting and the budget check, not billing, so being
 * slightly stale is acceptable; being absent is not (an unknown model would
 * otherwise record zero cost and be invisible to the cap).
 */
const PRICING: Record<string, { in: number; out: number }> = {
  "claude-haiku-4-5-20251001": { in: 1.0,  out: 5.0  },
  "claude-sonnet-4-5":         { in: 3.0,  out: 15.0 },
  "claude-opus-4-5":           { in: 15.0, out: 75.0 },
};
/** Deliberately pessimistic: an unpriced model bills at the most expensive known rate. */
const FALLBACK_PRICING = { in: 15.0, out: 75.0 };

export function estimateCostUsd(model: string, inputTokens: number, outputTokens: number): number {
  const p = PRICING[model] ?? FALLBACK_PRICING;
  const cost = (inputTokens / 1_000_000) * p.in + (outputTokens / 1_000_000) * p.out;
  return Math.round(cost * 10_000) / 10_000; // numeric(10,4)
}

/** Anthropic's usage block, structurally typed so this doesn't import the SDK. */
export interface TokenUsage { input_tokens?: number; output_tokens?: number }

export async function recordAiUsage(args: {
  route: string;
  userId: string | null;
  orgId: string | null;
  model: string;
  usage: TokenUsage | undefined;
  provider?: string;
}): Promise<void> {
  try {
    const admin = getSupabaseAdminClient();
    if (!admin) return;
    const input = args.usage?.input_tokens ?? 0;
    const output = args.usage?.output_tokens ?? 0;

    const row: Record<string, unknown> = {
      user_id: args.userId,
      route: args.route,
      provider: args.provider ?? "anthropic",
      model: args.model,
      input_tokens: input,
      output_tokens: output,
      cost_usd: estimateCostUsd(args.model, input, output),
    };
    // org_id is NOT NULL with a bootstrap-org default (migration 0010), so only
    // set it when we actually know the tenant.
    if (args.orgId) row.org_id = args.orgId;

    const { error } = await admin.from("ai_usage").insert(row);
    if (error) console.error("[ai/usage] failed to record:", error.message);
  } catch (e) {
    console.error("[ai/usage] failed to record:", e);
  }
}

/**
 * Monthly ceilings in USD. Defaults are a backstop against the catastrophic
 * case (a runaway loop, a burst of expensive generations), set high enough that
 * ordinary use never reaches them. Raise/lower per deployment via env.
 */
const GLOBAL_CAP = Number(process.env.AI_MONTHLY_CAP_USD ?? 100);
const ORG_CAP    = Number(process.env.AI_ORG_MONTHLY_CAP_USD ?? 50);

export interface BudgetVerdict {
  allowed: boolean;
  reason?: "global_cap" | "org_cap";
  spentUsd?: number;
  capUsd?: number;
}

/**
 * Call BEFORE an LLM request. When it returns `allowed: false`, skip the model
 * and use the route's existing deterministic fallback.
 *
 * Fails OPEN on any error — a meter that can't be read must not disable the
 * product's AI features.
 */
export async function checkAiBudget(orgId: string | null): Promise<BudgetVerdict> {
  try {
    const admin = getSupabaseAdminClient();
    if (!admin) return { allowed: true };

    const { data: globalSpend, error: gErr } = await admin.rpc("ai_spend_usd", { p_org: null, p_days: 30 });
    if (gErr) return { allowed: true }; // fail open
    if (Number.isFinite(GLOBAL_CAP) && GLOBAL_CAP > 0 && Number(globalSpend) >= GLOBAL_CAP) {
      console.warn(`[ai/usage] GLOBAL 30d spend $${globalSpend} >= cap $${GLOBAL_CAP} — LLM calls disabled, falling back.`);
      return { allowed: false, reason: "global_cap", spentUsd: Number(globalSpend), capUsd: GLOBAL_CAP };
    }

    if (orgId && Number.isFinite(ORG_CAP) && ORG_CAP > 0) {
      const { data: orgSpend, error: oErr } = await admin.rpc("ai_spend_usd", { p_org: orgId, p_days: 30 });
      if (oErr) return { allowed: true };
      if (Number(orgSpend) >= ORG_CAP) {
        console.warn(`[ai/usage] ORG ${orgId} 30d spend $${orgSpend} >= cap $${ORG_CAP} — falling back.`);
        return { allowed: false, reason: "org_cap", spentUsd: Number(orgSpend), capUsd: ORG_CAP };
      }
    }

    return { allowed: true };
  } catch {
    return { allowed: true }; // fail open
  }
}
