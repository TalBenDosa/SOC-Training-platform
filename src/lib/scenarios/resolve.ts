import "server-only";
import type { ScenarioBundle } from "@/lib/sim/types";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { recombineScenario } from "@/lib/scenarios/authored";

/**
 * Resolve a scenario slug to a full, gradable ScenarioBundle — the single entry
 * point used by BOTH the play page and the grade route so authored scenarios go
 * through the same server-graded path as the static ones.
 *
 *  1. Static built-ins first (buildScenarioBySlug — sync, in-memory).
 *  2. Otherwise an org-authored DB scenario: load its client-safe projection
 *     (content_scenarios) + its answer key (content_scenario_keys, service-role
 *     only) and recombine them in server memory. The org boundary is re-asserted
 *     here because the service role bypasses RLS: a row is resolvable only if it
 *     is global (org_id null) or belongs to the caller's org.
 *
 * The recombined bundle carries the answer key; callers that hand it to the
 * client (the play page) must strip it — the grade route consumes it in full.
 */
export async function resolveScenarioBundle(slug: string, orgId: string | null): Promise<ScenarioBundle | null> {
  const staticBundle = buildScenarioBySlug(slug);
  if (staticBundle) return staticBundle;

  // Only org-namespaced ids can be DB scenarios; skip the round-trip otherwise.
  if (!slug.startsWith("org-")) return null;

  const admin = getSupabaseAdminClient();
  if (!admin) return null;

  const { data: row } = await admin
    .from("content_scenarios")
    .select("id, org_id, status, content")
    .eq("id", slug)
    .maybeSingle();
  if (!row) return null;

  // Re-assert the tenant boundary (service role bypassed RLS).
  if (row.org_id !== null && row.org_id !== orgId) return null;

  const content = (row.content ?? {}) as Record<string, unknown>;
  if (content.kind !== "authored") return null; // legacy generated scenarios don't grade here

  const { data: keyRow } = await admin
    .from("content_scenario_keys")
    .select("answer_key")
    .eq("id", slug)
    .maybeSingle();

  const answerKey = (keyRow?.answer_key ?? {}) as Record<string, unknown>;
  return recombineScenario(content, answerKey);
}
