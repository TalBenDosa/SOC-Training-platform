import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { SCENARIOS, buildScenarioBySlug } from "@/lib/sim/scenarios";

/**
 * Admin-only scenario data for the content console (/admin).
 *
 * The console used to import "@/lib/sim/scenarios" in the browser, which put
 * every scenario pack — questions, answers, explanations, IOCs — in a public
 * static chunk. It now asks the server:
 *   GET /api/admin/scenarios            → per-scenario admin metadata
 *   GET /api/admin/scenarios?slug=<s>   → that scenario's events, IOCs, question count (drawer)
 */
export async function GET(req: Request) {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;

  const slug = new URL(req.url).searchParams.get("slug");
  if (slug) {
    let bundle;
    try { bundle = buildScenarioBySlug(slug); } catch { bundle = null; }
    if (!bundle) return NextResponse.json({ error: "Scenario not found." }, { status: 404 });
    return NextResponse.json({ events: bundle.events, iocs: bundle.iocs, questionCount: bundle.questions.length });
  }

  const scenarios = SCENARIOS.map(s => {
    let logCount = 0;
    try { logCount = buildScenarioBySlug(s.slug)?.events.length ?? 0; } catch { /* broken pack → 0 */ }
    return { slug: s.slug, attack_kind: s.attack_kind, threat_actor: s.threat_actor, logCount };
  });
  return NextResponse.json({ scenarios }, { headers: { "Cache-Control": "private, no-store" } });
}
