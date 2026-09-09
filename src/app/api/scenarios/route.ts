import { NextResponse } from "next/server";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { getAuthedUser } from "@/lib/auth/apiGuard";

/**
 * Scenario catalogue (metadata only — no answer key). This response is already
 * clean, but the route previously relied SOLELY on the edge middleware's
 * default-deny for access control. L-02 (defense-in-depth): assert the gate
 * explicitly here too, mirroring the sibling `GET /api/scenarios/[slug]`, so
 * the route does not depend on middleware alone. In local/no-Supabase dev
 * `getAuthedUser()` returns null and this 401s exactly as `[slug]` does — the
 * scenario list page builds from the SCENARIOS import server-side, not this API,
 * so nothing guest-facing depends on it.
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  return NextResponse.json({
    scenarios: SCENARIOS.map(s => ({
      slug: s.slug,
      title: s.title,
      summary: s.summary,
      difficulty: s.difficulty,
      attack_kind: s.attack_kind,
      threat_actor: s.threat_actor,
    })),
  });
}
