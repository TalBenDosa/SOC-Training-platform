import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { getAuthedUser } from "@/lib/auth/apiGuard";

/**
 * Scenario bundle, sanitised.
 *
 * FINDING (fixed here). This route previously did `return NextResponse.json(bundle)`
 * with no authentication and no filtering. A live check against production
 * confirmed that an anonymous `GET /api/scenarios/ransomware-lockbit` returned:
 *
 *   - `answer` and `explanation` for all five questions — the complete answer key
 *   - `narrative` and `learning_objectives` — the post-submission debrief
 *
 * The scenario PAGE deliberately withholds the narrative and objectives from its
 * payload until the report is submitted, precisely so the analyst has to
 * reconstruct the attack from the logs. This endpoint handed all of it over in
 * a single unauthenticated request, which defeated that completely.
 *
 * Two changes:
 *   1. Authentication required — scenario content is for registered learners.
 *   2. The answer key and debrief are stripped server-side, so they cannot leak
 *      even to a signed-in user poking at the API. Grading happens in
 *      /api/scenarios/[slug]/grade, which compares against the real bundle on
 *      the server — the client never needs the answers in order to submit.
 *
 * Note: nothing in the app currently fetches this route (the scenario page
 * builds its bundle server-side via buildScenarioBySlug). It is kept, sanitised,
 * rather than deleted so any external or future client has a safe shape.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ slug: string }> }) {
  const user = await getAuthedUser();
  if (!user) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const { slug } = await params;
  const bundle = buildScenarioBySlug(slug);
  if (!bundle) return NextResponse.json({ error: "Not found" }, { status: 404 });

  // ALLOWLIST, not blacklist. A previous version stripped only `narrative` and
  // `learning_objectives` and spread `...rest`, which still shipped the three
  // fields that ARE the answer: `attack_kind` (the grader derives the verdict
  // from it — grade/route.ts), `iocs` (the exact values the evidence rubric
  // scores against), and `killchain` (the post-submission debrief), plus
  // `threat_actor` attribution. An allowlist fails closed: a field added to the
  // bundle later cannot leak here unless it is deliberately added below.
  const b = bundle as unknown as Record<string, unknown>;
  return NextResponse.json({
    scenario_id: b.scenario_id,
    title: b.title,
    briefing: b.briefing,
    difficulty: b.difficulty,
    alerts: b.alerts,
    events: b.events,
    questions: (bundle.questions ?? []).map(q => ({
      id: q.id,
      prompt: q.prompt,
      kind: q.kind,
      options: q.options,
      xp: q.xp,
      // `answer` and `explanation` are intentionally omitted — see header.
    })),
  });
}
