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
export async function GET(_req: Request, { params }: { params: { slug: string } }) {
  const user = await getAuthedUser();
  if (!user) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) return NextResponse.json({ error: "Not found" }, { status: 404 });

  // Everything the learner legitimately needs in order to investigate — and
  // nothing that tells them the answer.
  const { narrative: _narrative, learning_objectives: _objectives, ...rest } = bundle;

  return NextResponse.json({
    ...rest,
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
