import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { issueAttemptToken } from "@/lib/grading/attemptToken";

export const runtime = "nodejs";

/**
 * Starts an investigation attempt. Returns a signed token the grade endpoint
 * requires, and from which it computes the elapsed time server-side.
 */
export async function POST(_req: Request, { params }: { params: { slug: string } }) {
  const slug = decodeURIComponent(params.slug);
  if (!buildScenarioBySlug(slug)) {
    return NextResponse.json({ error: "Scenario not found" }, { status: 404 });
  }
  return NextResponse.json(issueAttemptToken(slug));
}
