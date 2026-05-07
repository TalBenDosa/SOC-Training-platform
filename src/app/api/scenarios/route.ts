import { NextResponse } from "next/server";
import { SCENARIOS } from "@/lib/sim/scenarios";

export async function GET() {
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
