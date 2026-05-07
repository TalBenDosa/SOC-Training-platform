import { NextResponse } from "next/server";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const limit = Number(url.searchParams.get("limit") ?? 200);
  const source = url.searchParams.get("source");
  let events = [...buildPhishingToExfil().events, ...buildBecScenario().events]
    .sort((a, b) => b.ts.localeCompare(a.ts));
  if (source) events = events.filter(e => e.source === source);
  return NextResponse.json({ events: events.slice(0, limit), total: events.length });
}
