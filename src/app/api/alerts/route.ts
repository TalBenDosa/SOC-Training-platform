import { NextResponse } from "next/server";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";

export async function GET(req: Request) {
  const url = new URL(req.url);
  const severity = url.searchParams.get("severity");
  const limit = Number(url.searchParams.get("limit") ?? 50);
  let alerts = [...buildPhishingToExfil().alerts, ...buildBecScenario().alerts]
    .sort((a, b) => b.detected_at.localeCompare(a.detected_at));
  if (severity) alerts = alerts.filter(a => a.severity === severity);
  return NextResponse.json({ alerts: alerts.slice(0, limit), total: alerts.length });
}
