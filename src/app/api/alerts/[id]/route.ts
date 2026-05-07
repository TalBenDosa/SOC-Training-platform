import { NextResponse } from "next/server";
import { buildPhishingToExfil, buildBecScenario } from "@/lib/sim/scenarios";

export async function GET(_req: Request, { params }: { params: { id: string } }) {
  for (const b of [buildPhishingToExfil(), buildBecScenario()]) {
    const al = b.alerts.find(a => a.id === params.id);
    if (al) {
      const events = b.events.filter(e => al.related_events.includes(e.id));
      return NextResponse.json({ alert: al, events });
    }
  }
  return NextResponse.json({ error: "Not found" }, { status: 404 });
}
