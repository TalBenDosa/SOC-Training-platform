import { NextResponse } from "next/server";
import { getConsole } from "@/lib/missions/consoles";
import { paramOf } from "@/lib/http/params";

export const runtime = "nodejs";

/**
 * A room's investigation console (incidents, alerts, entities, detections, hunts) for its console
 * steps. Evidence only, public like the rooms and the same for everyone, so it caches. The tables it
 * queries come from the mission dataset (/api/missions/datasets/<id>); answer keys stay on the server.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const c = getConsole(paramOf(id));
  if (!c) return NextResponse.json({ error: "Console not found." }, { status: 404 });
  return NextResponse.json(c, { headers: { "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" } });
}
