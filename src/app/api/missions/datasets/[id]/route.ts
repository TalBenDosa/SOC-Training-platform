import { NextResponse } from "next/server";
import { getDataset } from "@/lib/missions/datasets";
import { paramOf } from "@/lib/http/params";

export const runtime = "nodejs";

/**
 * The VISIBLE copy of a mission dataset: the evidence tables a room's query
 * missions run on in the browser. Public like the rooms themselves (guests play
 * rooms too) and identical for everyone, so it caches. The shadow copy the
 * grader also uses never leaves the server (src/lib/missions/datasets).
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const ds = getDataset(paramOf(id));
  if (!ds) return NextResponse.json({ error: "Dataset not found." }, { status: 404 });
  return NextResponse.json(ds.visible, { headers: { "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400" } });
}
