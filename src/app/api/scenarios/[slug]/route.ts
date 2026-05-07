import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";

export async function GET(_req: Request, { params }: { params: { slug: string } }) {
  const bundle = buildScenarioBySlug(params.slug);
  if (!bundle) return NextResponse.json({ error: "Not found" }, { status: 404 });
  return NextResponse.json(bundle);
}
