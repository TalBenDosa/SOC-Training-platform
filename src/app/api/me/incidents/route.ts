/**
 * POST /api/me/incidents — records a live-feed attack the learner did not report.
 *
 * Reported incidents are stored by the grader itself (/api/dashboard/incident-report).
 * A MISS has no report to grade, so the live feed posts it here when the
 * "Learning Moment" debrief fires. The row feeds the learner's own Progress page
 * (missed attacks, response times); no XP or credit is read from it.
 */
import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { recordIncident } from "@/lib/progress/record";

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ saved: false, guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ saved: false }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  if (body.outcome !== "missed") return NextResponse.json({ error: "Only a missed attack is recorded here." }, { status: 400 });
  if (typeof body.title !== "string" || !body.title.trim()) return NextResponse.json({ error: "title is required." }, { status: 400 });

  const saved = await recordIncident(admin, {
    userId: user.id, orgId: user.orgId, outcome: "missed",
    incident: asObject(body.incident), company: body.company, title: body.title,
    mitre: body.mitre, missedTell: body.tell,
  });
  return NextResponse.json({ saved });
}
