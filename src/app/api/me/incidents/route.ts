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
import { isMissingSchema, recordIncident } from "@/lib/progress/record";

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

/**
 * GET /api/me/incidents: the storylines this learner met most recently (newest first, distinct), so a new
 * device or a cleared browser still never deals the same attack again (the live feed's draw avoids them).
 * Story ids only: no titles, no verdicts, nothing a learner could use as an answer.
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ storyIds: [], guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ storyIds: [] }, { status: 503 });
  const { data, error } = await admin.from("dashboard_incidents").select("story_id, created_at")
    .eq("user_id", user.id).not("story_id", "is", null).order("created_at", { ascending: false }).limit(60);
  if (error) return NextResponse.json({ storyIds: [] }, { status: isMissingSchema(error, "dashboard_incidents") ? 200 : 500 });
  const storyIds: string[] = [];
  for (const r of (data ?? []) as { story_id: string | null }[]) if (r.story_id && !storyIds.includes(r.story_id)) storyIds.push(r.story_id);
  return NextResponse.json({ storyIds: storyIds.slice(0, 12) }, { headers: { "Cache-Control": "no-store" } });
}
