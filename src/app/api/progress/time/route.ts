import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { findLesson } from "@/lib/lessons/paths";
import { parseLessonSlug } from "@/lib/lessons/lessonContent";
import { resolveGradableQuiz } from "@/lib/quizzes/resolve";

export const runtime = "nodejs";

/**
 * One beat of ACTIVE time on a lesson or a quiz (migration 0109, content_time). Sent by
 * useTimeOnContent every minute while the page is visible and the learner is active, and
 * once more when the page is left (sendBeacon). The org admin sees the total beside the
 * target time a learning plan sets (src/lib/plans/timeSpent.ts).
 *
 * The item must exist (a catalogue lesson, a gradable quiz of this org), a beat is capped
 * at 120 seconds here and in add_content_time, and guests are not recorded. A missing table
 * (code deployed before the migration) is answered 204: time tracking is best effort and
 * must never show the learner an error.
 */
export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return new NextResponse(null, { status: 204 });
  const admin = getSupabaseAdminClient();
  if (!admin) return new NextResponse(null, { status: 204 });

  let body: Record<string, unknown>;
  try {
    const raw = await req.text();
    if (raw.length > 1000) return NextResponse.json({ error: "Too large." }, { status: 413 });
    const parsed = JSON.parse(raw);
    body = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }
  const kind = body.kind;
  const id = typeof body.id === "string" ? body.id.slice(0, 300) : "";
  const seconds = Math.floor(Number(body.seconds));
  if ((kind !== "lesson" && kind !== "quiz") || !id || !Number.isFinite(seconds) || seconds < 1) {
    return NextResponse.json({ error: "kind (lesson|quiz), id and seconds are required." }, { status: 400 });
  }

  let itemId: string | null = null;
  if (kind === "lesson") {
    const p = parseLessonSlug(id);
    if (p && findLesson(p.pathSlug, p.lessonSlug)) itemId = `${p.pathSlug}--${p.lessonSlug}`;
  } else {
    const quiz = await resolveGradableQuiz(id, user.orgId ?? null);
    if (quiz) itemId = id;
  }
  if (!itemId) return NextResponse.json({ error: "Not found." }, { status: 404 });

  const { error } = await admin.rpc("add_content_time", {
    p_user: user.id, p_org: user.orgId ?? null, p_kind: kind, p_item: itemId, p_seconds: Math.min(seconds, 120),
  });
  if (error) {
    // Not deployed yet (42883 function / 42P01 table): silently skip; anything else is logged.
    if (!/42883|42P01|does not exist/i.test(`${error.code ?? ""} ${error.message}`)) console.error("[progress time] add failed:", error.message);
    return new NextResponse(null, { status: 204 });
  }
  return new NextResponse(null, { status: 204 });
}
