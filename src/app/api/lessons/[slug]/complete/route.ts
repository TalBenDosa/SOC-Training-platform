import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { findLesson } from "@/lib/lessons/paths";
import { parseLessonSlug } from "@/lib/lessons/lessonContent";
import { lessonXpFromFirstAnswers } from "@/lib/xp/firstAnswers";

export const runtime = "nodejs";

/**
 * POST /api/lessons/{pathSlug}--{lessonSlug}/complete
 *
 * Credits a completed lesson to the learner's overall score. Before this route
 * the lesson reader's "Mark Complete" only flipped local state and toasted
 * "+N XP" — nothing was recorded, so profiles.xp never moved (audit 2026-09).
 *
 * SERVER-AUTHORITATIVE (migration 0074):
 *  - The XP comes from the lesson CATALOG (src/lib/lessons/paths.ts) looked up
 *    here — the client sends no amount. Full XP when the learner's FIRST graded
 *    answers already passed the knowledge check (graded_first_answers, 0078);
 *    half when they passed only after the key was revealed.
 *  - complete_lesson() credits it only if the lesson's knowledge check was
 *    PASSED and recorded server-side (the quiz grade route stamps
 *    quiz_passed_at), and only ONCE — the first completion. Repeat calls return
 *    status "already" with credited 0.
 *  - The trigger on lesson_progress recomputes profiles.xp in the same
 *    transaction; the new total is returned so the UI shows what was credited.
 *
 * Guests / no-Supabase dev get { guest: true } and keep a local record instead.
 */
export async function POST(
  _req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to save lesson XP.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Progress storage isn't configured.", guest: true }, { status: 503 });

  const { slug } = await params;
  const parsed = parseLessonSlug(decodeURIComponent(slug));
  const found = parsed ? findLesson(parsed.pathSlug, parsed.lessonSlug) : null;
  if (!parsed || !found) return NextResponse.json({ error: "Lesson not found." }, { status: 404 });
  const lessonKey = `${parsed.pathSlug}--${parsed.lessonSlug}`;

  const { data: firsts, error: firstErr } = await admin.from("graded_first_answers")
    .select("correct").eq("user_id", user.id).eq("kind", "lesson").eq("content_id", lessonKey);
  if (firstErr) {
    console.error("[lesson complete] first answers read failed:", firstErr.message);
    return NextResponse.json({ error: "Couldn't save your lesson completion. Please try again." }, { status: 503 });
  }
  const lessonXp = lessonXpFromFirstAnswers(found.lesson.xp, (firsts ?? []).map(r => !!r.correct));

  const { data, error } = await admin.rpc("complete_lesson", {
    p_user: user.id, p_key: lessonKey, p_org: user.orgId ?? null, p_xp: lessonXp,
  });
  if (error) {
    console.error("[lesson complete] complete_lesson failed:", error.message);
    return NextResponse.json({ error: "Couldn't save your lesson completion. Please try again." }, { status: 500 });
  }
  const row = (Array.isArray(data) ? data[0] : data) as
    | { status: string; credited: number; xp_earned: number; total_xp: number | null; completed_at: string | null }
    | undefined;

  if (!row || row.status === "quiz_not_passed") {
    return NextResponse.json(
      { error: "Pass the knowledge check first — your pass wasn't recorded.", code: "quiz_not_passed" },
      { status: 409 },
    );
  }

  return NextResponse.json({
    status: row.status,                 // "credited" | "already"
    credited: row.credited ?? 0,        // XP added to the overall score by THIS call
    xpEarned: row.xp_earned ?? 0,       // what this lesson counts for overall
    totalXp: typeof row.total_xp === "number" ? row.total_xp : null,
    completedAt: row.completed_at,
  });
}
