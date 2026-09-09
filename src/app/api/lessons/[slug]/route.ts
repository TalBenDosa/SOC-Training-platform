/**
 * GET /api/lessons/{pathSlug}--{lessonSlug}
 *
 * Returns AI-generated lesson content (10 pages + 4-question quiz).
 *
 * Content generation, the process-lifetime cache, and the stub fallback all now
 * live in `@/lib/lessons/lessonContent` so that this route AND the server-side
 * quiz grader resolve the same content through one path.
 *
 * SECURITY (M-01): the quiz answer key (`answer` + `explanation`) is stripped
 * here via `stripLessonQuiz` — it never crosses to the client. Correctness is
 * revealed per-answered-question by POST /api/lessons/[slug]/quiz/grade, exactly
 * as scenarios reveal a question's answer only after it has been answered.
 */

import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { resolveGeneratedLesson, stripLessonQuiz } from "@/lib/lessons/lessonContent";

// Re-exported so existing importers (the lesson reader) keep their import path.
export type {
  LessonPage,
  LessonQuizQuestion,
  GeneratedLesson,
  ClientLesson,
  ClientLessonQuizQuestion,
} from "@/lib/lessons/lessonContent";

export const runtime = "nodejs";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  // L-02 (defense-in-depth): assert the auth posture explicitly here rather than
  // leaning only on the edge middleware's default-deny. Guests are DELIBERATELY
  // allowed — they receive stub content (this is the no-Supabase / no-API-key
  // convention), so we do not 401; a hard gate would break local dev and the
  // guest experience. `getAuthedUser()` is React-cache()d, so this shares its
  // read with the one inside resolveGeneratedLesson (no extra round-trip).
  await getAuthedUser();

  const { slug } = await params;
  const raw = decodeURIComponent(slug);

  const resolved = await resolveGeneratedLesson(raw);
  if ("error" in resolved) {
    return NextResponse.json({ error: resolved.error }, { status: resolved.status });
  }

  // Answer key stripped before it ever reaches the browser.
  return NextResponse.json(stripLessonQuiz(resolved.full));
}
