import { NextResponse } from "next/server";
import { paramOf } from "@/lib/http/params";
import { resolveGeneratedLesson, parseLessonSlug } from "@/lib/lessons/lessonContent";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { recordAndLoadFirstAnswers } from "@/lib/xp/firstAnswers";

export const runtime = "nodejs";

const LESSON_PASS_PCT = 70;

/**
 * POST /api/lessons/{pathSlug}--{lessonSlug}/quiz/grade
 *
 * Server-side grading for a lesson's knowledge-check quiz, mirroring
 * `POST /api/scenarios/[slug]/grade`. The client (the lesson reader's Quiz
 * component) submits its per-question selections; the server grades them against
 * the FULL lesson (resolved through the same cache/generator the GET route uses)
 * and returns, PER ANSWERED QUESTION ONLY, whether it was correct plus the
 * correct answer + explanation.
 *
 * ANTI-HARVEST: the GET route strips `answer`/`explanation` from every question
 * so the learner must actually read the pages. Grading must not hand that back
 * for free — a question's answer + explanation is revealed only once a
 * STRUCTURALLY VALID selection (one of that question's real option values) has
 * been submitted for THAT question. An empty `{}` POST therefore reveals nothing.
 *
 * No hard auth gate: like the Rooms submit route, lesson quizzes are guest-usable
 * (progress is client-side, grading has no user-specific side effect), and the
 * edge middleware already default-denies anonymous callers in production. This
 * keeps local/no-Supabase dev working.
 *
 * LESSON XP (migration 0074): when a SIGNED-IN learner passes, the pass is
 * recorded server-side (record_lesson_quiz_pass). That recorded pass is what
 * POST /api/lessons/[slug]/complete requires before it credits the lesson's XP,
 * so a client can't claim a lesson it never passed. `saved` tells the reader
 * whether the pass was recorded (null for guests).
 *
 * FIRST ANSWER (0078): each question's first graded answer is recorded for a
 * signed-in learner. /complete pays the lesson's full XP only if those first
 * answers already passed the check; passing only after the key was revealed
 * earns half.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const raw = paramOf(slug);

  const resolved = await resolveGeneratedLesson(raw);
  if ("error" in resolved) {
    return NextResponse.json({ error: resolved.error }, { status: resolved.status });
  }
  const lesson = resolved.full;

  let body: { answers?: Record<string, string> };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }
  const answers = body?.answers ?? {};

  const results = lesson.quiz.map((q, i) => {
    // The client keys selections by question index; JSON stringifies the key.
    const submitted = answers[String(i)];
    const validValues = new Set(q.options.map(o => o.value));
    const answered = typeof submitted === "string" && validValues.has(submitted);
    return {
      index: i,
      correct: answered ? submitted === q.answer : false,
      // Revealed only for a question the learner actually attempted.
      answer: answered ? q.answer : null,
      explanation: answered ? q.explanation : null,
    };
  });

  const total = lesson.quiz.length;
  const correct = results.filter(r => r.correct).length;
  const score = total > 0 ? Math.round((correct / total) * 100) : 0;

  const passed = score >= LESSON_PASS_PCT;

  const user = await getAuthedUser();
  const admin = user ? getSupabaseAdminClient() : null;
  const parsed = parseLessonSlug(raw);
  if (user && admin && parsed) {
    const answered = results.filter(r => r.answer !== null)
      .map(r => ({ questionId: String(r.index), answer: answers[String(r.index)], correct: r.correct }));
    if (answered.length > 0) {
      // Recorded before the key is revealed (see quizzes/[slug]/grade).
      const recorded = await recordAndLoadFirstAnswers(admin, user.id, "lesson", `${parsed.pathSlug}--${parsed.lessonSlug}`, answered);
      if (!recorded) return NextResponse.json({ error: "Couldn't save your answers — please try again." }, { status: 503 });
    }
  }

  let saved: boolean | null = null;
  if (passed) {
    if (user && admin && parsed) {
      const { error } = await admin.rpc("record_lesson_quiz_pass", {
        p_user: user.id,
        p_key: `${parsed.pathSlug}--${parsed.lessonSlug}`,
        p_org: user.orgId ?? null,
        p_pct: score,
      });
      if (error) console.error("[lesson quiz grade] record_lesson_quiz_pass failed:", error.message);
      saved = !error;
    }
  }

  return NextResponse.json({
    results,
    correct,
    total,
    score,
    passed,
    saved,
  });
}
