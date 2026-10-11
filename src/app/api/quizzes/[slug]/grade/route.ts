import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { paramOf } from "@/lib/http/params";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { resolveGradableQuiz } from "@/lib/quizzes/resolve";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { recordAndLoadFirstAnswers } from "@/lib/xp/firstAnswers";

export const runtime = "nodejs";

/**
 * POST /api/quizzes/[slug]/grade
 *
 * Server-side grading for a standalone quiz, mirroring
 * `POST /api/scenarios/[slug]/grade`. The QuizClient submits the learner's
 * selection(s); the server grades them against the FULL quiz (resolved through
 * `resolveGradableQuiz` — built-ins + org-published) and returns, PER ANSWERED
 * QUESTION ONLY, whether it was correct plus the correct option index +
 * explanation.
 *
 * ANTI-HARVEST: the page ships a sanitized quiz (no `answer`/`explanation`), so
 * the learner never has the key up front. A question's answer + explanation is
 * revealed only once a STRUCTURALLY VALID selection (a real option index for
 * THAT question) has been submitted for it — the QuizClient grades one question
 * at a time, at confirm, so a `{}` POST reveals nothing.
 *
 * No hard auth gate: like the Rooms submit route, quizzes are guest-usable; the
 * edge middleware already default-denies anonymous callers in production. This
 * keeps local/no-Supabase dev working.
 *
 * FIRST ANSWER (0078): for a signed-in learner each question's first graded
 * answer is recorded (graded_first_answers). Once the key is revealed a later
 * correct answer earns only half its XP at /finish — see src/lib/xp/firstAnswers.ts.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const user = await getAuthedUser();
  const { slug: rawSlug } = await params;
  const slug = paramOf(rawSlug);

  const quiz = await resolveGradableQuiz(slug, user?.orgId ?? null);
  if (!quiz) {
    return NextResponse.json({ error: "Quiz not found." }, { status: 404 });
  }

  let body: { answers?: Record<string, number> };
  try {
    body = asObject(await req.json());
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }
  const answers = body?.answers ?? {};

  const results = quiz.questions.map(q => {
    const submitted = answers[q.id];
    const answered =
      typeof submitted === "number" &&
      Number.isInteger(submitted) &&
      submitted >= 0 &&
      submitted < q.options.length;
    return {
      id: q.id,
      correct: answered ? submitted === q.answer : false,
      // Revealed only for a question the learner actually attempted.
      answer: answered ? q.answer : null,
      explanation: answered ? q.explanation : null,
    };
  });

  if (user) {
    const admin = getSupabaseAdminClient();
    const answered = quiz.questions
      .map((q, i) => ({ q, r: results[i] }))
      .filter(({ r }) => r.answer !== null)
      .map(({ q, r }) => ({ questionId: q.id, answer: answers[q.id], correct: r.correct }));
    if (admin && answered.length > 0) {
      // The first answer must be on record BEFORE the key is revealed — otherwise
      // /finish would later record the corrected answer as the "first" one.
      const recorded = await recordAndLoadFirstAnswers(admin, user.id, "quiz", slug, answered);
      if (!recorded) return NextResponse.json({ error: "Couldn't save your answer — please try again." }, { status: 503 });
    }
  }

  return NextResponse.json({ results });
}
