import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { resolveGradableQuiz } from "@/lib/quizzes/resolve";

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
 * No hard auth gate: like the Rooms submit route, quizzes are guest-usable and
 * grading has no user-specific side effect; the edge middleware already
 * default-denies anonymous callers in production. The session is read only to
 * scope org-authored quiz resolution. This keeps local/no-Supabase dev working.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const user = await getAuthedUser();
  const { slug: rawSlug } = await params;
  const slug = decodeURIComponent(rawSlug);

  const quiz = await resolveGradableQuiz(slug, user?.orgId ?? null);
  if (!quiz) {
    return NextResponse.json({ error: "Quiz not found." }, { status: 404 });
  }

  let body: { answers?: Record<string, number> };
  try {
    body = await req.json();
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

  return NextResponse.json({ results });
}
