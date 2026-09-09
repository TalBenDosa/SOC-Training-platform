import { NextResponse } from "next/server";
import { resolveGeneratedLesson } from "@/lib/lessons/lessonContent";

export const runtime = "nodejs";

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
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug } = await params;
  const raw = decodeURIComponent(slug);

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

  return NextResponse.json({
    results,
    correct,
    total,
    score,
    passed: score >= 70,
  });
}
