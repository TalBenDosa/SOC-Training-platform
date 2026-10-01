import { NextResponse } from "next/server";
import { paramOf } from "@/lib/http/params";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { resolveGradableQuiz } from "@/lib/quizzes/resolve";
import { recordAndLoadFirstAnswers, firstAnswerXp } from "@/lib/xp/firstAnswers";

export const runtime = "nodejs";

/**
 * POST /api/quizzes/[slug]/finish
 *
 * Credits a finished standalone quiz to the learner's overall score. Before this
 * route existed the quiz page only DISPLAYED "+N XP earned" — nothing was
 * recorded, so profiles.xp (server-authoritative, see migration 0070) never
 * moved (user report 2026-09-24).
 *
 * The client sends every answer it confirmed; the server RE-GRADES them against
 * the full key (never trusts a client-computed score), pays each question under
 * the first-answer rule (full XP if the learner's FIRST graded answer to it was
 * right, half if they only got it right after the key was revealed — 0078,
 * src/lib/xp/firstAnswers.ts), then records the attempt
 * through record_quiz_attempt(): only the BEST attempt per quiz counts, so
 * retries can't farm XP. The trigger on quiz_progress recomputes profiles.xp in
 * the same transaction and the new total is returned so the UI can show it.
 *
 * Guests / no-Supabase dev get { guest: true } and keep a local best instead.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to save quiz XP.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Progress storage isn't configured.", guest: true }, { status: 503 });

  const { slug: rawSlug } = await params;
  const slug = paramOf(rawSlug);
  const quiz = await resolveGradableQuiz(slug, user.orgId ?? null);
  if (!quiz) return NextResponse.json({ error: "Quiz not found." }, { status: 404 });

  let body: { answers?: Record<string, unknown> };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const answers = body?.answers && typeof body.answers === "object" ? body.answers : {};

  const graded = quiz.questions.map(q => {
    const a = answers[q.id];
    const valid = typeof a === "number" && Number.isInteger(a) && a >= 0 && a < q.options.length;
    return { q, a, valid, correct: valid && a === q.answer };
  });
  // Normally every answer was already recorded at /grade; anything missing is
  // recorded now, as its first answer.
  const first = await recordAndLoadFirstAnswers(admin, user.id, "quiz", slug,
    graded.filter(g => g.valid).map(g => ({ questionId: g.q.id, answer: g.a, correct: g.correct })));
  if (!first) return NextResponse.json({ error: "Couldn't save your quiz result. Please try again." }, { status: 503 });

  let correct = 0;
  let xpEarned = 0;
  for (const g of graded) {
    if (g.correct) correct++;
    xpEarned += firstAnswerXp(g.q.xp, g.correct, first.get(g.q.id));
  }
  const total = quiz.questions.length;
  const scorePct = total ? Math.round((correct / total) * 100) : 0;

  const { data, error } = await admin.rpc("record_quiz_attempt", {
    p_user: user.id, p_slug: slug, p_org: user.orgId ?? null, p_xp: xpEarned, p_pct: scorePct,
  });
  if (error) {
    console.error("[quiz finish] record_quiz_attempt failed:", error.message);
    return NextResponse.json({ error: "Couldn't save your quiz result. Please try again." }, { status: 500 });
  }
  const row = (Array.isArray(data) ? data[0] : data) as { prev_best: number; best: number; total_xp: number } | undefined;
  const prevBest = row?.prev_best ?? 0;
  const bestXp = row?.best ?? xpEarned;

  return NextResponse.json({
    xpEarned,              // this attempt (re-graded server-side)
    scorePct,
    bestXp,                // what counts toward the overall score for this quiz
    delta: Math.max(0, bestXp - prevBest),
    totalXp: typeof row?.total_xp === "number" ? row.total_xp : null,
  });
}
