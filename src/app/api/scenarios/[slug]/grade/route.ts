import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";

export const runtime = "nodejs";

export async function POST(
  req: Request,
  { params }: { params: { slug: string } },
) {
  const slug = decodeURIComponent(params.slug);
  const bundle = buildScenarioBySlug(slug);
  if (!bundle) {
    return NextResponse.json({ error: "Scenario not found" }, { status: 404 });
  }

  const body = await req.json() as {
    answers: Record<string, string | string[]>;
    timeTaken: number;
    iocTagged: number;
  };

  const { answers = {}, timeTaken = 0, iocTagged = 0 } = body;

  // Grade each question
  const perQuestion = bundle.questions.map(q => {
    const submitted = answers[q.id];
    let correct = false;

    if (q.kind === "multi") {
      const expected = [...(q.answer as string[])].sort();
      const given = Array.isArray(submitted) ? [...submitted].sort() : [];
      correct = expected.length === given.length && expected.every((v, i) => v === given[i]);
    } else {
      correct = submitted === q.answer;
    }

    return {
      id: q.id,
      correct,
      yourAnswer: submitted ?? (q.kind === "multi" ? [] : ""),
      correctAnswer: q.answer,
      explanation: q.explanation,
      prompt: q.prompt,
      xp: q.xp,
    };
  });

  const correctCount = perQuestion.filter(q => q.correct).length;
  const score = Math.round((correctCount / bundle.questions.length) * 100);
  const xpEarned = perQuestion.filter(q => q.correct).reduce((s, q) => s + q.xp, 0) + iocTagged * 10;
  const timeBonusXp = timeTaken < 600 ? 50 : timeTaken < 1200 ? 25 : 0;
  const passed = score >= 70;

  // AI feedback (Claude) — falls back to static text if no API key
  let aiFeedback = passed
    ? `Good investigation on "${bundle.title}". You correctly identified ${correctCount}/${bundle.questions.length} attack stages. Keep practicing to master all kill-chain phases.`
    : `You scored ${score}% on "${bundle.title}". Review the missed questions, especially the ${perQuestion.filter(q => !q.correct).map(q => q.prompt.slice(0, 40)).join("; ")} concepts. Retry to improve your score.`;

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (apiKey) {
    try {
      const { default: Anthropic } = await import("@anthropic-ai/sdk");
      const client = new Anthropic({ apiKey });

      const wrongSummary = perQuestion
        .filter(q => !q.correct)
        .map(q => `"${q.prompt.slice(0, 80)}" (correct: ${Array.isArray(q.correctAnswer) ? q.correctAnswer.join(", ") : q.correctAnswer}; explanation: ${q.explanation})`)
        .join("; ");

      const msg = await client.messages.create({
        model: process.env.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
        max_tokens: 200,
        messages: [{
          role: "user",
          content: `You are a SOC training platform assistant. Give brief, encouraging 2-sentence feedback.

Student completed "${bundle.title}" scenario.
Score: ${score}% (${correctCount}/${bundle.questions.length} correct)
Time taken: ${Math.floor(timeTaken / 60)}m ${timeTaken % 60}s
IOCs tagged: ${iocTagged}
${wrongSummary ? `Questions missed: ${wrongSummary}` : "All questions correct!"}

Write exactly 2 sentences of actionable, encouraging feedback. Be specific to what they got wrong.`,
        }],
      });

      aiFeedback = msg.content
        .map(c => (c.type === "text" ? c.text : ""))
        .join("")
        .trim();
    } catch {
      // keep static fallback
    }
  }

  return NextResponse.json({ score, xpEarned, timeBonusXp, perQuestion, aiFeedback, passed });
}
