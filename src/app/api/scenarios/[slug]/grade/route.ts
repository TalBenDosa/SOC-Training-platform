import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { getAuthedUser } from "@/lib/auth/apiGuard";

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
    verdict?: string | null;
    verdictReason?: string;
    analystNotes?: string;
    findings?: string;
    indicators?: { type: string; value: string }[];
  };

  const {
    answers = {}, timeTaken = 0, iocTagged = 0,
    verdict = null, verdictReason = "", analystNotes = "", findings = "",
    indicators = [],
  } = body;

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
  // A scenario shipped with no questions used to divide by zero, making `score`
  // NaN and `passed` permanently false — it could never be completed.
  const quizScore = bundle.questions.length > 0
    ? Math.round((correctCount / bundle.questions.length) * 100)
    : 0;

  // ── Written report ────────────────────────────────────────────────────────
  // The report is the actual analyst deliverable, and it used to be discarded:
  // a blank report and a rigorous one scored identically. It is now graded on a
  // rubric, deterministically first so the result never depends on an API key.
  const reportText = [analystNotes, findings, verdictReason].join(" ").trim();
  const words = reportText.split(/\s+/).filter(Boolean).length;

  const expectedVerdict = bundle.attack_kind === "false_positive" ? "benign" : "malicious";
  const verdictCorrect = verdict === expectedVerdict;

  // Did they name the things that matter? Credit each scenario IOC they cite,
  // whether via the indicator list or in prose.
  const scenarioIocValues = (bundle.iocs ?? []).map(i => i.value.toLowerCase());
  const citedValues = new Set(
    indicators.map(i => String(i.value).toLowerCase().trim()).filter(Boolean),
  );
  const iocsCited = scenarioIocValues.filter(
    v => citedValues.has(v) || reportText.toLowerCase().includes(v),
  ).length;
  const iocCoverage = scenarioIocValues.length
    ? iocsCited / scenarioIocValues.length
    : 0;

  const reportRubric = {
    // Did they commit to a call at all, and was it right?
    verdict:  verdict ? (verdictCorrect ? 25 : 5) : 0,
    // Substance. Below ~40 words there is no analysis to assess.
    depth:    words >= 150 ? 25 : words >= 80 ? 18 : words >= 40 ? 10 : words > 0 ? 4 : 0,
    // Evidence: naming the indicators the incident actually turned on.
    evidence: Math.round(iocCoverage * 30),
    // Reasoning, not just assertion — did they justify the verdict?
    reasoning: verdictReason.trim().split(/\s+/).filter(Boolean).length >= 25 ? 20
             : verdictReason.trim().split(/\s+/).filter(Boolean).length >= 10 ? 12 : 0,
  };
  const reportScore = Math.min(
    100,
    reportRubric.verdict + reportRubric.depth + reportRubric.evidence + reportRubric.reasoning,
  );

  // Quiz and report both count. The quiz tests recognition; the report tests
  // whether they can actually communicate an incident, which is the job.
  const score = Math.round(quizScore * 0.6 + reportScore * 0.4);
  const xpEarned =
    perQuestion.filter(q => q.correct).reduce((s, q) => s + q.xp, 0) +
    iocTagged * 10 +
    Math.round(reportScore * 1.5);
  const timeBonusXp = timeTaken < 600 ? 50 : timeTaken < 1200 ? 25 : 0;
  const passed = score >= 70;

  // AI feedback (Claude) — falls back to static text if no API key
  const reportNote =
    reportScore >= 75 ? "Your written report was thorough — verdict, evidence and reasoning all present."
    : reportScore >= 45 ? "Your report covered the basics; cite more of the incident's indicators and justify the verdict in more depth."
    : "Your written report was thin. In a real SOC the report IS the deliverable: state a verdict, cite the indicators it rests on, and explain your reasoning.";

  let aiFeedback = passed
    ? `Good investigation on "${bundle.title}". You identified ${correctCount}/${bundle.questions.length} attack stages and scored ${reportScore}/100 on the report. ${reportNote}`
    : `You scored ${score}% on "${bundle.title}" (quiz ${quizScore}, report ${reportScore}). ${reportNote}`;

  // The paid LLM feedback is gated behind a signed-in user so anonymous callers
  // can't run up the AI bill. Guests still get full static feedback above.
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (apiKey && (await getAuthedUser())) {
    try {
      const { default: Anthropic } = await import("@anthropic-ai/sdk");
      const client = new Anthropic({ apiKey });

      const wrongSummary = perQuestion
        .filter(q => !q.correct)
        .map(q => `"${q.prompt.slice(0, 80)}" (correct: ${Array.isArray(q.correctAnswer) ? q.correctAnswer.join(", ") : q.correctAnswer}; explanation: ${q.explanation})`)
        .join("; ");

      const msg = await client.messages.create({
        model: process.env.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
        max_tokens: 320,
        messages: [{
          role: "user",
          content: `You are a SOC training platform assistant. Give brief, encouraging feedback.

Student completed "${bundle.title}" scenario.
Quiz: ${quizScore}% (${correctCount}/${bundle.questions.length} correct)
Report: ${reportScore}/100 — verdict ${verdict ?? "not given"} (expected ${expectedVerdict}), ${words} words, cited ${iocsCited}/${scenarioIocValues.length} key indicators
Time taken: ${Math.floor(timeTaken / 60)}m ${timeTaken % 60}s
${wrongSummary ? `Questions missed: ${wrongSummary}` : "All questions correct!"}

Their written analysis:
"""
${reportText.slice(0, 1500) || "(left blank)"}
"""

Write exactly 3 sentences of actionable, encouraging feedback. One sentence on the quiz, and TWO on the quality of their written analysis specifically — whether the verdict is supported, whether they cited the right evidence, and what a senior analyst would have added. Be concrete about their actual words.`,
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

  return NextResponse.json({
    score, xpEarned, timeBonusXp, perQuestion, aiFeedback, passed,
    quizScore,
    report: {
      score: reportScore,
      rubric: reportRubric,
      words,
      iocsCited,
      iocsTotal: scenarioIocValues.length,
      verdictCorrect,
    },
  });
}
