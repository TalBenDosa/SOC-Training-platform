import { NextResponse } from "next/server";
import { buildScenarioBySlug } from "@/lib/sim/scenarios";
import { getAuthedUser } from "@/lib/auth/apiGuard";

export const runtime = "nodejs";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  const { slug: rawSlug } = await params;
  const slug = decodeURIComponent(rawSlug);
  const bundle = buildScenarioBySlug(slug);
  if (!bundle) {
    return NextResponse.json({ error: "Scenario not found" }, { status: 404 });
  }

  let body: {
    answers?: Record<string, string | string[]>;
    timeTaken?: number;
    iocTagged?: number;
    verdict?: string | null;
    verdictReason?: string;
    analystNotes?: string;
    findings?: string;
    indicators?: { type: string; value: string }[];
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  const {
    answers = {}, timeTaken = 0, iocTagged = 0,
    verdict = null, verdictReason = "", analystNotes = "", findings = "",
    indicators = [],
  } = body;

  // Grade each question.
  //
  // ANTI-HARVEST: the sibling `GET /api/scenarios/[slug]` deliberately strips
  // answers/explanations so the learner must reason the incident out. Grading
  // must not hand that back for free — a student could otherwise POST an empty
  // body and read the entire answer key + debrief without solving anything.
  // Rule: you only see a question's correct answer + explanation once you have
  // actually committed an answer to THAT question. Unanswered → withheld.
  const isAnswered = (v: string | string[] | undefined) =>
    Array.isArray(v) ? v.length > 0 : typeof v === "string" && v.trim() !== "";

  const perQuestion = bundle.questions.map(q => {
    const submitted = answers[q.id];
    const answered = isAnswered(submitted);
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
      // Revealed only for a question the learner actually attempted.
      correctAnswer: answered ? q.answer : null,
      explanation: answered ? q.explanation : null,
      prompt: q.prompt,
      xp: q.xp,
    };
  });

  // A genuine attempt = every question answered AND a non-empty written report.
  // Only then is the full debrief (narrative / objectives / kill-chain) released.
  const attemptedAll = bundle.questions.length > 0 && bundle.questions.every(q => isAnswered(answers[q.id]));

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
  // The client sends the analyst's call as "tp"/"fp" (true/false positive);
  // normalise to the malicious/benign scheme the rubric compares against. Without
  // this, "tp" !== "malicious" made the 25-pt correct-verdict tier unreachable and
  // verdictCorrect permanently false — every right call scored as if wrong.
  const normalizedVerdict = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : verdict;
  const verdictCorrect = normalizedVerdict === expectedVerdict;

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

  // Fabrication check — penalise inventing indicators that appear NOWHERE in the
  // scenario's telemetry or IOC list. Citing an IP/hash/email that doesn't exist
  // is an integrity failure worse than citing none, and a real SOC report that
  // fabricates evidence is unusable. Mirrors the dashboard incident-report grader.
  const realValues = new Set(scenarioIocValues);
  const eventsBlob = JSON.stringify(bundle.events ?? []).toLowerCase();
  const claimed = new Set<string>();
  for (const m of reportText.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))  claimed.add(m[0].toLowerCase()); // IPv4
  for (const m of reportText.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g)) claimed.add(m[0].toLowerCase()); // email
  for (const m of reportText.matchAll(/\b[0-9a-f]{32,64}\b/gi))         claimed.add(m[0].toLowerCase()); // hash
  const isRealValue = (v: string) => realValues.has(v) || eventsBlob.includes(v);
  const fabricated = [...claimed].filter(v => v.length >= 4 && !isRealValue(v));

  const reportRubric = {
    // Did they commit to a call at all, and was it right?
    verdict:  verdict ? (verdictCorrect ? 25 : 5) : 0,
    // Substance. Below ~40 words there is no analysis to assess.
    depth:    words >= 150 ? 25 : words >= 80 ? 18 : words >= 40 ? 10 : words > 0 ? 4 : 0,
    // Evidence: naming the indicators the incident actually turned on — but a
    // fabricated indicator caps this near zero regardless of how many real ones
    // were cited.
    evidence: fabricated.length > 0 ? (iocsCited > 0 ? 5 : 0) : Math.round(iocCoverage * 30),
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
  const fabricationNote = fabricated.length > 0
    ? ` ⚠ Your report cited ${fabricated.length} indicator${fabricated.length > 1 ? "s" : ""} that appear nowhere in this incident's telemetry — never invent evidence; cite only what the logs actually show.`
    : "";
  const reportNote =
    reportScore >= 75 ? "Your written report was thorough — verdict, evidence and reasoning all present."
    : reportScore >= 45 ? "Your report covered the basics; cite more of the incident's indicators and justify the verdict in more depth."
    : "Your written report was thin. In a real SOC the report IS the deliverable: state a verdict, cite the indicators it rests on, and explain your reasoning.";

  let aiFeedback = (passed
    ? `Good investigation on "${bundle.title}". You identified ${correctCount}/${bundle.questions.length} attack stages and scored ${reportScore}/100 on the report. ${reportNote}`
    : `You scored ${score}% on "${bundle.title}" (quiz ${quizScore}, report ${reportScore}). ${reportNote}`) + fabricationNote;

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

  // The full debrief is the reward for a real attempt — released only when every
  // question was answered and a non-empty report was written. A blank/garbage
  // submission (answer-harvesting) gets score + per-question `correct` flags but
  // no narrative/objectives/kill-chain.
  const releaseDebrief = attemptedAll && words > 0;

  return NextResponse.json({
    score, xpEarned, timeBonusXp, perQuestion, aiFeedback, passed,
    quizScore,
    debriefWithheld: !releaseDebrief,
    // Withheld from the page payload so it is not readable in view-source during
    // the investigation; delivered here once a genuine attempt is in.
    debrief: releaseDebrief ? {
      narrative: bundle.narrative,
      learningObjectives: bundle.learning_objectives ?? [],
      killchain: bundle.killchain ?? [],
    } : null,
    report: {
      score: reportScore,
      rubric: reportRubric,
      words,
      iocsCited,
      iocsTotal: scenarioIocValues.length,
      verdictCorrect,
      fabricated: fabricated.length,
    },
  });
}
