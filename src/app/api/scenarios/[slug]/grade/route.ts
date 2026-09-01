import { NextResponse } from "next/server";
import { resolveScenarioBundle } from "@/lib/scenarios/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { checkAiBudget, recordAiUsage } from "@/lib/ai/usage";
import { scoreScenarioReport } from "@/lib/scenarios/reportScoring";

export const runtime = "nodejs";

export async function POST(
  req: Request,
  { params }: { params: Promise<{ slug: string }> },
) {
  // Explicit gate, matching the sibling GET route's fix (see its doc comment):
  // the edge middleware's default-deny already blocks anonymous callers when
  // Supabase is configured, but a route should not depend solely on that for
  // access it can trivially assert itself — and in local/no-Supabase mode the
  // middleware check is bypassed entirely, so this is the only gate left.
  const gradeUser = await getAuthedUser();
  if (!gradeUser) {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }

  const { slug: rawSlug } = await params;
  const slug = decodeURIComponent(rawSlug);
  // Resolves static built-ins AND org-authored DB scenarios (the latter get
  // their answer key merged in from the service-role-only key table).
  const bundle = await resolveScenarioBundle(slug, gradeUser.orgId);
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
    indicators?: { type: string; value: string }[];
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  const {
    answers = {}, timeTaken = 0,
    verdict = null, verdictReason = "", analystNotes = "",
    indicators = [],
  } = body;

  // Grade each question.
  //
  // ANTI-HARVEST: the sibling `GET /api/scenarios/[slug]` deliberately strips
  // answers/explanations so the learner must reason the incident out. Grading
  // must not hand that back for free — a student could otherwise POST a single
  // non-empty character for every question and read the entire answer key +
  // debrief without ever having looked at the scenario's real options.
  // Rule: you only see a question's correct answer + explanation once you have
  // actually committed a STRUCTURALLY VALID answer to THAT question — one of
  // its real option values (single) or a non-empty subset of them (multi).
  // This doesn't stop someone willing to read the options and pick blindly
  // (same bound the Rooms two-try model accepts elsewhere on this platform),
  // but it does stop a naive bot from bulk-scraping every scenario's answer
  // key + narrative with a single generic `{}`-shaped POST per question id.
  const isAnswered = (q: (typeof bundle.questions)[number], v: string | string[] | undefined) => {
    const validValues = new Set((q.options ?? []).map(o => o.value));
    if (q.kind === "multi") {
      return Array.isArray(v) && v.length > 0 && v.every(x => validValues.has(x));
    }
    return typeof v === "string" && validValues.has(v);
  };

  const perQuestion = bundle.questions.map(q => {
    const submitted = answers[q.id];
    const answered = isAnswered(q, submitted);
    let correct = false;

    if (q.kind === "multi") {
      const expected = [...(q.answer as string[])].sort();
      const given = Array.isArray(submitted) ? [...submitted].sort() : [];
      correct = expected.length === given.length && expected.every((v, i) => v === given[i]);
    } else {
      correct = submitted === q.answer;
    }

    // Show the human-readable option LABEL, never the internal option value:
    // feedback used to read "Correct: ext" (the value) instead of the real answer.
    const optLabel = (val: string) => (q.options ?? []).find(o => o.value === val)?.label ?? val;
    const toLabels = (a: string | string[]) => Array.isArray(a) ? a.map(optLabel) : optLabel(a);

    return {
      id: q.id,
      correct,
      yourAnswer: submitted !== undefined ? toLabels(submitted) : (q.kind === "multi" ? [] : ""),
      // Revealed only for a question the learner actually attempted.
      correctAnswer: answered ? toLabels(q.answer as string | string[]) : null,
      explanation: answered ? q.explanation : null,
      prompt: q.prompt,
      xp: q.xp,
    };
  });

  // A genuine attempt = every question answered AND a non-empty written report.
  // Only then is the full debrief (narrative / objectives / kill-chain) released.
  const attemptedAll = bundle.questions.length > 0 && bundle.questions.every(q => isAnswered(q, answers[q.id]));

  const correctCount = perQuestion.filter(q => q.correct).length;
  // A scenario shipped with no questions used to divide by zero, making `score`
  // NaN and `passed` permanently false — it could never be completed.
  const quizScore = bundle.questions.length > 0
    ? Math.round((correctCount / bundle.questions.length) * 100)
    : 0;

  // Deterministic rubric — extracted to a pure, unit-tested module (the IOC
  // widening is exploit-prone, so reportScoring.test.ts locks it down). See
  // reportScoring.ts for the evidence / fabrication / depth logic.
  const {
    reportText, words, expectedVerdict, verdictCorrect, verdictWrong,
    scenarioIocValues, iocsCited, usefulCitedCount, fabricated, misattributed,
    reportRubric, reportScore,
  } = scoreScenarioReport({
    verdict, verdictReason, analystNotes, indicators,
    iocs: bundle.iocs, events: bundle.events, attackKind: bundle.attack_kind,
  });

  // Quiz and report both count. The quiz tests recognition; the report tests
  // whether they can actually communicate an incident, which is the job.
  const score = Math.round(quizScore * 0.6 + reportScore * 0.4);
  const passed = score >= 70;
  const xpEarned =
    perQuestion.filter(q => q.correct).reduce((s, q) => s + q.xp, 0) +
    // Reward CITING REAL indicators (precision), not merely tagging any (recall).
    usefulCitedCount * 10 +
    Math.round(reportScore * 1.5);
  // The time bonus rewards thoroughness, not haste: only a PASSING investigation
  // earns it, so racing to a fast wrong/thin answer no longer pays.
  const timeBonusXp = passed ? (timeTaken < 600 ? 50 : timeTaken < 1200 ? 25 : 0) : 0;

  // AI feedback (Claude) — falls back to static text if no API key
  // The verdict is the analyst's headline output — a wrong call is called out
  // explicitly (it was silent before) and caps the report score.
  const calledVerdict = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : "no verdict";
  const verdictNote = verdictWrong
    ? ` ⚠ Your verdict was wrong — you called this ${calledVerdict}, the evidence shows ${expectedVerdict}. The verdict is the single most important output of an investigation, so a wrong call caps the report below passing.`
    : "";
  const fabricationNote = fabricated.length > 0
    ? ` ⚠ Your report cited ${fabricated.length} indicator${fabricated.length > 1 ? "s" : ""} that appear nowhere in this incident's telemetry — never invent evidence; cite only what the logs actually show.`
    : "";
  const misattributionNote = misattributed.length > 0
    ? ` ⚠ You tagged ${misattributed.join(", ")} as a hostile indicator — that is a known-benign address (a public DNS resolver, not adversary infrastructure). Tagging a benign or internal asset as malicious is a Tier-1 precision error.`
    : "";
  const reportNote =
    reportScore >= 75 ? "Your written report was thorough — verdict, evidence and reasoning all present."
    : reportScore >= 45 ? "Your report covered the basics; cite more of the incident's indicators and justify the verdict in more depth."
    : "Your written report was thin. In a real SOC the report IS the deliverable: state a verdict, cite the indicators it rests on, and explain your reasoning.";

  let aiFeedback = (passed
    ? `Good investigation on "${bundle.title}". You identified ${correctCount}/${bundle.questions.length} attack stages and scored ${reportScore}/100 on the report. ${reportNote}`
    : `You scored ${score}% on "${bundle.title}" (quiz ${quizScore}, report ${reportScore}). ${reportNote}`) + verdictNote + misattributionNote + fabricationNote;

  // The paid LLM feedback additionally requires org budget headroom — `gradeUser`
  // itself is guaranteed non-null here, since the whole route is now gated above.
  const apiKey = process.env.ANTHROPIC_API_KEY;
  // Spend ceiling (migration 0024): over budget, skip the model entirely. The
  // student still gets the full rubric-based feedback computed above — the same
  // experience as a deployment with no API key.
  const gradeBudget = apiKey && gradeUser ? await checkAiBudget(gradeUser.orgId) : { allowed: false };
  if (apiKey && gradeUser && gradeBudget.allowed) {
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

      await recordAiUsage({
        route: "/api/scenarios/[slug]/grade",
        userId: gradeUser.id,
        orgId: gradeUser.orgId,
        model: msg.model,
        usage: msg.usage,
      });
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
      verdictWrong,
      fabricated: fabricated.length,
      misattributed: misattributed.length,
    },
  });
}
