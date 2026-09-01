import { NextResponse } from "next/server";
import { resolveScenarioBundle } from "@/lib/scenarios/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { checkAiBudget, recordAiUsage } from "@/lib/ai/usage";

export const runtime = "nodejs";

// Recursively flattens a scenario's telemetry down to its leaf string/number/
// boolean VALUES only — never object keys. Used to check whether a freely-typed
// indicator was genuinely observed in the incident's raw events, without also
// matching on structural field names like "vendor" or "hostname" (which
// `JSON.stringify` would otherwise expose as substrings of the whole blob).
function collectLeafValues(node: unknown, out: string[] = []): string[] {
  if (node == null) return out;
  if (typeof node === "string") {
    if (node) out.push(node);
    return out;
  }
  if (typeof node === "number" || typeof node === "boolean") {
    out.push(String(node));
    return out;
  }
  if (Array.isArray(node)) {
    for (const v of node) collectLeafValues(v, out);
    return out;
  }
  if (typeof node === "object") {
    for (const v of Object.values(node as Record<string, unknown>)) collectLeafValues(v, out);
    return out;
  }
  return out;
}

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
    answers = {}, timeTaken = 0, iocTagged = 0,
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
  const attemptedAll = bundle.questions.length > 0 && bundle.questions.every(q => isAnswered(q, answers[q.id]));

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
  const reportText = [analystNotes, verdictReason].join(" ").trim();
  const words = reportText.split(/\s+/).filter(Boolean).length;

  const expectedVerdict = bundle.attack_kind === "false_positive" ? "benign" : "malicious";
  // The client sends the analyst's call as "tp"/"fp" (true/false positive);
  // normalise to the malicious/benign scheme the rubric compares against. Without
  // this, "tp" !== "malicious" made the 25-pt correct-verdict tier unreachable and
  // verdictCorrect permanently false — every right call scored as if wrong.
  const normalizedVerdict = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : verdict;
  const verdictCorrect = normalizedVerdict === expectedVerdict;

  // ── Evidence / IOCs ───────────────────────────────────────────────────────
  // The curated bundle.iocs are the indicators the incident TURNED ON — the target
  // for "enough evidence". But per product direction, ANY indication that aids the
  // investigation counts as an IOC: an indicator the analyst pulled from the
  // telemetry that is not on the curated list is still valid investigative
  // evidence and earns credit. "Real" = on the IOC list OR appearing anywhere in
  // the scenario's events.
  const scenarioIocValues = (bundle.iocs ?? []).map(i => i.value.toLowerCase());
  const realValues = new Set(scenarioIocValues);
  // Leaf VALUES only (never object keys), joined on a separator a substring
  // match can't cross. `JSON.stringify(events)` was tried first and rejected:
  // it embeds every field NAME too ("vendor", "hostname", "process" are all
  // literal substrings of that blob), so typing the word "vendor" as a cited
  // indicator would "find" it. Restricting to values closes that hole.
  const eventsBlob = collectLeafValues(bundle.events ?? []).join("").toLowerCase();
  // A freely-typed indicator only counts as pulled-from-telemetry if it has
  // enough shape to plausibly BE an indicator (an IP/hash/email/hostname has a
  // digit, dot, @, underscore or hyphen, or is long enough not to be a common
  // word). Without this, a description field's ordinary prose ("...the backup
  // agent logon...") makes short common words like "the"/"log"/"get" match
  // almost any scenario's blob, letting a report earn full evidence credit by
  // pasting a handful of stopwords instead of citing real evidence.
  const looksLikeIndicator = (v: string) => v.length >= 6 || /[\d@._-]/.test(v);
  const isRealValue = (v: string) => realValues.has(v) || (looksLikeIndicator(v) && eventsBlob.includes(v));

  const citedValues = new Set(
    indicators.map(i => String(i.value).toLowerCase().trim()).filter(Boolean),
  );

  // How many of the curated KEY indicators they named — used only for honest
  // "you named X of the Y key indicators" feedback, not to cap the score.
  const iocsCited = scenarioIocValues.filter(
    v => citedValues.has(v) || reportText.toLowerCase().includes(v),
  ).length;

  // Every REAL indicator the analyst surfaced — tagged in the IOC list OR named in
  // the written report — counts toward evidence, not just the curated key set.
  const usefulCited = new Set<string>();
  for (const v of citedValues) if (v.length >= 3 && isRealValue(v)) usefulCited.add(v);
  for (const v of scenarioIocValues) if (reportText.toLowerCase().includes(v)) usefulCited.add(v);

  // Coverage credits ANY useful indicator, measured against the key-set size as
  // the "enough evidence" bar (capped at 1) — so citing helpful non-curated
  // indicators earns credit instead of being ignored.
  const iocTarget = Math.max(1, scenarioIocValues.length);
  const iocCoverage = Math.min(1, usefulCited.size / iocTarget);

  // Fabrication check — penalise inventing indicators that appear NOWHERE in the
  // scenario's telemetry or IOC list. Citing an IP/hash/email that doesn't exist
  // is an integrity failure worse than citing none, and a real SOC report that
  // fabricates evidence is unusable. Mirrors the dashboard incident-report grader.
  const claimed = new Set<string>();
  for (const m of reportText.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))  claimed.add(m[0].toLowerCase()); // IPv4
  for (const m of reportText.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g)) claimed.add(m[0].toLowerCase()); // email
  for (const m of reportText.matchAll(/\b[0-9a-f]{32,64}\b/gi))         claimed.add(m[0].toLowerCase()); // hash
  const fabricated = [...claimed].filter(v => v.length >= 4 && !isRealValue(v));

  const reportRubric = {
    // Did they commit to a call at all, and was it right?
    verdict:  verdict ? (verdictCorrect ? 25 : 5) : 0,
    // Substance. Below ~40 words there is no analysis to assess.
    depth:    words >= 150 ? 25 : words >= 80 ? 18 : words >= 40 ? 10 : words > 0 ? 4 : 0,
    // Evidence: naming the indicators the incident actually turned on — but a
    // fabricated indicator caps this near zero regardless of how many real ones
    // were cited.
    evidence: fabricated.length > 0 ? (usefulCited.size > 0 ? 5 : 0) : Math.round(iocCoverage * 30),
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
      fabricated: fabricated.length,
    },
  });
}
