import { z } from "zod";
import type { ScenarioBundle } from "@/lib/sim/types";
import { expectedVerdictFor } from "@/lib/sim/types";

/**
 * Pure scenario grading: quiz + written report → score, XP, per-question
 * results and the rubric. No I/O, no LLM, no auth — the route handler owns
 * those. Everything here is deterministic so a test can pin the numbers.
 */

const MAX_TEXT = 5000;

export const submissionSchema = z.object({
  attemptToken: z.string().min(1).max(256),
  answers: z.record(z.string().max(64), z.union([z.string().max(200), z.array(z.string().max(200)).max(20)])),
  verdict: z.enum(["tp", "fp"]),
  verdictReason: z.string().max(MAX_TEXT).default(""),
  analystNotes: z.string().max(MAX_TEXT).default(""),
  findings: z.string().max(MAX_TEXT).default(""),
  indicators: z.array(z.object({
    type: z.string().max(32),
    value: z.string().max(512),
  })).max(50).default([]),
});

export type Submission = z.infer<typeof submissionSchema>;

export interface PerQuestionResult {
  id: string;
  correct: boolean;
  yourAnswer: string | string[];
  correctAnswer: string | string[];
  explanation: string;
  prompt: string;
  xp: number;
}

export interface ReportRubric {
  verdict: number;
  depth: number;
  evidence: number;
  reasoning: number;
}

export interface GradeOutcome {
  score: number;
  passed: boolean;
  quizScore: number;
  correctCount: number;
  perQuestion: PerQuestionResult[];
  xpEarned: number;
  timeBonusXp: number;
  report: {
    score: number;
    rubric: ReportRubric;
    words: number;
    iocsCited: number;
    iocsTotal: number;
    verdictCorrect: boolean;
    expectedVerdict: "tp" | "fp";
    text: string;
  };
}

export const PASS_MARK = 70;

function wordCount(text: string): number {
  return text.trim().split(/\s+/).filter(Boolean).length;
}

/** True when `value` appears in `text` as a whole token, not inside a longer word. */
function citesValue(text: string, value: string): boolean {
  if (!value) return false;
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^a-z0-9_])${escaped}([^a-z0-9_]|$)`, "i").test(text);
}

/**
 * Returns the ids of questions the submission did not answer. A submission
 * with any of these is incomplete and must not be graded: grading returns the
 * key, so an empty submission would be a free answer sheet.
 */
export function unansweredQuestions(bundle: ScenarioBundle, answers: Submission["answers"]): string[] {
  return bundle.questions
    .filter(q => {
      const a = answers[q.id];
      if (a === undefined) return true;
      return Array.isArray(a) ? a.length === 0 : a === "";
    })
    .map(q => q.id);
}

export function gradeSubmission(
  bundle: ScenarioBundle,
  submission: Submission,
  elapsedSeconds: number,
): GradeOutcome {
  const { answers, verdict, verdictReason, analystNotes, findings, indicators } = submission;

  const perQuestion: PerQuestionResult[] = bundle.questions.map(q => {
    const submitted = answers[q.id];
    let correct: boolean;
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
  // A scenario with no questions used to divide by zero (NaN score, never passable).
  const quizScore = bundle.questions.length > 0
    ? Math.round((correctCount / bundle.questions.length) * 100)
    : 0;

  // ── Written report ──────────────────────────────────────────────────────
  const reportText = [analystNotes, findings, verdictReason].join(" ").trim();
  const words = wordCount(reportText);
  const reasonWords = wordCount(verdictReason);

  const expectedVerdict = expectedVerdictFor(bundle);
  const verdictCorrect = verdict === expectedVerdict;

  // Credit each scenario IOC the analyst cites, via the indicator list or in prose.
  const scenarioIocValues = (bundle.iocs ?? []).map(i => i.value.toLowerCase());
  const citedValues = new Set(indicators.map(i => i.value.toLowerCase().trim()).filter(Boolean));
  const iocsCited = scenarioIocValues.filter(v => citedValues.has(v) || citesValue(reportText, v)).length;
  const iocCoverage = scenarioIocValues.length ? iocsCited / scenarioIocValues.length : 0;

  const rubric: ReportRubric = {
    verdict:   verdictCorrect ? 25 : 5,
    depth:     words >= 150 ? 25 : words >= 80 ? 18 : words >= 40 ? 10 : words > 0 ? 4 : 0,
    evidence:  Math.round(iocCoverage * 30),
    reasoning: reasonWords >= 25 ? 20 : reasonWords >= 10 ? 12 : 0,
  };
  const reportScore = Math.min(100, rubric.verdict + rubric.depth + rubric.evidence + rubric.reasoning);

  // Quiz tests recognition; the report tests whether they can communicate an incident.
  const score = Math.round(quizScore * 0.6 + reportScore * 0.4);
  const passed = score >= PASS_MARK;

  // XP is computed entirely from server-verified inputs. The old `iocTagged`
  // field let the client claim any number of tagged IOCs for 10 XP each, and
  // rewarded the same indicators a second time through the evidence rubric.
  const xpEarned =
    perQuestion.filter(q => q.correct).reduce((s, q) => s + q.xp, 0) +
    iocsCited * 10 +
    Math.round(reportScore * 1.5);
  const timeBonusXp = elapsedSeconds < 600 ? 50 : elapsedSeconds < 1200 ? 25 : 0;

  return {
    score, passed, quizScore, correctCount, perQuestion, xpEarned, timeBonusXp,
    report: {
      score: reportScore, rubric, words, iocsCited,
      iocsTotal: scenarioIocValues.length, verdictCorrect, expectedVerdict, text: reportText,
    },
  };
}

export function staticFeedback(bundle: ScenarioBundle, outcome: GradeOutcome): string {
  const r = outcome.report.score;
  const reportNote =
    r >= 75 ? "Your written report was thorough — verdict, evidence and reasoning all present."
    : r >= 45 ? "Your report covered the basics; cite more of the incident's indicators and justify the verdict in more depth."
    : "Your written report was thin. In a real SOC the report IS the deliverable: state a verdict, cite the indicators it rests on, and explain your reasoning.";

  return outcome.passed
    ? `Good investigation on "${bundle.title}". You identified ${outcome.correctCount}/${bundle.questions.length} attack stages and scored ${r}/100 on the report. ${reportNote}`
    : `You scored ${outcome.score}% on "${bundle.title}" (quiz ${outcome.quizScore}, report ${r}). ${reportNote}`;
}
