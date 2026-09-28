/**
 * Explains a scenario report score (#16 of the team-exercise report).
 *
 * The grade route used to return "Your written report was thin" and a bare
 * 80/100 — the learner could not tell which 20 points they lost or what to do
 * differently. This module turns the rubric that `scoreScenarioReport()`
 * ALREADY computed into a per-criterion breakdown plus concrete "what you
 * missed" items. It never re-scores: every point value here is read from the
 * rubric, so `reportScoring.test.ts` stays the single lock on the formula. The
 * thresholds quoted in the advice mirror reportScoring.ts; the test below
 * pins them so the copy can't drift from the maths.
 *
 * ANSWER-KEY SAFETY: the names of the curated key indicators the learner did
 * NOT cite are part of the answer key. They are released only when the caller
 * says the attempt is genuine (`revealKey` — the same gate that releases the
 * debrief: every question answered + a non-empty report). Otherwise the
 * learner gets counts only. Fabricated / misattributed values are echoed back
 * freely — they are the learner's own input, not key material.
 */
import type { ReportScoreResult } from "@/lib/scenarios/reportScoring";

export interface BreakdownItem {
  key: "verdict" | "depth" | "evidence" | "reasoning";
  label: string;
  points: number;
  max: number;
  /** One line explaining how the points were earned (or lost). */
  detail: string;
}

export interface ReportBreakdown {
  items: BreakdownItem[];
  /** True when a wrong verdict capped the report at 49 regardless of the rest. */
  cappedByVerdict: boolean;
  /** Curated key indicators the report did not cite — null when withheld. */
  missedIndicators: string[] | null;
  /** Curated key indicators the report did cite (the learner's own work). */
  citedIndicators: string[];
  /** Values the report cited that appear nowhere in the telemetry. */
  fabricatedValues: string[];
  /** Known-benign values the report tagged as hostile. */
  misattributedValues: string[];
  /** Specific, actionable "what you missed" lines, most important first. */
  improvements: string[];
  /** A one-sentence, specific summary used in place of the generic report note. */
  summary: string;
}

// Mirrors of the thresholds in reportScoring.ts (pinned by reportBreakdown.test.ts).
export const DEPTH_FULL_WORDS = 150;
export const REASONING_FULL_WORDS = 25;
export const REASONING_PARTIAL_WORDS = 10;

const MAX = { verdict: 25, depth: 25, evidence: 30, reasoning: 20 } as const;

function countWords(s: string): number {
  return s.trim().split(/\s+/).filter(Boolean).length;
}

export interface BreakdownInput {
  scored: ReportScoreResult;
  verdict: string | null;
  verdictReason: string;
  indicators: { value: string }[];
  /** The scenario's curated key indicators, original casing. */
  iocs: readonly { value: string }[] | undefined;
  /** Release the names of missed key indicators (genuine attempt only). */
  revealKey: boolean;
}

export function buildReportBreakdown(input: BreakdownInput): ReportBreakdown {
  const { scored, verdict, verdictReason, indicators, iocs, revealKey } = input;
  const { reportRubric: r, words, expectedVerdict, verdictWrong, reportText } = scored;

  // Which curated key indicators were cited — the same rule reportScoring uses
  // for `iocsCited` (tagged, or named anywhere in the prose).
  const cited = new Set(indicators.map(i => String(i.value).toLowerCase().trim()).filter(Boolean));
  const prose = reportText.toLowerCase();
  const curated = (iocs ?? []).map(i => i.value);
  const citedIndicators = curated.filter(v => cited.has(v.toLowerCase()) || prose.includes(v.toLowerCase()));
  const missed = curated.filter(v => !citedIndicators.includes(v));
  const reasonWords = countWords(verdictReason);
  const called = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : null;
  const extraReal = Math.max(0, scored.usefulCitedCount - citedIndicators.length);

  const items: BreakdownItem[] = [
    {
      key: "verdict", label: "Verdict", points: r.verdict, max: MAX.verdict,
      detail: !verdict
        ? "No verdict given — the verdict is the headline of the report."
        : verdictWrong
          ? (revealKey
              ? `You called it ${called}; the evidence shows ${expectedVerdict}. A wrong verdict caps the whole report at 49.`
              : `You called it ${called}, and that is not what the evidence shows. A wrong verdict caps the whole report at 49.`)
          : `Correct — ${expectedVerdict}.`,
    },
    {
      key: "depth", label: "Depth", points: r.depth, max: MAX.depth,
      detail: words >= DEPTH_FULL_WORDS
        ? `${words} words — a full write-up.`
        : `${words} word${words === 1 ? "" : "s"} across notes + reasoning — ${DEPTH_FULL_WORDS}+ earns full marks.`,
    },
    {
      key: "evidence", label: "Evidence", points: r.evidence, max: MAX.evidence,
      detail: scored.fabricated.length > 0 || scored.misattributed.length > 0
        ? "Capped: the report cites an indicator that is invented or known-benign."
        : `${citedIndicators.length}/${curated.length} key indicator${curated.length === 1 ? "" : "s"} cited`
          + (extraReal > 0 ? ` (+${extraReal} other real value${extraReal === 1 ? "" : "s"} from the telemetry)` : "")
          + ".",
    },
    {
      key: "reasoning", label: "Reasoning", points: r.reasoning, max: MAX.reasoning,
      detail: reasonWords >= REASONING_FULL_WORDS
        ? `${reasonWords}-word verdict justification.`
        : `Verdict justification is ${reasonWords} word${reasonWords === 1 ? "" : "s"} — ${REASONING_PARTIAL_WORDS}+ earns partial, ${REASONING_FULL_WORDS}+ full marks.`,
    },
  ];

  // ── What you missed — most consequential first ────────────────────────────
  const improvements: string[] = [];
  if (!verdict) improvements.push("State a verdict (malicious or benign) — without it the report can't be acted on.");
  else if (verdictWrong) improvements.push(revealKey
    ? `Re-check the verdict: this incident is ${expectedVerdict}. Walk the events in order and ask what each one proves.`
    : "Re-check the verdict. Walk the events in order and ask what each one proves.");
  if (scored.fabricated.length > 0) {
    improvements.push(`Remove indicators that are not in the logs: ${scored.fabricated.slice(0, 5).join(", ")}. Cite only values you can point to in an event.`);
  }
  if (scored.misattributed.length > 0) {
    improvements.push(`${scored.misattributed.join(", ")} is a known-benign address (public DNS), not adversary infrastructure — don't tag it as an IOC.`);
  }
  if (missed.length > 0) {
    improvements.push(revealKey
      ? `Key indicators you didn't cite: ${missed.join(", ")}.`
      : `You cited ${citedIndicators.length} of ${curated.length} key indicators — pull the attacker IPs, domains, hashes and accounts out of the events and tag them.`);
  }
  if (reasonWords < REASONING_FULL_WORDS) {
    improvements.push("Justify the verdict in 25+ words: which events prove it, in what order, and why a benign explanation doesn't fit.");
  }
  if (words < DEPTH_FULL_WORDS) {
    improvements.push("Write up the full chain in your notes — initial access, what the attacker did on each host, what left the network, and the containment you'd recommend.");
  }

  const total = scored.reportScore;
  const summary =
    `Report ${total}/100 — verdict ${r.verdict}/${MAX.verdict}, depth ${r.depth}/${MAX.depth}, `
    + `evidence ${r.evidence}/${MAX.evidence}, reasoning ${r.reasoning}/${MAX.reasoning}`
    + (verdictWrong ? " (capped at 49 by the wrong verdict)." : ".")
    + (improvements.length > 0 ? ` Biggest gap: ${improvements[0]}` : " Nothing major missed.");

  return {
    items,
    cappedByVerdict: verdictWrong,
    missedIndicators: revealKey ? missed : null,
    citedIndicators,
    fabricatedValues: scored.fabricated.slice(0, 10),
    misattributedValues: scored.misattributed,
    improvements,
    summary,
  };
}
