/**
 * Pure, deterministic scoring for the scenario incident report.
 *
 * Extracted from `src/app/api/scenarios/[slug]/grade/route.ts` so the rubric can
 * be unit-tested in isolation — the route itself does auth, bundle resolution and
 * an optional LLM call, none of which the scoring depends on. Keep this in lockstep
 * with the route: the route now just calls `scoreScenarioReport()`.
 *
 * The evidence rule is the sensitive part. "Any indication that aids the
 * investigation counts as an IOC" — an indicator the analyst pulled from the
 * telemetry (not only the curated `bundle.iocs`) earns credit — but that must not
 * become free points for typing junk. Two guards make it safe:
 *   1. `collectLeafValues` matches only leaf VALUES, never object keys (so field
 *      names like "vendor"/"hostname" can't be "cited").
 *   2. `looksLikeIndicator` requires a freely-typed value to have indicator shape
 *      before it may match the telemetry blob (so common stopwords can't match a
 *      description's prose). Curated `bundle.iocs` matches are exempt — they're
 *      vetted content.
 * `reportScoring.test.ts` locks both guards down.
 */

export interface ReportScoreInput {
  verdict: string | null;
  verdictReason: string;
  analystNotes: string;
  indicators: { type?: string; value: string }[];
  iocs: readonly { value: string }[] | undefined;
  events: unknown;
  attackKind: string;
}

export interface ReportScoreResult {
  reportText: string;
  words: number;
  expectedVerdict: "benign" | "malicious";
  verdictCorrect: boolean;
  scenarioIocValues: string[];
  iocsCited: number;
  usefulCitedCount: number;
  fabricated: string[];
  reportRubric: { verdict: number; depth: number; evidence: number; reasoning: number };
  reportScore: number;
}

/**
 * Recursively flattens telemetry down to its leaf string/number/boolean VALUES
 * only — never object keys. `JSON.stringify(events)` was tried first and rejected:
 * it embeds every field NAME too ("vendor", "hostname", "process" are all literal
 * substrings of that blob), so typing the word "vendor" as a cited indicator would
 * "find" it. Restricting to values closes that hole.
 */
export function collectLeafValues(node: unknown, out: string[] = []): string[] {
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

export function scoreScenarioReport(input: ReportScoreInput): ReportScoreResult {
  const { verdict, verdictReason, analystNotes, indicators, iocs, events, attackKind } = input;

  const reportText = [analystNotes, verdictReason].join(" ").trim();
  const words = reportText.split(/\s+/).filter(Boolean).length;

  const expectedVerdict: "benign" | "malicious" =
    attackKind === "false_positive" ? "benign" : "malicious";
  // The client sends the analyst's call as "tp"/"fp"; normalise to malicious/benign.
  const normalizedVerdict = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : verdict;
  const verdictCorrect = normalizedVerdict === expectedVerdict;

  // ── Evidence / IOCs ────────────────────────────────────────────────────────
  const scenarioIocValues = (iocs ?? []).map(i => i.value.toLowerCase());
  const realValues = new Set(scenarioIocValues);
  const eventsBlob = collectLeafValues(events ?? []).join("").toLowerCase();
  const looksLikeIndicator = (v: string) => v.length >= 6 || /[\d@._-]/.test(v);
  const isRealValue = (v: string) => realValues.has(v) || (looksLikeIndicator(v) && eventsBlob.includes(v));

  const citedValues = new Set(
    indicators.map(i => String(i.value).toLowerCase().trim()).filter(Boolean),
  );

  // Curated KEY indicators named — for honest "X/Y key indicators" feedback only.
  const iocsCited = scenarioIocValues.filter(
    v => citedValues.has(v) || reportText.toLowerCase().includes(v),
  ).length;

  // Every REAL indicator surfaced — tagged OR named in prose — counts toward evidence.
  const usefulCited = new Set<string>();
  for (const v of citedValues) if (v.length >= 3 && isRealValue(v)) usefulCited.add(v);
  for (const v of scenarioIocValues) if (reportText.toLowerCase().includes(v)) usefulCited.add(v);

  const iocTarget = Math.max(1, scenarioIocValues.length);
  const iocCoverage = Math.min(1, usefulCited.size / iocTarget);

  // Fabrication — inventing an IP/hash/email present nowhere is an integrity failure.
  const claimed = new Set<string>();
  for (const m of reportText.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))  claimed.add(m[0].toLowerCase()); // IPv4
  for (const m of reportText.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g)) claimed.add(m[0].toLowerCase()); // email
  for (const m of reportText.matchAll(/\b[0-9a-f]{32,64}\b/gi))         claimed.add(m[0].toLowerCase()); // hash
  const fabricated = [...claimed].filter(v => v.length >= 4 && !isRealValue(v));

  const reportRubric = {
    verdict:  verdict ? (verdictCorrect ? 25 : 5) : 0,
    depth:    words >= 150 ? 25 : words >= 80 ? 18 : words >= 40 ? 10 : words > 0 ? 4 : 0,
    evidence: fabricated.length > 0 ? (usefulCited.size > 0 ? 5 : 0) : Math.round(iocCoverage * 30),
    reasoning: verdictReason.trim().split(/\s+/).filter(Boolean).length >= 25 ? 20
             : verdictReason.trim().split(/\s+/).filter(Boolean).length >= 10 ? 12 : 0,
  };
  const reportScore = Math.min(
    100,
    reportRubric.verdict + reportRubric.depth + reportRubric.evidence + reportRubric.reasoning,
  );

  return {
    reportText, words, expectedVerdict, verdictCorrect,
    scenarioIocValues, iocsCited, usefulCitedCount: usefulCited.size,
    fabricated, reportRubric, reportScore,
  };
}
