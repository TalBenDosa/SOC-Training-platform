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
 *      before it may match the telemetry (so common stopwords can't match a
 *      description's prose). Curated `bundle.iocs` matches are exempt — they're
 *      vetted content.
 *   3. CREDIT needs a whole value or a whole token of one (split on separators
 *      such as / \ : = , and whitespace), never an arbitrary substring. With
 *      substrings, "185", "85." and "5.2" cut out of one IP were each a distinct
 *      "real" indicator worth XP, so one request could farm the XP cap. The
 *      fabrication check stays lenient (any substring of a single value) so an
 *      analyst quoting part of a URL or command line is not penalised.
 * `reportScoring.test.ts` locks these guards down.
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
  verdictWrong: boolean;
  scenarioIocValues: string[];
  iocsCited: number;
  usefulCitedCount: number;
  fabricated: string[];
  misattributed: string[];
  reportRubric: { verdict: number; depth: number; evidence: number; reasoning: number };
  reportScore: number;
}

// Well-known-benign addresses that are never a hostile indicator. Citing a public
// DNS resolver as an IOC is a Tier-1 precision error, the same class as tagging the
// victim's own asset — it is penalised, not credited. (Kept deliberately small and
// unambiguous; the victim's own internal IP can't be detected generically here.)
const BENIGN_INDICATORS = new Set<string>([
  "8.8.8.8", "8.8.4.4",           // Google Public DNS
  "1.1.1.1", "1.0.0.1",           // Cloudflare DNS
  "208.67.222.222", "208.67.220.220", // OpenDNS
  "9.9.9.9",                      // Quad9
]);

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

/**
 * Is this value shaped like an indicator an analyst would cite (QA-SCN-1)? An IP, a
 * hash, an email, a URL, a domain / host / account name, a file name. NOT a timestamp,
 * a bare number or an ordinary word: tagging event timestamps as "IPs" used to earn
 * full evidence credit.
 */
export function isIocShaped(v: string): boolean {
  const s = v.trim().toLowerCase();
  if (s.length < 3) return false;
  if (/^\d+$/.test(s)) return false;                                      // a count, a pid, a port
  if (/^\d{4}-\d{2}-\d{2}([t ]|$)/.test(s) || /^\d{1,2}:\d{2}(:\d{2})?/.test(s)) return false; // timestamps
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(s)) return true;          // IPv4 / CIDR
  if (/^[0-9a-f:]+$/.test(s) && s.includes(":") && s.length >= 6) return true;   // IPv6
  if (/^[0-9a-f]{32,128}$/.test(s)) return true;                            // hashes
  if (/^[\w.+-]+@[\w.-]+\.[a-z]{2,}$/.test(s)) return true;                 // email
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(s)) return true;                        // URL
  if (/^[\w.-]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta|lnk|msi|zip|rar|7z|iso|dmg|pkg|sh|py|elf|so|docm|xlsm|pdf|scr)$/.test(s)) return true; // file
  // host / domain / account: letters plus a digit, dot, hyphen, underscore or $ (WS-FIN-3041, evil.example, svc_backup, DC01$)
  if (/^[a-z0-9][\w.$-]*$/.test(s) && /[a-z]/.test(s) && /[\d._$-]/.test(s)) return true;
  return false;
}

/** Distinct words relative to the total: "blah blah blah" is one word repeated (QA-SCN-1). */
function effectiveWordCount(text: string): number {
  const all = text.toLowerCase().split(/\s+/).filter(Boolean);
  const distinct = new Set(all).size;
  // Natural prose repeats words; ~2.5 uses per distinct word is generous. Padding is not.
  return Math.min(all.length, Math.round(distinct * 2.5));
}

/** Separators an indicator never contains; splitting a value on them yields its tokens. */
const TOKEN_SPLIT = /[\s"'`,;|()<>[\]{}=\\/:]+/;

export function scoreScenarioReport(input: ReportScoreInput): ReportScoreResult {
  const { verdict, verdictReason, analystNotes, iocs, events, attackKind } = input;
  // Client-supplied: a non-array must not throw (it used to 500 the grade route).
  const indicators = Array.isArray(input.indicators) ? input.indicators : [];

  const reportText = [analystNotes, verdictReason].join(" ").trim();
  const words = reportText.split(/\s+/).filter(Boolean).length;
  // Depth and reasoning count DISTINCT effort, not raw length (QA-SCN-1).
  const effWords = effectiveWordCount(reportText);
  const effReasonWords = effectiveWordCount(verdictReason);

  const expectedVerdict: "benign" | "malicious" =
    attackKind === "false_positive" ? "benign" : "malicious";
  // The client sends the analyst's call as "tp"/"fp"; normalise to malicious/benign.
  const normalizedVerdict = verdict === "tp" ? "malicious" : verdict === "fp" ? "benign" : verdict;
  const verdictCorrect = normalizedVerdict === expectedVerdict;

  // ── Evidence / IOCs ────────────────────────────────────────────────────────
  const scenarioIocValues = (iocs ?? []).map(i => i.value.toLowerCase());
  const realValues = new Set(scenarioIocValues);
  const leaves = collectLeafValues(events ?? []).map(v => v.toLowerCase());
  // Whole values + their tokens: what may EARN credit.
  const leafTokens = new Set<string>();
  for (const leaf of leaves) {
    leafTokens.add(leaf.trim());
    for (const t of leaf.split(TOKEN_SPLIT)) if (t) leafTokens.add(t);
  }
  // Newline-joined so a match can't straddle two different values.
  const eventsBlob = leaves.join("\n");
  const looksLikeIndicator = (v: string) => v.length >= 6 || /[\d@._-]/.test(v);
  /** Earns credit: a curated IOC, or a whole value / whole token seen in the telemetry. */
  const isRealValue = (v: string) => realValues.has(v) || (looksLikeIndicator(v) && isIocShaped(v) && leafTokens.has(v));
  /** Grounded in the telemetry at all (fabrication check only — deliberately lenient). */
  const isGroundedValue = (v: string) => realValues.has(v) || (looksLikeIndicator(v) && eventsBlob.includes(v));

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
  // Curated key indicators count in full; other real, IOC-shaped values from the
  // telemetry count half (QA-SCN-1: any long token used to fill the whole bar).
  let evidencePoints = 0;
  for (const v of usefulCited) evidencePoints += realValues.has(v) ? 1 : 0.5;
  const iocCoverage = Math.min(1, evidencePoints / iocTarget);

  // Fabrication — inventing an IP/hash/email present nowhere is an integrity failure.
  const claimed = new Set<string>();
  for (const m of reportText.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))  claimed.add(m[0].toLowerCase()); // IPv4
  for (const m of reportText.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g)) claimed.add(m[0].toLowerCase()); // email
  for (const m of reportText.matchAll(/\b[0-9a-f]{32,64}\b/gi))         claimed.add(m[0].toLowerCase()); // hash
  const fabricated = [...claimed].filter(v => v.length >= 4 && !isGroundedValue(v));

  // Precision error: a known-benign address tagged (or written) as a hostile
  // indicator. Checked across BOTH the tagged IOC list and the prose.
  const misattributed = [...new Set([...citedValues, ...claimed])].filter(v => BENIGN_INDICATORS.has(v));

  const reportRubric = {
    verdict:  verdict ? (verdictCorrect ? 25 : 5) : 0,
    depth:    effWords >= 150 ? 25 : effWords >= 80 ? 18 : effWords >= 40 ? 10 : effWords > 0 ? 4 : 0,
    // A fabricated OR misattributed indicator caps evidence near zero — precision,
    // not just recall: an unusable report is worse than a sparse one.
    evidence: (fabricated.length > 0 || misattributed.length > 0)
      ? (usefulCited.size > 0 ? 5 : 0)
      : Math.round(iocCoverage * 30),
    reasoning: effReasonWords >= 25 ? 20 : effReasonWords >= 10 ? 12 : 0,
  };
  const rawReportScore = Math.min(
    100,
    reportRubric.verdict + reportRubric.depth + reportRubric.evidence + reportRubric.reasoning,
  );
  // A confident WRONG verdict is worse than none: the verdict is the single most
  // important output, so a thorough write-up must not pass the report on evidence
  // and depth alone when the core call is wrong. Cap below the report pass line.
  const verdictWrong = verdict != null && !verdictCorrect;
  const reportScore = verdictWrong ? Math.min(rawReportScore, 49) : rawReportScore;

  return {
    reportText, words, expectedVerdict, verdictCorrect, verdictWrong,
    scenarioIocValues, iocsCited, usefulCitedCount: usefulCited.size,
    fabricated, misattributed, reportRubric, reportScore,
  };
}
