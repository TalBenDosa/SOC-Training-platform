/**
 * POST /api/dashboard/incident-report
 *
 * Grades a student's free-text incident report against WHAT ACTUALLY HAPPENED.
 * The dashboard sends the real indicators (IPs, users, hosts, domains, hashes)
 * and MITRE techniques of the injected attack as ground truth, so the grader can:
 *   - reward citing genuine evidence pulled from the logs, and
 *   - catch FABRICATED data (indicators the student invented that never appear
 *     in the feed — e.g. "host:koko") and call it out explicitly.
 *
 * Scoring rubric (0-100):
 *   Attack Identification  (0-40) — correct attack type/TTPs identified
 *   Evidence               (0-30) — specific, REAL indicators referenced
 *   Action & Impact        (0-30) — recommended response + business impact stated
 *
 * Pass threshold: score >= 60
 */

import { NextResponse } from "next/server";

export const runtime = "nodejs";

export interface IncidentReportRequest {
  company: string;
  summary: string;
  attackTitle?: string;
  /** MITRE technique IDs the real attack used (ground truth) */
  attackMitreTechniques?: string[];
  /** Real indicator values from the actual attack events (ground truth) */
  realIndicators?: string[];
}

export interface IncidentReportResponse {
  score: number;
  passed: boolean;
  feedback: string;
  strengths: string[];
  gaps: string[];
}

// ── Fabrication / citation analysis ───────────────────────────────────────────

/**
 * Compare the indicators the student CLAIMED in their write-up against the real
 * indicators from the attack. Returns which real ones they correctly cited and
 * which claimed values are fabricated (invented — not in the logs at all).
 */
function analyseIndicators(summary: string, real: string[]) {
  const t = summary.toLowerCase();
  const realLower = real.map(r => r.toLowerCase());
  const isReal = (v: string) => {
    const lv = v.toLowerCase();
    return realLower.some(r => r === lv || r.includes(lv) || lv.includes(r));
  };

  // Which real indicators did they quote?
  const cited = real.filter(r => {
    const lr = r.toLowerCase();
    return t.includes(lr) || t.includes(lr.split("@")[0]); // full value or username part
  });

  // Extract indicator-shaped claims from the student's text
  const claimed = new Set<string>();
  for (const m of summary.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))        claimed.add(m[0]); // IPv4
  for (const m of summary.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g))       claimed.add(m[0]); // email
  for (const m of summary.matchAll(/\bhost(?:name)?\s*[:=]?\s*([a-z0-9][\w.-]{1,})/gi)) claimed.add(m[1]); // host: X
  for (const m of summary.matchAll(/\b[0-9a-f]{32,64}\b/gi))              claimed.add(m[0]); // hash

  const fabricated = [...claimed].filter(v => !isReal(v));
  return { cited, fabricated };
}

// ── Heuristic fallback ────────────────────────────────────────────────────────

function heuristicGrade(req: IncidentReportRequest): IncidentReportResponse {
  const { summary, attackTitle, realIndicators = [] } = req;
  const t = summary.trim().toLowerCase();

  // ── Component 1 — Attack Identification (0-40) ───────────────────────────
  const genericWords  = /incident|attack|threat|breach|suspicious|intrusion|compromise|unauthorized|anomal/i;
  const categoryWords = /phishing|malware|ransomware|spray|credential|lateral|exfil|c2|beacon|brute.?force|mfa|injection|privilege|escalat|dump|harvest|backdoor|persist|trojan|rootkit|botnet/i;
  const specificWords = /password.?spray|mfa.?fatigue|credential.?dump|lsass|kerberos|as.?rep.?roast|mimikatz|impacket|responder|ntlm.?relay|golden.?ticket|dcsync|pass.?the.?hash|process.?inject|dll.?inject|drive.?by|business.?email.?compromise|supply.?chain|pod.?escape|oauth.?consent|apt/i;

  const titleKeywords = attackTitle
    ? attackTitle.toLowerCase().replace(/[→\-–]/g, " ").split(/\s+/).filter(w => w.length > 4)
    : [];
  const matchesTitle = titleKeywords.length > 0 && titleKeywords.some(kw => t.includes(kw));

  const mitreWords = /T1\d{3}|mitre|att&ck|initial.?access|lateral.?movement|exfiltration|command.?and.?control|privilege.?escalat|credential.?access|defense.?evasion/i;
  const hasMitre   = mitreWords.test(summary);

  let attackScore = 0;
  if (specificWords.test(summary))       attackScore = 30;
  else if (categoryWords.test(summary))  attackScore = 20;
  else if (genericWords.test(summary))   attackScore = 10;
  if (matchesTitle) attackScore = Math.min(40, attackScore + 5);
  if (hasMitre)     attackScore = Math.min(40, attackScore + 5);
  // Named a specific attack but it does NOT match the real story → likely wrong type
  const wrongType = attackScore >= 20 && titleKeywords.length > 0 && !matchesTitle && !hasMitre;
  if (wrongType) attackScore = Math.min(attackScore, 20);

  // ── Component 2 — Evidence (0-30), verified against ground truth ──────────
  const { cited, fabricated } = analyseIndicators(summary, realIndicators);
  const hasFabrication = fabricated.length > 0;
  let iocScore: number;
  if (hasFabrication) {
    // Invented indicators are a serious integrity problem — cap evidence low.
    iocScore = Math.min(5, cited.length > 0 ? 5 : 0);
  } else if (realIndicators.length === 0) {
    // No ground truth available — fall back to "did they quote any indicator?"
    iocScore = /\d{1,3}(\.\d{1,3}){3}/.test(summary) ? 15 : 0;
  } else {
    iocScore = Math.min(30, cited.length * 12); // ~12 pts per real indicator cited
  }

  // ── Component 3 — Action & Impact (0-30) ─────────────────────────────────
  const hasAction = /isolat|block|reset|revoke|escalat|notif|contain|report|suspend|disable|investigate|remediat|patch|quarantin/i.test(summary);
  const hasImpact = /data|breach|operat|customer|patient|financ|revenue|service|regulat|legal|reputation|risk|impact|compromise|stolen|loss|disrupt/i.test(summary);
  const actionScore = (hasAction ? 15 : 0) + (hasImpact ? 15 : 0);

  const score  = Math.min(100, attackScore + iocScore + actionScore);
  const passed = score >= 60;

  const strengths: string[] = [];
  const gaps: string[] = [];

  if (attackScore >= 30 && !wrongType) strengths.push("Named a specific attack technique.");
  else if (attackScore >= 20 && !wrongType) strengths.push("Identified the broad attack category.");
  if (cited.length > 0) strengths.push(`Cited ${cited.length} real indicator${cited.length > 1 ? "s" : ""} from the logs (${cited.slice(0, 3).join(", ")}).`);
  if (hasAction) strengths.push("Included a recommended response action.");
  if (hasImpact) strengths.push("Described the business impact or risk.");

  // Fabrication is the headline gap — name exactly what was invented.
  if (hasFabrication) {
    gaps.push(`Fabricated evidence: "${fabricated.slice(0, 3).join('", "')}" ${fabricated.length > 1 ? "do" : "does"} not appear anywhere in the logs. Never invent indicators — quote the real values you can see${realIndicators.length ? ` (e.g. ${realIndicators.slice(0, 2).join(", ")})` : ""}.`);
  }
  if (wrongType) {
    gaps.push(`The attack type you named doesn't match the evidence. Re-read the logs and identify what actually happened${attackTitle ? ` (this was: ${attackTitle}).` : "."}`);
  } else if (attackScore < 20) {
    gaps.push("Missing: name the specific attack technique (e.g. password spray, MFA fatigue, LSASS dump, phishing). Generic words like 'attack' earn only 10/40.");
  } else if (attackScore < 30) {
    gaps.push("Good category — name the exact technique for full Attack Identification points.");
  }
  if (!hasFabrication && cited.length === 0 && realIndicators.length > 0) {
    gaps.push(`Missing: quote real indicators from the logs (e.g. ${realIndicators.slice(0, 2).join(", ")}). Generic phrases like "a suspicious IP" don't count.`);
  }
  if (!hasAction) gaps.push("Missing: state what action to take (isolate host, block IP, reset credentials, escalate).");
  if (!hasImpact) gaps.push("Missing: explain the business risk or potential impact.");

  const feedback = passed
    ? `Report passed — score ${score}/100. You identified the attack and backed it with real evidence.`
    : hasFabrication
      ? `Report scored ${score}/100 — below the 60-point threshold. ${gaps[0]}`
      : `Report scored ${score}/100 — below 60. ${gaps[0] ?? "Add the specific attack technique, real indicators, and a response action."}`;

  return { score, passed, feedback, strengths, gaps };
}

// ── System prompt ─────────────────────────────────────────────────────────────

function buildSystemPrompt(): string {
  return `You are a senior SOC team lead grading a Tier-1 analyst trainee's incident report. Be rigorous and specific — this is training, so wrong or invented facts must be corrected clearly.

The trainee watched a simulated SIEM feed, identified an attack, and wrote a report. You are given the GROUND TRUTH of what actually happened (the real attack, its MITRE techniques, and the real indicator values that appear in the logs).

Grading rubric (total 100 points):

1. Attack Identification (0-40)
   - Did they name the attack that ACTUALLY happened (per the ground-truth techniques/title)?
   - If they named a DIFFERENT attack than what occurred, cap this at 20 and say so.
   - Score: 0 = none, 20 = vague/wrong, 35 = correct category, 40 = correct + attacker goal.

2. Evidence (0-30) — verified against the REAL indicators
   - Reward quoting the actual indicator values (IPs, users, hosts, domains, hashes) that appear in the logs.
   - CRITICAL: if the trainee cites an indicator that is NOT in the real indicator list (they invented it — e.g. a hostname or IP that never appears), treat it as FABRICATED. Fabricated evidence caps this component at 5 and MUST be named explicitly in the gaps.
   - Score: 0 = none, 10 = generic, 20 = 1-2 real values, 30 = 3+ real values. Fabrication → ≤5.

3. Action & Impact (0-30)
   - Concrete response action (isolate, block, reset, escalate…) AND business/operational risk.
   - Score: 0 = neither, 15 each.

Pass threshold: 60.

Be concrete in feedback: if they invented data, quote exactly what they invented and what the real value was. If they named the wrong attack, say what it actually was.

Return ONLY valid JSON, no markdown:
{
  "score": number,
  "passed": boolean,
  "feedback": "2-4 sentences: the main finding, and clearly flag any invented/incorrect data",
  "strengths": ["what they did well (0-3 items)"],
  "gaps": ["what was wrong or missing — name fabricated/incorrect data explicitly (1-4 items)"]
}`;
}

function buildUserPrompt(req: IncidentReportRequest): string {
  const { company, summary, attackTitle, attackMitreTechniques, realIndicators = [] } = req;

  const mitreBlock = attackMitreTechniques && attackMitreTechniques.length > 0
    ? attackMitreTechniques.map(t => `  ${t}`).join("\n")
    : "  (not available)";
  const indBlock = realIndicators.length > 0
    ? realIndicators.map(v => `  ${v}`).join("\n")
    : "  (not available)";

  return `COMPANY: ${company}

=== GROUND TRUTH (what actually happened) ===
ATTACK: ${attackTitle ?? "Unknown"}
REAL MITRE TECHNIQUES:
${mitreBlock}
REAL INDICATORS THAT APPEAR IN THE LOGS (any indicator the trainee cites that is NOT here is fabricated):
${indBlock}

=== TRAINEE'S INCIDENT REPORT ===
"${summary}"

Grade strictly against the ground truth. If the trainee named the wrong attack or invented indicators (e.g. a host or IP not in the list above), you MUST call it out by name in the gaps and score accordingly. Return JSON only.`;
}

// ── Handler ───────────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const body: IncidentReportRequest = await req.json();

  if (!body.summary?.trim()) {
    return NextResponse.json({
      score: 0,
      passed: false,
      feedback: "No report was written. Describe what attack you detected and what action to take.",
      strengths: [],
      gaps: ["The report field was empty — write your analysis before submitting."],
    } satisfies IncidentReportResponse);
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return NextResponse.json(heuristicGrade(body));
  }

  try {
    const { default: Anthropic } = await import("@anthropic-ai/sdk");
    const client = new Anthropic({ apiKey });

    const msg = await client.messages.create({
      model: process.env.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
      max_tokens: 640,
      system: [{ type: "text" as const, text: buildSystemPrompt(), cache_control: { type: "ephemeral" as const } }],
      messages: [{ role: "user", content: buildUserPrompt(body) }],
    });

    const raw = msg.content.map(c => (c.type === "text" ? c.text : "")).join("").trim();
    const result = JSON.parse(raw) as IncidentReportResponse;
    return NextResponse.json(result);
  } catch (err) {
    console.error("[incident-report]", err);
    return NextResponse.json(heuristicGrade(body));
  }
}
