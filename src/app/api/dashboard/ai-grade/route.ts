/**
 * POST /api/dashboard/ai-grade
 *
 * AI-powered grading for three student input surfaces:
 *   "behavior"  — TriageWorksheet "What happened?" field
 *   "ioc_notes" — InvestigationWorkbench "My Notes" tab
 *   "ciso"      — InvestigationDrawer "Explain to CISO" section
 *
 * Each context gets a tailored system prompt and XP budget.
 * Falls back to heuristic scoring when ANTHROPIC_API_KEY is absent.
 */

import { NextResponse } from "next/server";

export const runtime = "nodejs";

// ── Shared event shape ────────────────────────────────────────────────────────

export interface GradeEvent {
  id?: string;
  description?: string;
  event_type: string;
  source: string;
  severity: string;
  user_email?: string;
  hostname?: string;
  src_ip?: string;
  mitre_technique?: string;
  mitre_tactic?: string;
  raw?: Record<string, unknown>;
  fp_explanation?: string;
  ruleLevel?: number;
}

export type GradeContext = "behavior" | "ioc_notes" | "ciso";

export interface AIGradeRequest {
  context: GradeContext;
  event: GradeEvent;
  text: string;
  /** Collected IOCs — used in ioc_notes context */
  iocs?: Array<{ type: string; value: string; context?: string }>;
}

export interface AIGradeResponse {
  pass: boolean;
  xp: number;
  maxXp: number;
  feedback: string;
  strength: string;
  gap: string;
}

// ── XP budgets per context ────────────────────────────────────────────────────

const MAX_XP: Record<GradeContext, number> = {
  behavior:  10,
  ioc_notes: 20,
  ciso:      15,
};

// ── Heuristic fallback ────────────────────────────────────────────────────────

function heuristicGrade(req: AIGradeRequest): AIGradeResponse {
  const { context, event, text, iocs = [] } = req;
  const t = text.trim().toLowerCase();
  const max = MAX_XP[context];

  if (context === "behavior") {
    const hasUser     = !!(event.user_email && t.includes(event.user_email.split("@")[0].toLowerCase()));
    const hasHost     = !!(event.hostname && t.includes(event.hostname.toLowerCase()));
    const hasIP       = !!(event.src_ip && t.includes(event.src_ip));
    const hasMitre    = !!(event.mitre_technique && t.includes(event.mitre_technique.toLowerCase()));
    const hasTechWord = /process|connect|spawn|execut|download|upload|access|auth|login|command|network|lateral|cred/i.test(text);
    const iocRefs = [hasUser, hasHost, hasIP, hasMitre, hasTechWord].filter(Boolean).length;
    const xp = Math.min(max, Math.round((iocRefs / 4) * max));
    const pass = xp >= Math.ceil(max * 0.5);
    return {
      pass, xp, maxXp: max,
      feedback: pass
        ? "Description references key observable indicators from the event."
        : "Description is too generic — mention the specific process, IP, or user shown in the log.",
      strength: iocRefs > 0 ? "You referenced at least one observable from the event." : "",
      gap: !hasUser && event.user_email ? `Missing: the user involved (${event.user_email})` :
           !hasTechWord ? "Describe the actual action observed, not just the category." :
           "Add the destination IP or domain if visible in the log.",
    };
  }

  if (context === "ioc_notes") {
    const iocVals = iocs.map(i => i.value.toLowerCase());
    const mentioned = iocVals.filter(v => t.includes(v)).length;
    const hasConclusion = /attack|threat|lateral|exfil|malicious|compromise|c2|malware|ransomware/i.test(text);
    const hasAction = /isolat|block|reset|revoke|escalat|notif|contain|report/i.test(text);
    const ratio = iocs.length === 0 ? 0 : mentioned / iocs.length;
    const xp = Math.min(max, Math.round((ratio * 10) + (hasConclusion ? 5 : 0) + (hasAction ? 5 : 0)));
    const pass = xp >= Math.ceil(max * 0.4);
    return {
      pass, xp, maxXp: max,
      feedback: pass
        ? "Notes cover the key indicators and draw a reasonable conclusion."
        : "Notes need more coverage of the collected IOCs and a recommended action.",
      strength: mentioned > 0 ? `Correctly referenced ${mentioned} of ${iocs.length} collected IOCs.` : "",
      gap: !hasAction ? "Missing: what action should be taken? (isolate, block, escalate)" :
           !hasConclusion ? "Missing: what does this collection of IOCs tell you — what type of attack?" :
           "Good coverage. Try to explain the attack narrative, not just list IOCs.",
    };
  }

  // context === "ciso"
  const hasImpact = /customer|revenue|data|breach|operat|service|legal|regulat|patient|financial|reputation/i.test(text);
  const hasAction = /recommend|should|need|must|action|isolat|block|reset|report|notif|suspend|escalat/i.test(text);
  const noJargon  = !/MITRE|T1\d{3}|IOC|TTPs|Sigma|YARA|kibana|splunk|SIEM|APT\d|lateral/i.test(text);
  const long      = text.trim().length > 80;
  const xp = (hasImpact ? 5 : 0) + (hasAction ? 5 : 0) + (noJargon ? 3 : 0) + (long ? 2 : 0);
  const pass = hasImpact && hasAction;
  return {
    pass, xp: Math.min(xp, max), maxXp: max,
    feedback: pass
      ? noJargon
        ? "Clear executive summary — business risk and recommended action are present."
        : "Good content but contains technical jargon a CISO may not recognise."
      : "CISO summary needs business impact AND a recommended action.",
    strength: hasImpact ? "Business impact is clearly stated." : hasAction ? "Recommended action is present." : "",
    gap: !hasImpact ? "Missing: what business risk does this create? (data loss, service disruption, etc.)" :
         !hasAction ? "Missing: what should leadership do?" :
         !noJargon  ? "Remove technical acronyms — write for a non-technical audience." :
         "Solid. Consider adding the urgency/timeline for the recommended action.",
  };
}

// ── System prompts per context ────────────────────────────────────────────────

function buildSystemPrompt(context: GradeContext): string {
  if (context === "behavior") {
    return `You are a senior SOC analyst grading a trainee's behavior description for a security event.

The trainee was shown a specific log event and asked: "What happened? Describe in your own words."
They must accurately describe what the log shows — not a generic attack type, but the specific observable.

Grade the description on:
1. Accuracy — does it correctly reflect the event (process name, connection, user, action)?
2. Specificity — does it mention actual observables from the log (IP, user, hostname, command)?
3. Comprehension — does it show they understood what was notable/suspicious about this event?

XP scale 0-10:
- 0-2: Wrong, generic, or copied text
- 3-5: Partially correct, missing key specifics
- 6-8: Accurate and specific
- 9-10: Accurate, specific, and explains WHY it's notable

Return ONLY valid JSON, no markdown:
{
  "pass": boolean,
  "xp": number,
  "maxXp": 10,
  "feedback": "2 sentences — what they got right/wrong in context of THIS event",
  "strength": "one line — what they did well, or empty string",
  "gap": "one line — the most important thing they missed"
}`;
  }

  if (context === "ioc_notes") {
    return `You are a senior SOC analyst grading a trainee's investigation notes during a live incident.

The trainee collected IOCs from live events and wrote their analysis in the notes field.

Grade the notes on:
1. IOC Coverage — do their notes reference the indicators they collected?
2. Attack Narrative — do they explain what the IOCs indicate as a whole (not just list them)?
3. Recommended Action — do they state what should happen next (isolate, block, escalate)?
4. Accuracy — is their interpretation of the IOCs correct given the event context?

XP scale 0-20:
- 0-5: Empty or irrelevant
- 6-10: Lists IOCs but no analysis or action
- 11-15: Analysis present but missing action or has errors
- 16-20: Complete — narrative + IOC references + recommended action

Return ONLY valid JSON, no markdown:
{
  "pass": boolean,
  "xp": number,
  "maxXp": 20,
  "feedback": "2 sentences on quality of the analysis",
  "strength": "one line — what they did well, or empty string",
  "gap": "one line — the most important gap in their analysis"
}`;
  }

  // context === "ciso"
  return `You are grading whether a SOC analyst's executive summary is suitable for a CISO (non-technical executive).

The trainee must summarise a security incident in 2 sentences that a non-technical manager can act on.

Requirements:
1. Business Impact — must state what risk exists to the business (data, operations, customers, legal)
2. Recommended Action — must state what leadership should decide or approve
3. No Technical Jargon — no MITRE technique IDs (T1xxx), no acronyms (IOC, TTPs, SIEM, APT), no tool names

XP scale 0-15:
- 0-3: Jargon-filled, technical-only, or empty
- 4-8: Has business language but missing impact or action
- 9-12: Business impact + action, minor jargon
- 13-15: Clear, jargon-free, actionable for leadership

Return ONLY valid JSON, no markdown:
{
  "pass": boolean,
  "xp": number,
  "maxXp": 15,
  "feedback": "2 sentences — was this CISO-ready and why/why not",
  "strength": "one line — what they did well, or empty string",
  "gap": "one line — the most important improvement needed"
}`;
}

// ── User prompt per context ───────────────────────────────────────────────────

function buildUserPrompt(req: AIGradeRequest): string {
  const { context, event, text, iocs = [] } = req;

  const eventSummary = [
    `Event: ${event.description ?? event.event_type}`,
    `Source: ${event.source} | Severity: ${event.severity}`,
    event.user_email && `User: ${event.user_email}`,
    event.hostname   && `Host: ${event.hostname}`,
    event.src_ip     && `Src IP: ${event.src_ip}`,
    event.mitre_technique && `MITRE: ${event.mitre_technique} (${event.mitre_tactic ?? "n/a"})`,
    event.fp_explanation && `Note: ${event.fp_explanation}`,
    event.ruleLevel !== undefined && `Rule level: ${event.ruleLevel}`,
  ].filter(Boolean).join("\n");

  const rawSnippet = event.raw
    ? Object.entries(event.raw)
        .filter(([, v]) => v !== undefined && String(v).length < 100)
        .slice(0, 8)
        .map(([k, v]) => `  ${k}: ${v}`)
        .join("\n")
    : "";

  if (context === "behavior") {
    return `EVENT CONTEXT:
${eventSummary}
${rawSnippet ? `\nKey raw fields:\n${rawSnippet}` : ""}

STUDENT'S BEHAVIOR DESCRIPTION:
"${text}"

Grade this description and return JSON.`;
  }

  if (context === "ioc_notes") {
    const iocList = iocs.length > 0
      ? iocs.map(i => `  [${i.type}] ${i.value}${i.context ? ` (${i.context})` : ""}`).join("\n")
      : "  (no IOCs collected)";
    return `EVENT CONTEXT:
${eventSummary}

COLLECTED IOCs:
${iocList}

STUDENT'S INVESTIGATION NOTES:
"${text}"

Grade these notes and return JSON.`;
  }

  // ciso
  return `EVENT CONTEXT:
${eventSummary}

STUDENT'S CISO SUMMARY:
"${text}"

Grade this executive summary and return JSON.`;
}

// ── Main handler ──────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const body: AIGradeRequest = await req.json();
  const { text } = body;

  if (!text?.trim()) {
    const max = MAX_XP[body.context] ?? 10;
    return NextResponse.json({
      pass: false, xp: 0, maxXp: max,
      feedback: "Nothing was written. Submit your analysis before requesting a grade.",
      strength: "",
      gap: "The field was empty.",
    } satisfies AIGradeResponse);
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
      max_tokens: 512,
      system: [{ type: "text" as const, text: buildSystemPrompt(body.context), cache_control: { type: "ephemeral" as const } }],
      messages: [{ role: "user", content: buildUserPrompt(body) }],
    });

    const raw = msg.content.map(c => (c.type === "text" ? c.text : "")).join("").trim();
    const result = JSON.parse(raw) as AIGradeResponse;
    return NextResponse.json(result);
  } catch (err) {
    console.error("[ai-grade]", err);
    return NextResponse.json(heuristicGrade(body));
  }
}
