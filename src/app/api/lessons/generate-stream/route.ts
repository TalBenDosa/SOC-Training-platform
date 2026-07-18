/**
 * POST /api/lessons/generate-stream
 * ───────────────────────────────────
 * Section-by-section streaming lesson generator — powered by Google Gemini.
 *
 * Emits Server-Sent Events (text/event-stream) as each step completes:
 *   { type: "phase",        message: string }
 *   { type: "outline",      data: { title, sectionHeadings[] } }
 *   { type: "section_done", index: number, section: { heading, content, codeExample? } }
 *   { type: "done",         lesson: GeneratedLesson }
 *   { type: "error",        message: string }
 */

export const dynamic    = "force-dynamic";
export const maxDuration = 300;

import OpenAI from "openai";
import type { GeneratedLesson } from "../generate/route";

// ─── OpenAI client ────────────────────────────────────────────────────────────

const MODEL = "gpt-4o-mini";

function getClient() {
  return new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });
}

// ─── Rate-limit helpers ───────────────────────────────────────────────────────

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/** Call fn, retry up to maxRetries times on 429 with exponential backoff */
async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 4,
  baseDelay = 8000,
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const msg = err instanceof Error ? err.message : String(err);
      const isRateLimit = msg.includes("429") || msg.includes("quota") || msg.includes("rate");
      if (!isRateLimit || attempt === maxRetries) throw err;
      const delay = baseDelay * Math.pow(1.8, attempt); // 8s, 14s, 26s, 46s
      console.warn(`[generate-stream] Rate limit hit, waiting ${Math.round(delay / 1000)}s before retry ${attempt + 1}/${maxRetries}…`);
      await sleep(delay);
    }
  }
  throw lastErr;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

function calcXp(sectionCount: number, difficulty: string): number {
  const base = sectionCount * 20 + 30;
  const mult: Record<string, number> = {
    beginner: 1, intermediate: 1.3, advanced: 1.6, expert: 2,
  };
  return Math.round(base * (mult[difficulty] ?? 1));
}

function calcMinutes(sectionCount: number): number {
  return sectionCount * 5 + 10;
}

function parseJson<T>(text: string, fallback: T): T {
  try {
    // Strip markdown fences if Gemini wraps in ```json ... ```
    const stripped = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");
    const m = stripped.match(/\{[\s\S]*\}/);
    if (!m) return fallback;
    return JSON.parse(m[0]) as T;
  } catch {
    return fallback;
  }
}

// ─── System prompt ────────────────────────────────────────────────────────────

function systemPrompt(difficulty: string): string {
  const audienceProfile =
    difficulty === "beginner"
      ? `AUDIENCE: Someone who just joined a SOC or is studying for their first security certification. They understand computers at a user level — they know what a browser is, what a file is, what a password is. They do NOT know what a packet is, what a protocol is, what an event log is, or what "authentication" means technically. Your job is to build their mental model from scratch.

BEGINNER TEACHING STANDARD:
- Every technical term gets defined the moment it appears. No exceptions. Format: "The Windows Registry (a centralized database built into every Windows operating system where applications and the OS itself store configuration settings, user preferences, and — critically for us — evidence of attacker activity)..."
- When explaining a mechanism, trace the full cause-and-effect chain. Do not skip steps. If you say "the attacker exfiltrates data", explain what that physically means: which process opened which connection to which destination.
- Use concrete comparisons from everyday life, but make them precise. Not "it's like a library". Instead: "Windows event logs work the way a building's access control system works — every time someone badges in or out, the system creates a timestamped record. When an attacker logs in, that record exists. Your job as an analyst is to read those records and recognize when something doesn't fit."
- Every explanation must answer: what is it, how does it work at a mechanical level, and what does an analyst actually see?`

      : difficulty === "intermediate"
      ? `AUDIENCE: Someone with 6–18 months in IT or basic security experience. They understand networking fundamentals (TCP/IP, DNS, HTTP), basic Windows and Linux administration, and have opened a SIEM at least once. They are NOT fluent in attack techniques, detection logic, or SOC investigation workflows.

INTERMEDIATE TEACHING STANDARD:
- Build on their IT foundation — connect new SOC concepts to things they already know. "You already know DNS resolves domain names to IPs. What you may not know is that this same mechanism is how attackers exfiltrate data without triggering standard network controls — by encoding stolen data inside DNS queries."
- Go deep on the mechanics of attacks. Not just "the attacker dumps credentials" but exactly which API calls, which files are accessed, which privileges are required, what artifacts are created, and why defenders often miss it.
- Code examples and detection queries should be fully explained: what each field means, why that threshold was chosen, what the false positive rate looks like in practice.`

      : difficulty === "advanced"
      ? `AUDIENCE: Experienced SOC analysts, threat hunters, or detection engineers with solid fundamentals. They know common attack techniques, can read SIEM queries, and understand the incident response lifecycle.

ADVANCED TEACHING STANDARD:
- No hand-holding on basics. Go straight to the nuance, the edge cases, the evasion techniques defenders typically miss.
- Focus on detection gaps, anti-forensics, living-off-the-land variants, and real attacker tradecraft from documented APT campaigns.
- Detection content should address tuning, baselining, and the analyst decision tree — not just "write this query".`

      : `AUDIENCE: Detection engineers, senior threat hunters, purple teamers. Expert-level depth on adversary simulation, custom tooling, detection engineering at scale, and hardening decisions that close entire attack classes.`;

  return `You are a cybersecurity lecturer with 15 years of hands-on experience — you have worked incident response, built detection pipelines, and taught SOC analysts at organizations ranging from financial institutions to government agencies. You now write professional training content at the level of a SANS course combined with the clarity of a seasoned classroom instructor.

${audienceProfile}

═══════════════════════════════════════════════
LECTURER WRITING STANDARD — NON-NEGOTIABLE
═══════════════════════════════════════════════

DEPTH OF EXPLANATION:
A great lecturer does not just state facts — they explain mechanisms, consequences, and investigator implications in the same breath. Every technical claim must be followed by WHY it matters and WHAT the analyst does with that knowledge.

Bad: "Event ID 4624 indicates a successful logon."
Good: "Event ID 4624 is generated by the Windows Security log every time an authentication attempt succeeds — regardless of whether it was a human, a service account, or an attacker using stolen credentials. On a healthy domain controller, you will see thousands of these per day, which is exactly why attackers know their successful logon will be buried in noise. The field that separates legitimate logons from suspicious ones is not the event ID itself but the combination of LogonType (type 3 for network logons, which never require the user to physically touch a keyboard), AuthenticationPackageName (NTLM vs. Kerberos tells you which protocol was used and which attacks become possible), and the source IP — specifically whether it belongs to the user's expected subnet."

EXAMPLES — LECTURER QUALITY:
Every example must be grounded in a real scenario, real field names, real tools. Not toy examples. Write examples the way a lecturer writes them on a whiteboard mid-lecture: specific, precise, with enough context that the student understands both what they are looking at and what to do next.

BANNED PHRASES — never write these:
- "Let's imagine" / "Imagine you are" / "Imagine a scenario"
- "Step 1:" / "Step 2:" / "Step 3:" (as sub-headings or in-line enumeration)
- "Step by step" (as a phrase)
- "In this section, we will" / "In this lesson, we will"
- "Now that we understand" / "Having learned about"
- "In conclusion" / "To summarize"
- "Think of X like a Y" (generic analogies — use precise comparisons instead)
- "It is important to note" / "It is worth mentioning"
- "Simply" / "Just" / "Basically" / "Obviously"

SUB-HEADING QUALITY:
Sub-headings must be specific to the content — NOT generic. A reader should be able to read the sub-headings alone and understand what the section covers.
BAD: "How It Works" / "Overview" / "Introduction" / "Key Concepts"
GOOD: "Why NTLM Authentication Creates a Credential Interception Window" / "The Three Registry Keys Every Attacker Touches First" / "Reading a Forged Kerberos Ticket with Mimikatz Output"

FORMAT RULES:
- Full paragraphs only — no bullet points inside the content field
- Vary sentence structure and paragraph length deliberately
- Mix second-person ("when you open this log...") with analytical third-person ("the attacker's goal at this stage is...") and direct observation ("what the data shows is...")

TECHNICAL ACCURACY:
- Real MITRE ATT&CK IDs with full technique names (T1558.003 – Kerberoasting, not invented)
- Real tool names, real log field names, real CVEs, real threat actor names (APT29, FIN7, LAPSUS$)
- No invented threat actors, no made-up CVEs

Return ONLY valid JSON, no markdown fences.`;
}

// ─── Phase 1: Outline ─────────────────────────────────────────────────────────

interface Outline {
  title: string;
  intro: string;
  sectionHeadings: string[];
  keyTakeaways: string[];
  quiz: {
    question: string;
    options: { label: string; value: string }[];
    answer: string;
    explanation: string;
  }[];
}

async function generateOutline(
  client: OpenAI,
  topic: string,
  difficulty: string,
  kind: string,
  syllabus: string,
  sectionCount: number,
): Promise<Outline> {
  const defaultHeadings = [
    `The Foundations of ${topic} — What Every Analyst Must Know Before Day One`,
    `Inside the Attack — How ${topic} Works at the Protocol and Process Level`,
    `Real Incidents, Real Impact — Documented Cases and Attacker Tradecraft`,
    `The Evidence Trail — Log Sources, Fields, and What They Reveal`,
    `Building Detections That Actually Fire — Alerts, Rules, and Thresholds`,
    `The Investigation in Practice — From First Alert to Confident Verdict`,
    `Containment, Eradication, and Hardening — The Response Playbook`,
    `Gaps, Edge Cases, and Advanced Techniques — Where Defenders Often Fall Short`,
  ].slice(0, sectionCount);

  const res = await withRetry(() => client.chat.completions.create({
    model: MODEL,
    max_tokens: 3000,
    messages: [
      { role: "system", content: systemPrompt(difficulty) },
      {
        role: "user",
        content: `Create the outline for a ${difficulty}-level ${kind} about: "${topic}"
${syllabus ? `\nSpecific focus:\n${syllabus}\n` : ""}

Return this exact JSON (no extra keys):
{
  "title": "A specific, compelling title (8–14 words) that names the technique, tool, or threat — e.g. 'How Attackers Abuse Kerberos Service Tickets and How You Catch Them' or 'DNS Tunneling Detection: Turning Packet-Level Analysis into Actionable Alerts'. Do NOT use generic titles like 'Introduction to X' or 'Understanding X'.",
  "intro": "Three substantial paragraphs (600+ words total). Para 1: Start directly — not with 'In this lesson' or 'Welcome'. Open with the specific problem or threat and why it matters RIGHT NOW for a working SOC analyst. Explain the core concept from zero, defining every term as you use it, as if the student has never encountered this topic. Para 2: Ground it in reality — a specific documented incident or APT campaign (real actor, real victim sector, real outcome, real timeline). Explain what the attackers did technically, not just 'they hacked the company'. Para 3: Set expectations clearly — what the student will be able to DO after completing this lesson. Use concrete, testable skills, not vague promises. Prohibited phrases in the intro: 'Let us begin', 'In this lesson we will', 'Let's imagine', 'Welcome to'.",
  "sectionHeadings": ${JSON.stringify(defaultHeadings)},
  "keyTakeaways": [
    "Recognize [specific indicator or behavior] in [specific tool/log] and know what it means",
    "Write a [Splunk SPL / KQL / Sigma] query that detects [specific behavior] with [specific tuning approach]",
    "Distinguish [this attack] from [the most common false positive] using [specific field or context clue]",
    "Execute [specific investigation pivot] when [specific trigger condition] appears in the data",
    "Harden [specific configuration] to eliminate or reduce [specific attack surface]"
  ],
  "quiz": [
    {
      "question": "Scenario-based: start with 'A tier-1 analyst receives an alert showing...' or 'During a threat hunt you notice...' or 'Post-incident review reveals...' — make the question require real understanding, not just recall",
      "options": [
        {"label": "Wrong — specific technical detail that sounds right but is incorrect or incomplete", "value": "a"},
        {"label": "Correct — complete and technically precise answer", "value": "b"},
        {"label": "Wrong — a common analyst mistake or false positive assumption", "value": "c"},
        {"label": "Wrong — partially correct but misses a critical step or field", "value": "d"}
      ],
      "answer": "b",
      "explanation": "Explain why b is correct, what specifically makes a, c, d wrong, and the key principle the analyst should take away."
    }
  ]
}

Generate exactly ${sectionCount} section headings — they must be specific to "${topic}", not generic. Do NOT use phrases like "Step by Step", "Introduction", or "Overview" in headings.
Generate exactly 4 quiz questions. All content must be specific to "${topic}" at ${difficulty} level.`,
      },
    ],
  }));

  const text = res.choices[0]?.message?.content ?? "";
  return parseJson<Outline>(text, {
    title: topic,
    intro: `This ${kind} covers ${topic} for SOC analysts at the ${difficulty} level.`,
    sectionHeadings: defaultHeadings,
    keyTakeaways: [
      `Identify key indicators of ${topic}`,
      "Apply detection logic in your SIEM/EDR",
      "Follow escalation and response procedures",
      "Reduce false positives through context",
      "Reference relevant MITRE ATT&CK techniques",
    ],
    quiz: [],
  });
}

// ─── Phase 2: Individual section ──────────────────────────────────────────────

interface SectionResult {
  heading: string;
  content: string;
  codeExample?: string;
  imageQuery?: string;
}

// Teaching styles — one per section slot, cycling if more than 8 sections
const SECTION_STYLES = [
  {
    name: "Grounded in Reality",
    opening: "Open with a concrete, specific real-world incident (name the victim sector, the attacker group or technique, the outcome) that makes the student care about this topic before you explain it technically. Then unpack the underlying mechanism that made that incident possible.",
    subheadingHint: "Use sub-headings that describe the content specifically — e.g. 'The Three Conditions That Make This Attack Possible', 'What the Attacker Sees on Their Screen', 'Why Windows Logs This Differently from Linux'.",
    closingHint: "Close with a crisp one-sentence observation about why understanding this changes how an analyst reads the data.",
  },
  {
    name: "Mechanics First",
    opening: "Start by describing the technical mechanism from first principles — what exactly happens at the packet, process, or protocol level. Write it as if you are watching a slow-motion replay: 'Here is exactly what happens the moment an attacker runs this command...'",
    subheadingHint: "Sub-headings should reflect the technical layers or stages — e.g. 'The Protocol Exchange That Triggers the Vulnerability', 'Memory Layout During a Credential Dump', 'The Difference Between a Legitimate and a Malicious Request at the Wire Level'.",
    closingHint: "End by connecting the mechanical detail back to what the analyst will actually observe in their tooling.",
  },
  {
    name: "Attacker's Perspective First",
    opening: "Begin from the attacker's point of view — what goal are they trying to achieve, what tool or technique do they use, and what does success look like for them? Then flip the perspective: now that you understand what the attacker is doing, here is what it leaves behind for the defender.",
    subheadingHint: "Sub-headings can contrast attacker and defender views — e.g. 'What the Attacker Gains from This Move', 'The Artifacts Left Behind', 'How a Defender Turns This Against Them'.",
    closingHint: "Close with a detection insight the student can act on immediately.",
  },
  {
    name: "Evidence-Led",
    opening: "Start from the data — present a realistic log snippet, event sequence, or alert and ask the student to notice what stands out. Then explain the underlying cause that produced this evidence. Work backwards from the observable to the mechanism.",
    subheadingHint: "Sub-headings can describe evidence layers — e.g. 'What the SIEM Alert Actually Contains', 'Correlating Two Log Sources to Confirm the Behavior', 'Separating Signal from Background Noise'.",
    closingHint: "Close by describing what a complete evidence chain looks like and what gap still needs to be filled.",
  },
  {
    name: "Detection Engineering",
    opening: "Open by framing the detection challenge: why is this hard to catch? What does the malicious activity look like compared to legitimate behavior? Then build the detection logic piece by piece, explaining every decision.",
    subheadingHint: "Sub-headings should describe the detection construction process — e.g. 'Choosing the Right Log Source for This Behavior', 'The Field Values That Distinguish Attacker from Admin', 'Tuning to Eliminate the Top Five False Positives'.",
    closingHint: "End with a note about what this detection will miss and how to layer it with other signals.",
  },
  {
    name: "Investigator's Walkthrough",
    opening: "Narrate a realistic investigation: an alert fires, the analyst opens their SIEM. Walk the student through each decision point — what the analyst looks at first, what they pivot to, what questions they ask the data. Write it as a guided tour of an investigation.",
    subheadingHint: "Sub-headings should match investigation phases — e.g. 'The Alert That Triggered the Investigation', 'Pivoting on the Process Tree', 'The Question That Changed the Direction of the Hunt'.",
    closingHint: "Close by describing the decision: escalate to IR, close as false positive, or continue the hunt — and what evidence tipped the balance.",
  },
  {
    name: "Failure Mode Analysis",
    opening: "Start by describing what goes wrong when defenders don't understand or detect this — the consequences of missing it: lateral movement, ransomware detonation, data exfiltration. Then work backwards to explain what defenders need to have in place to catch it.",
    subheadingHint: "Sub-headings should describe the failure → fix progression — e.g. 'The Gap That Let the Attacker Persist for 47 Days', 'The Detection That Would Have Caught It on Day One', 'Hardening Decisions That Remove the Attack Surface'.",
    closingHint: "Close with the key hardening or detection control the student should prioritize first.",
  },
  {
    name: "Comparative Analysis",
    opening: "Open by drawing a clear contrast — this technique versus the one that came before it, this tool versus the alternative, this log source versus the one analysts mistake it for. Comparison is one of the fastest ways to build deep understanding.",
    subheadingHint: "Sub-headings can frame the comparison — e.g. 'Kerberoasting vs. AS-REP Roasting: Two Paths, Two Different Defenses', 'On-Premise Active Directory vs. Azure AD: Where the Evidence Lives', 'Why Sysmon Sees What Windows Security Audit Misses'.",
    closingHint: "Close by summarizing when to reach for one approach versus another and what shapes that decision in a real SOC.",
  },
] as const;

async function generateSection(
  client: OpenAI,
  topic: string,
  difficulty: string,
  sectionIndex: number,
  sectionTotal: number,
  heading: string,
  previousSections: SectionResult[],
): Promise<SectionResult> {
  const style = SECTION_STYLES[sectionIndex % SECTION_STYLES.length];

  const prevSummary = previousSections.length > 0
    ? `## Already covered in earlier sections — do NOT repeat this material:\n${
        previousSections.map((s, i) => `${i + 1}. "${s.heading}" — ${s.content.split(". ").slice(0, 2).join(". ")}.`).join("\n")
      }\n\n`
    : "";

  const res = await withRetry(() => client.chat.completions.create({
    model: MODEL,
    max_tokens: 3500,
    messages: [
      { role: "system", content: systemPrompt(difficulty) },
      {
        role: "user",
        content: `${prevSummary}Write section ${sectionIndex + 1} of ${sectionTotal} for a ${difficulty}-level SOC lesson about "${topic}".

Section title: **"${heading}"**

═══════════════════════════════════════
TEACHING STYLE FOR THIS SECTION: ${style.name}
═══════════════════════════════════════

OPENING APPROACH:
${style.opening}

SUB-HEADING GUIDANCE:
${style.subheadingHint}
Write exactly 2–3 sub-headings using ### format.
Sub-headings MUST be specific and descriptive, NOT generic phrases like "Overview", "How It Works", "Introduction", or "Step 1/2/3".

CLOSING APPROACH:
${style.closingHint}

═══════════════════════════════════════
MANDATORY REQUIREMENTS
═══════════════════════════════════════

LENGTH & DEPTH — LECTURER STANDARD:
- Total: 850–1100 words. This is not a blog post — it is a lecture. Depth over brevity.
- Every paragraph must advance understanding. No filler. No "as mentioned above". No repeating the section heading in prose.
- ${difficulty === "beginner"
  ? "BEGINNER DEPTH REQUIREMENT: every technical term defined inline the moment it appears. Trace cause-and-effect chains completely — do not skip steps in a mechanism. A beginner reading this must finish with a working mental model, not just awareness that the thing exists."
  : difficulty === "intermediate"
  ? "INTERMEDIATE DEPTH REQUIREMENT: connect concepts to attack chains, log sources, and detection logic. Explain what the analyst will actually see in their tooling and what decisions they need to make."
  : "ADVANCED DEPTH REQUIREMENT: focus on nuance, evasion variants, detection gaps, tuning considerations, and real attacker tradecraft from documented campaigns. Assume the reader knows the basics — go where most resources don't."}

TECHNICAL PRECISION — LECTURER STANDARD:
The difference between a generic article and a lecturer's explanation is specificity.
- Do not say "the attacker uses a tool" — name the tool, the specific flag or parameter, and what it does at the OS level
- Do not say "a log event is generated" — name the exact event ID, which log file it appears in, which field contains the interesting value, and what that value looks like in a real alert
- Do not say "you can detect this in your SIEM" — write the actual query logic (Splunk SPL or KQL) and explain every clause
- Reference: Splunk, Microsoft Sentinel, CrowdStrike Falcon, MDE, SentinelOne, Elastic SIEM, Okta, Azure AD / Entra ID
- Real MITRE ATT&CK IDs with full names: T1558.003 – Kerberoasting
- Real log field names: winlog.event_data.CommandLine, process.parent.name, source.ip, event.code, user.name
- Real threat actors when relevant: APT29, FIN7, Lazarus Group, LAPSUS$, Scattered Spider

WRITING QUALITY — LECTURER STANDARD:
- Full paragraphs only. No bullet lists in the content field.
- Write the way a skilled lecturer speaks: authoritative, precise, with occasional direct address ("what you are looking at here is..."), varied rhythm, no padding
- Each paragraph should end with either a consequence, an implication for the analyst, or a bridge to the next idea
- None of the banned phrases from the system prompt

CODE EXAMPLE — LECTURER QUALITY:
- A real, copy-pasteable query or command that a working analyst would actually run
- Splunk SPL / Microsoft Sentinel KQL / Sigma YAML / PowerShell / bash — match the tool to the context
- Multi-line, well-commented: explain what each clause does and why it is written that way
- If it is a log excerpt, include realistic field values — not "username: user1" but "user.name: svc_backup" with a note explaining why a service account name is suspicious in this context

Return ONLY this JSON (no markdown fences, no extra keys):
{
  "content": "### Specific Descriptive Sub-heading\\n\\nParagraphs...\\n\\n### Another Specific Sub-heading\\n\\nParagraphs...\\n\\n### Third Sub-heading If Needed\\n\\nFinal paragraphs...",
  "codeExample": "# Explanation of what this does and when to use it\\n<actual realistic code>",
  "imageQuery": "3-4 English keywords for an Unsplash photo that visually represents this section's core concept"
}`,
      },
    ],
  }));

  const text = res.choices[0]?.message?.content ?? "";
  const parsed = parseJson<{ content?: string; codeExample?: string; imageQuery?: string }>(text, {});

  return {
    heading,
    content: parsed.content ?? `Section ${sectionIndex + 1}: ${heading}\n\nContent for this section about ${topic}.`,
    codeExample: parsed.codeExample,
    imageQuery: parsed.imageQuery,
  };
}

// ─── Route ────────────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({})) as {
    topic?: string;
    difficulty?: string;
    kind?: "lesson" | "lab" | "quiz";
    syllabus?: string;
    sections?: number;
  };

  const topic        = (body.topic ?? "SOC Operations").trim();
  const difficulty   = body.difficulty ?? "intermediate";
  const kind         = body.kind ?? "lesson";
  const syllabus     = body.syllabus ?? "";
  const sectionCount = Math.min(Math.max(body.sections ?? 8, 3), 10);

  const encoder = new TextEncoder();

  if (!process.env.OPENAI_API_KEY) {
    return new Response(
      `data: ${JSON.stringify({ type: "error", message: "OPENAI_API_KEY not configured in .env.local" })}\n\n`,
      { status: 200, headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" } },
    );
  }

  const client = getClient();

  const stream = new ReadableStream({
    async start(controller) {
      function send(event: Record<string, unknown>) {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
      }

      try {
        // ── Phase 1: Outline ───────────────────────────────────────────────
        send({ type: "phase", message: `📋 Building lesson outline for "${topic}"…` });
        const outline = await generateOutline(
          client, topic, difficulty, kind, syllabus, sectionCount,
        );
        send({ type: "outline", data: { title: outline.title, sectionHeadings: outline.sectionHeadings } });

        // ── Phase 2: Sections ──────────────────────────────────────────────
        const sections: SectionResult[] = [];

        for (let i = 0; i < outline.sectionHeadings.length; i++) {
          const heading = outline.sectionHeadings[i];

          // Pace requests to stay within Gemini free-tier rate limit (15 RPM)
          // 4s gap → max ~15 calls/min including the outline call
          if (i > 0) await sleep(4000);

          send({
            type: "phase",
            message: `✍️ Writing section ${i + 1}/${outline.sectionHeadings.length}: "${heading}"…`,
          });

          const section = await generateSection(
            client, topic, difficulty,
            i, outline.sectionHeadings.length, heading, sections,
          );
          sections.push(section);

          send({ type: "section_done", index: i, section });
        }

        // ── Phase 3: Assemble & send done ──────────────────────────────────
        const slug = slugify(outline.title ?? topic);
        const lesson: GeneratedLesson = {
          id:   `gen-lesson-${Date.now()}`,
          slug: `${slug}-${Date.now()}`,
          title:      outline.title,
          topic,
          difficulty,
          kind,
          intro:         outline.intro,
          sections,
          keyTakeaways:  outline.keyTakeaways,
          quiz:          outline.quiz,
          references:    [],
          xp:               calcXp(sectionCount, difficulty),
          estimatedMinutes: calcMinutes(sectionCount),
          published_at:     new Date().toISOString(),
          createdAt:        new Date().toISOString(),
          researchUsed:     false,
        };

        send({ type: "done", lesson });
      } catch (err) {
        const raw = err instanceof Error ? err.message : String(err);
        let message = raw;
        if (raw.includes("API key") || raw.includes("401") || raw.includes("authentication") || raw.includes("Incorrect")) {
          message = "OpenAI API key error — check OPENAI_API_KEY in .env.local";
        } else if (raw.includes("quota") || raw.includes("429") || raw.includes("rate") || raw.includes("insufficient_quota")) {
          message = "OpenAI quota exceeded — check your billing at platform.openai.com";
        } else if (raw.includes("model") || raw.includes("404")) {
          message = "OpenAI model not found";
        }
        console.error("[generate-stream] OpenAI error:", raw);
        send({ type: "error", message });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type":  "text/event-stream",
      "Cache-Control": "no-cache",
      "Connection":    "keep-alive",
    },
  });
}
