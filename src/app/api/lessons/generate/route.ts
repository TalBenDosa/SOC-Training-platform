import OpenAI from "openai";
import { requireAdmin } from "@/lib/auth/apiGuard";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface GeneratedLesson {
  id: string;
  slug: string;
  title: string;
  topic: string;
  difficulty: string;
  kind: "lesson" | "lab" | "quiz";
  intro: string;
  sections: { heading: string; content: string; codeExample?: string }[];
  keyTakeaways: string[];
  quiz: {
    question: string;
    options: { label: string; value: string }[];
    answer: string;
    explanation: string;
  }[];
  references: string[];
  xp: number;
  estimatedMinutes: number;
  published_at: string;
  createdAt: string;
  researchUsed: boolean;
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

// ─── Prompts ──────────────────────────────────────────────────────────────────

function buildSystemPrompt(difficulty: string, kind: string): string {
  const levelHint =
    difficulty === "beginner"     ? "no prior security experience — define all jargon, explain every concept from scratch, use analogies" :
    difficulty === "intermediate" ? "1–2 years SOC experience — build on known SIEM/EDR basics, introduce advanced detection patterns" :
    difficulty === "advanced"     ? "3–5 years with deep technical knowledge — skip basics, focus on nuanced edge cases, evasion, advanced hunting" :
                                    "expert-level red/blue team — assume mastery, focus on cutting-edge TTPs, custom detection engineering, adversary simulation";

  return `You are a senior SOC analyst, threat hunter, and cybersecurity curriculum designer with 15+ years of experience writing professional training material (equivalent to SANS FOR508/SEC555 quality).

You are creating a ${difficulty}-level ${kind} for security operations professionals (${levelHint}).

WRITING STANDARDS — mandatory for every section:
1. Each section MUST contain at minimum 600 words of substantive technical content
2. Each section MUST include at least ONE of: a realistic SPL query, KQL query, Sigma rule, log excerpt, CLI command, or Yara rule — placed in the codeExample field
3. Write in the second person ("When you investigate...", "You will notice...", "Your next step is...")
4. Cite real tool names throughout: Splunk, Microsoft Sentinel, CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne, Elastic SIEM, Okta, Azure AD, Carbon Black, Tanium, Tenable, Rapid7, etc.
5. Include specific MITRE ATT&CK technique IDs (e.g. T1059.003, T1136.001, T1078.004) with their exact names
6. Reference real-world threat actors when relevant (APT29, Lazarus Group, FIN7, etc.)
7. Log field names must be realistic (process.name, event.code, winlog.event_data.CommandLine, src_ip, etc.)
8. Every claim must be accurate — do not invent CVEs, tool features, or technique IDs

STRUCTURE REQUIREMENTS:
- Intro: 3 full paragraphs (400+ words), explain WHY this matters, what threats exploit this, and what the reader will learn
- Sections: EXACTLY the requested number, each with 600+ words of content and a code example
- Key takeaways: 5 items starting with action verbs (Identify / Configure / Detect / Analyze / Build)
- Quiz: EXACTLY 4 scenario-based questions — realistic SOC situations, not trivia. Each option must be plausible

Return ONLY valid JSON — no markdown fences, no preamble, no trailing text.`;
}

function buildGeneratePrompt(
  topic: string,
  difficulty: string,
  kind: string,
  syllabus: string,
  sectionCount: number,
  researchContext: string,
): string {
  const contextBlock = researchContext
    ? `## Current Research on "${topic}"\n\n${researchContext}\n\n---\n\n`
    : "";

  const sectionGuidance = [
    "Threat Overview & Attack Chain — how the attack/technique works end-to-end, who uses it, real incident examples",
    "Technical Deep-Dive — internals, protocols, data structures, OS/kernel interactions involved",
    "Detection Engineering — SIEM rules, behavioral detections, log sources, field names, query examples",
    "Investigation & Triage — step-by-step analyst workflow, what to look for, pivot points, false positive reduction",
    "Response & Remediation — containment steps, eradication, recovery, post-incident hardening",
    "Advanced Techniques & Edge Cases — evasion methods, detection gaps, hunting hypotheses, custom detections",
    "Threat Intelligence & Attribution — actor profiles, campaign overlays, IOC management, intel enrichment",
  ].slice(0, sectionCount);

  return `${contextBlock}Create a professional, in-depth ${difficulty}-level ${kind} about: **"${topic}"**
${syllabus ? `\nSpecific focus areas requested:\n${syllabus}\n` : ""}

## Content Requirements

Each section MUST:
- Contain 600–900 words of substantive, technically accurate content
- Include at least one REAL code example: SPL search, KQL query, Sigma rule, CLI command, log excerpt, or YARA rule
- Reference real products, MITRE ATT&CK IDs, threat actor names, and log field names
- Teach something actionable — the reader must be able to DO something after reading it

Suggested section themes (adapt as needed for the topic):
${sectionGuidance.map((s, i) => `${i + 1}. ${s}`).join("\n")}

## Output Format

Return exactly this JSON (no markdown fences, no extra keys, no preamble):
{
  "title": "Specific, engaging title (8–14 words, e.g. 'Detecting Kerberoasting Attacks with Splunk and Microsoft Sentinel')",
  "intro": "Three full paragraphs (400+ words total). Para 1: what this topic is and why attackers use/exploit it. Para 2: real-world impact — name specific incidents, actors, or CVEs. Para 3: what this ${kind} covers and what the reader will be able to do afterwards.",
  "sections": [
    {
      "heading": "Descriptive section title (5–10 words)",
      "content": "600–900 words of detailed technical content. Use second-person voice ('When you investigate...', 'You will notice...'). Include: specific tool names, exact log field names (e.g. process.name, winlog.event_data.CommandLine), MITRE ATT&CK technique IDs with names (e.g. T1558.003 – Kerberoasting), realistic threat actor references, concrete step-by-step examples. Do NOT use bullet points — write in full paragraphs that flow naturally.",
      "codeExample": "REQUIRED: A realistic, copy-pasteable example. Use SPL for Splunk topics, KQL for Sentinel/Azure topics, Sigma YAML for detection rules, bash/PowerShell for commands, or a realistic multi-line log excerpt with real field names. Include a comment line explaining what it does."
    }
  ],
  "keyTakeaways": [
    "Identify [specific artifact/indicator] in [specific tool/log source]",
    "Configure [specific detection/rule] to alert on [specific behavior]",
    "Detect [specific TTP] by correlating [specific log fields]",
    "Analyze [specific evidence type] to distinguish [false positive scenario] from real attacks",
    "Build [specific hunt/query/playbook] to proactively search for [specific threat]"
  ],
  "quiz": [
    {
      "question": "Scenario-based question (e.g. 'A SOC analyst notices...' or 'During a hunt you observe...'). Must test practical judgment, not memorization.",
      "options": [
        {"label": "Plausible but incorrect option with specific technical detail", "value": "a"},
        {"label": "Correct answer with specific technical justification", "value": "b"},
        {"label": "Plausible but incorrect option — a common analyst mistake", "value": "c"},
        {"label": "Plausible but incorrect option — partially correct but missing key step", "value": "d"}
      ],
      "answer": "b",
      "explanation": "2–3 sentences explaining WHY this is correct, what makes the wrong answers incorrect, and any key nuance the analyst should remember."
    }
  ],
  "references": ["URLs or titles from the research context — include up to 8 of the most relevant"]
}

CRITICAL: Exactly ${sectionCount} sections. Exactly 4 quiz questions. All content must be specific to "${topic}" — no generic filler.`;
}

// ─── Route ────────────────────────────────────────────────────────────────────
// (Web research phase removed — use generate-stream for full pipeline)

// ─── Local fallback ────────────────────────────────────────────────────────────

function buildLocalLesson(
  topic: string,
  difficulty: string,
  kind: "lesson" | "lab" | "quiz",
  sectionCount: number,
): GeneratedLesson {
  const title = `${topic} — SOC Analyst ${kind.charAt(0).toUpperCase() + kind.slice(1)}`;
  const slugBase = slugify(title);
  const headings = [
    "Introduction & Overview",
    "Core Technical Concepts",
    "Detection & Analysis",
    "Response & Mitigation",
    "Practical Exercises",
    "Advanced Techniques",
    "Case Studies & Lessons Learned",
  ];

  return {
    id: `gen-lesson-${Date.now()}`,
    slug: `${slugBase}-${Date.now()}`,
    title,
    topic,
    difficulty,
    kind,
    intro: `This ${kind} provides a comprehensive overview of **${topic}** for SOC analysts at the ${difficulty} level.\n\nUnderstanding ${topic} is critical for modern security operations — this content covers both the theoretical foundations and practical detection/response techniques you'll apply daily in the SOC.\n\nBy the end of this ${kind}, you will be able to identify key indicators, apply correct tooling, and respond effectively to incidents involving ${topic}.`,
    sections: Array.from({ length: sectionCount }, (_, i) => ({
      heading: headings[i % headings.length],
      content: `This section covers ${headings[i % headings.length].toLowerCase()} in the context of ${topic}. SOC analysts must be proficient in these areas to correctly triage and escalate incidents.\n\nKey focus areas include understanding the underlying mechanisms, recognizing behavioral patterns in log data, and applying MITRE ATT&CK sub-techniques for detection coverage.\n\nPractical exercises reinforce the material with hands-on SIEM queries and scenario walkthroughs.`,
    })),
    keyTakeaways: [
      `Identify key indicators and artifacts associated with ${topic}`,
      `Apply appropriate detection logic in your SIEM/EDR tooling`,
      `Follow established escalation and response procedures`,
      `Reduce false positive rates through accurate context assessment`,
      `Reference MITRE ATT&CK techniques relevant to ${topic} threats`,
    ],
    quiz: [
      {
        question: `Which approach is most effective for detecting ${topic} in a SOC environment?`,
        options: [
          { label: "Search for known-bad IOC hashes only", value: "a" },
          { label: "Correlate behavior patterns across multiple log sources", value: "b" },
          { label: "Only alert on critical-severity events", value: "c" },
          { label: "Disable alerting and review logs manually", value: "d" },
        ],
        answer: "b",
        explanation: "Behavioral correlation across multiple sources provides the best detection coverage, reducing both false positives and negatives compared to IOC-only or severity-only approaches.",
      },
    ],
    references: [],
    xp: calcXp(sectionCount, difficulty),
    estimatedMinutes: calcMinutes(sectionCount),
    published_at: new Date().toISOString(),
    createdAt: new Date().toISOString(),
    researchUsed: false,
  };
}

// ─── Route (Gemini-powered) ───────────────────────────────────────────────────

export async function POST(req: Request) {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;

  const body = await req.json().catch(() => ({}));
  const {
    title,
    topic = "SOC Operations",
    difficulty = "intermediate",
    kind = "lesson",
    syllabus = "",
    sections: sectionCount = 5,
  } = body as {
    title?: string;
    topic?: string;
    difficulty?: string;
    kind?: "lesson" | "lab" | "quiz";
    syllabus?: string;
    sections?: number;
  };

  const lessonTopic = (title || topic).trim();

  // ── No API key — return local stub immediately ─────────────────────────────
  if (!process.env.OPENAI_API_KEY) {
    return Response.json(buildLocalLesson(lessonTopic, difficulty, kind, sectionCount));
  }

  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  try {
    const response = await client.chat.completions.create({
      model: "gpt-4o-mini",
      max_tokens: 8000,
      messages: [
        { role: "system", content: buildSystemPrompt(difficulty, kind) },
        {
          role: "user",
          content: buildGeneratePrompt(
            lessonTopic, difficulty, kind, syllabus, sectionCount, "",
          ),
        },
      ],
    });

    const text = response.choices[0]?.message?.content ?? "";
    const stripped = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");
    const jsonMatch = stripped.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("Model did not return valid JSON");

    const parsed = JSON.parse(jsonMatch[0]);
    const slug = slugify(parsed.title ?? lessonTopic);

    const lesson: GeneratedLesson = {
      id:    `gen-lesson-${Date.now()}`,
      slug:  `${slug}-${Date.now()}`,
      title: parsed.title ?? lessonTopic,
      topic: lessonTopic,
      difficulty,
      kind,
      intro:         parsed.intro         ?? "",
      sections:      (parsed.sections ?? []).map((s: { heading: string; content: string; codeExample?: string }) => ({
        heading:     s.heading,
        content:     s.content,
        codeExample: s.codeExample || undefined,
      })),
      keyTakeaways:  parsed.keyTakeaways  ?? [],
      quiz:          parsed.quiz          ?? [],
      references:    (parsed.references ?? []).filter(Boolean).slice(0, 8),
      xp:               calcXp(sectionCount, difficulty),
      estimatedMinutes: calcMinutes(sectionCount),
      published_at:     new Date().toISOString(),
      createdAt:        new Date().toISOString(),
      researchUsed:     false,
    };

    return Response.json(lesson);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[generate] Gemini lesson generation failed:", message);
    return Response.json(buildLocalLesson(lessonTopic, difficulty, kind, sectionCount));
  }
}
