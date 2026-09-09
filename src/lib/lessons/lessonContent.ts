import "server-only";
/**
 * Server-side lesson content: generation, the process-lifetime cache, and the
 * client-safe projection.
 *
 * Extracted from `src/app/api/lessons/[slug]/route.ts` so that BOTH the GET
 * route (which serves the answer-STRIPPED lesson to the browser) and the new
 * `POST /api/lessons/[slug]/quiz/grade` route (which grades server-side against
 * the FULL lesson) resolve exactly the same content through one code path.
 *
 * SECURITY (M-01): the full `GeneratedLesson` carries the quiz answer key
 * (`answer` + `explanation`). It must never cross to the client. Callers that
 * respond to the browser MUST project through `stripLessonQuiz()`; only the
 * server-side grader ever reads the full quiz.
 */

import { findLesson } from "@/lib/lessons/paths";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { checkAiBudget, recordAiUsage } from "@/lib/ai/usage";

export interface LessonPage {
  pageNumber: number;
  title: string;
  body: string;
  codeExample?: string;
  // Optional still image for concepts Mermaid can't express — a real console
  // screenshot (Splunk/Sentinel/EDR UI), a network topology, etc. `src` should
  // be a same-origin path under /public (e.g. /lessons/img/foo.webp) or a data:
  // URI; the CSP already permits self/data/https img-src (next.config.mjs).
  // AI-generated lessons never populate this (they can't produce accurate
  // imagery) — it is for hand-authored/curated lessons only.
  image?: { src: string; alt: string; caption?: string };
  keyPoints: string[];
}

export interface LessonQuizQuestion {
  question: string;
  options: { label: string; value: string }[];
  answer: string;
  explanation: string;
}

export interface GeneratedLesson {
  lessonSlug: string;
  lessonTitle: string;
  pages: LessonPage[];
  quiz: LessonQuizQuestion[];
}

// ─── Client-safe projections (answer key removed) ───────────────────────────────

/** A quiz question as the browser is allowed to see it: prompt + options, but
 *  NOT the correct `answer` or the post-answer `explanation`. */
export type ClientLessonQuizQuestion = Omit<LessonQuizQuestion, "answer" | "explanation">;

/** The lesson as delivered to the client — identical to GeneratedLesson except
 *  the quiz is stripped of its answer key. */
export type ClientLesson = Omit<GeneratedLesson, "quiz"> & {
  quiz: ClientLessonQuizQuestion[];
};

/** Project a full lesson down to what is safe to hand the browser. Mirrors
 *  `sanitizeRoom` / the scenario GET allowlist: the answer key stays server-side
 *  and is revealed only per-answered-question by the grade route. */
export function stripLessonQuiz(lesson: GeneratedLesson): ClientLesson {
  return {
    ...lesson,
    quiz: lesson.quiz.map(({ answer: _answer, explanation: _explanation, ...q }) => q),
  };
}

// ─── Server-side cache ────────────────────────────────────────────────────────

const cache = new Map<string, GeneratedLesson>();

// ─── Prompts ──────────────────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are a senior SOC analyst and cybersecurity trainer writing structured lesson content for a training platform called "Hack The SOC".

Your students are junior-to-intermediate security analysts. Write content that is:
- Practical and grounded in real SOC tooling (Splunk, Sentinel, CrowdStrike, etc.)
- Uses real log examples, command lines, and MITRE technique IDs where relevant
- Conversational but authoritative — explain the "why" not just the "what"
- Structured with clear headings and bullet points

Output ONLY valid JSON matching this exact schema (no markdown code fence, no preamble):
{
  "pages": [
    {
      "pageNumber": 1,
      "title": "string — page title",
      "body": "string — 200-300 words of markdown content",
      "codeExample": "string or null — a real log line, command, YAML snippet, OR a Mermaid diagram (see below)",
      "keyPoints": ["string", "string", "string"]
    }
  ],
  "quiz": [
    {
      "question": "string",
      "options": [
        { "label": "string", "value": "a" },
        { "label": "string", "value": "b" },
        { "label": "string", "value": "c" },
        { "label": "string", "value": "d" }
      ],
      "answer": "a",
      "explanation": "string — 1-2 sentences explaining why"
    }
  ]
}

DIAGRAMS: When a page describes something structural or sequential — a protocol exchange (Kerberos, TLS, TCP handshake), a kill chain, a process tree, a trust relationship, an authentication flow, or an attack path — prefer setting "codeExample" to Mermaid diagram source instead of a log line. Prose explains these badly; a diagram is far clearer. The platform renders Mermaid automatically. The source MUST start on its first line with one of: flowchart, sequenceDiagram, stateDiagram-v2, timeline, or flowchart TD/LR. Example:
"codeExample": "sequenceDiagram\\n  participant Client\\n  participant KDC\\n  Client->>KDC: AS-REQ (encrypted timestamp)\\n  KDC-->>Client: AS-REP (TGT + session key)\\n  Client->>KDC: TGS-REQ (present TGT)\\n  KDC-->>Client: TGS-REP (service ticket)"
Use a real log line or command for codeExample when the page is about reading telemetry; use a Mermaid diagram when the page is about how a process or relationship works. Aim for at least 2-3 diagrams across the 10 pages where the topic is structural.

Generate exactly 10 pages and exactly 4 quiz questions. The quiz tests the content covered in the pages.`;

function buildUserPrompt(lessonTitle: string, topic: string, difficulty: string, pathTitle: string, moduleTitle: string): string {
  return `Generate lesson content for the following lesson in the "${pathTitle}" learning path, module "${moduleTitle}":

Lesson title: "${lessonTitle}"
Topic: ${topic}
Difficulty: ${difficulty}
Target audience: Junior-to-mid level SOC analysts

Cover the topic progressively across 10 pages — start with foundations and build to practical application.
Include realistic examples (log snippets, alert fields, MITRE technique IDs) throughout.`;
}

// ─── Stub content (when no API key) ──────────────────────────────────────────

function buildStub(lessonTitle: string, topic: string): GeneratedLesson {
  return {
    lessonSlug: "",
    lessonTitle,
    pages: Array.from({ length: 10 }, (_, i) => ({
      pageNumber: i + 1,
      title: i === 0 ? `Introduction: ${lessonTitle}` : `Part ${i + 1}: ${topic.split(",")[i % 3] ?? topic}`,
      body: `## ${i === 0 ? "Introduction" : `Part ${i + 1}`}\n\nThis lesson covers **${lessonTitle}**.\n\n${topic}\n\n> **Note:** This is stub content. Configure \`ANTHROPIC_API_KEY\` in your \`.env.local\` to generate real AI-written lesson content.\n\nKey concepts for SOC analysts:\n- Understanding the fundamentals\n- Applying this knowledge during investigations\n- Practical examples from real-world incidents`,
      codeExample: i % 3 === 0 ? `# Example relevant to ${lessonTitle}\nEventID=4688 ProcessName=powershell.exe CommandLine="-EncodedCommand <base64>"` : undefined,
      keyPoints: [
        `Core concept ${i + 1}a for ${lessonTitle}`,
        `Practical application in a SOC context`,
        `How this relates to MITRE ATT&CK`,
      ],
    })),
    quiz: [
      {
        question: `What is the primary purpose of ${lessonTitle} in a SOC context?`,
        options: [
          { label: "Improving threat detection coverage", value: "a" },
          { label: "Reducing false positives", value: "b" },
          { label: "Both detection and response operations", value: "c" },
          { label: "Compliance reporting only", value: "d" },
        ],
        answer: "c",
        explanation: `${lessonTitle} supports both detection and response operations in a SOC environment.`,
      },
      {
        question: "Which MITRE ATT&CK tactic involves adversaries running malicious code?",
        options: [
          { label: "Initial Access (TA0001)", value: "a" },
          { label: "Execution (TA0002)", value: "b" },
          { label: "Persistence (TA0003)", value: "c" },
          { label: "Defense Evasion (TA0005)", value: "d" },
        ],
        answer: "b",
        explanation: "Execution (TA0002) covers techniques where adversaries run malicious code on target systems.",
      },
      {
        question: "A process tree shows WINWORD.EXE → powershell.exe → cmd.exe. What does this indicate?",
        options: [
          { label: "Normal Office automation", value: "a" },
          { label: "Macro-based initial access (T1566.001)", value: "b" },
          { label: "User browsing activity", value: "c" },
          { label: "Windows Update process", value: "d" },
        ],
        answer: "b",
        explanation: "Office spawning PowerShell then cmd.exe is a classic indicator of macro-based malware execution (T1566.001 + T1059.001).",
      },
      {
        question: "When should an analyst escalate to Tier 2?",
        options: [
          { label: "Every alert regardless of severity", value: "a" },
          { label: "Only critical severity alerts", value: "b" },
          { label: "When the alert is confirmed malicious or investigation scope exceeds L1 capability", value: "c" },
          { label: "After 24 hours of investigation", value: "d" },
        ],
        answer: "c",
        explanation: "Escalation happens when an alert is confirmed true positive or when the investigation requires deeper forensic capabilities beyond Tier 1.",
      },
    ],
  };
}

// ─── Slug parsing ───────────────────────────────────────────────────────────────

/** Split a `{pathSlug}--{lessonSlug}` route slug. Returns null on bad format. */
export function parseLessonSlug(raw: string): { pathSlug: string; lessonSlug: string } | null {
  const sep = raw.indexOf("--");
  if (sep === -1) return null;
  return { pathSlug: raw.slice(0, sep), lessonSlug: raw.slice(sep + 2) };
}

export type ResolveLessonResult =
  | { full: GeneratedLesson }
  | { error: string; status: number };

/**
 * Resolve a route slug to the FULL lesson (answer key included), generating and
 * caching via Claude when configured or falling back to the stub. This is the
 * single source of truth used by the GET route (stripped before responding) and
 * the quiz grader (reads the full quiz server-side).
 *
 * Guest / no-API-key / over-budget callers get the stub — unchanged behaviour,
 * kept identical to the previous inline GET so nothing about the guest path or
 * the paid-LLM budgeting regresses.
 */
export async function resolveGeneratedLesson(raw: string): Promise<ResolveLessonResult> {
  const parsed = parseLessonSlug(raw);
  if (!parsed) {
    return { error: "Invalid slug format. Expected: {pathSlug}--{lessonSlug}", status: 400 };
  }
  const { pathSlug, lessonSlug } = parsed;

  const found = findLesson(pathSlug, lessonSlug);
  if (!found) {
    return { error: `Lesson not found: ${pathSlug}/${lessonSlug}`, status: 404 };
  }

  const cacheKey = raw;
  const cached = cache.get(cacheKey);
  if (cached) return { full: cached };

  // Real AI generation is gated behind a signed-in user so anonymous callers
  // can't run up the AI bill by enumerating lesson slugs. Guests get the stub.
  const apiKey = process.env.ANTHROPIC_API_KEY;
  const authed = apiKey ? await getAuthedUser() : null;
  // Spend ceiling (migration 0024) — over budget, serve the stub rather than
  // generating. Treated exactly like "no AI backend" so the cache isn't poisoned.
  const overBudget = authed ? !(await checkAiBudget(authed.orgId)).allowed : false;
  if (!apiKey || !authed || overBudget) {
    const stub = buildStub(found.lesson.title, found.lesson.topic);
    stub.lessonSlug = lessonSlug;
    // Only persist the stub when there is genuinely no AI backend; if AI exists
    // but the caller is a guest, don't poison the cache for a future signed-in
    // user who should receive real generated content.
    if (!apiKey) cache.set(cacheKey, stub);
    return { full: stub };
  }

  try {
    const { default: Anthropic } = await import("@anthropic-ai/sdk");
    const client = new Anthropic({ apiKey });

    const userPrompt = buildUserPrompt(
      found.lesson.title,
      found.lesson.topic,
      found.lesson.difficulty,
      found.path.title,
      found.module.title,
    );

    const msg = await client.messages.create({
      model: process.env.ANTHROPIC_MODEL ?? "claude-haiku-4-5-20251001",
      max_tokens: 6000,
      system: [
        {
          type: "text" as const,
          text: SYSTEM_PROMPT,
          cache_control: { type: "ephemeral" as const },
        },
      ],
      messages: [{ role: "user", content: userPrompt }],
    });

    const rawJson = msg.content
      .map(c => (c.type === "text" ? c.text : ""))
      .join("");

    const parsedJson = JSON.parse(rawJson) as { pages: LessonPage[]; quiz: LessonQuizQuestion[] };

    const result: GeneratedLesson = {
      lessonSlug,
      lessonTitle: found.lesson.title,
      pages: parsedJson.pages,
      quiz: parsedJson.quiz,
    };

    cache.set(cacheKey, result);
    await recordAiUsage({
      route: "/api/lessons/[slug]",
      userId: authed.id,
      orgId: authed.orgId,
      model: msg.model,
      usage: msg.usage,
    });
    return { full: result };
  } catch (err) {
    console.error("[lessons API]", err);
    const stub = buildStub(found.lesson.title, found.lesson.topic);
    stub.lessonSlug = lessonSlug;
    return { full: stub };
  }
}
