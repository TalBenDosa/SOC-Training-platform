/**
 * GET /api/lessons/{pathSlug}--{lessonSlug}
 *
 * Returns AI-generated lesson content (10 pages + 4-question quiz).
 * Content is cached in a server-side Map for the Node.js process lifetime
 * (survives hot-reloads, resets on server restart — cheap for dev/demo).
 *
 * If ANTHROPIC_API_KEY is set, generates real content via Claude with
 * prompt caching on the system message. Otherwise returns stub content.
 */

import { NextResponse } from "next/server";
import { findLesson } from "@/lib/lessons/paths";

export const runtime = "nodejs";

export interface LessonPage {
  pageNumber: number;
  title: string;
  body: string;
  codeExample?: string;
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
      "codeExample": "string or null — a real log line, command, or YAML snippet",
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

// ─── Route handler ─────────────────────────────────────────────────────────────

export async function GET(
  _req: Request,
  { params }: { params: { slug: string } },
) {
  const raw = decodeURIComponent(params.slug);
  const sep = raw.indexOf("--");
  if (sep === -1) {
    return NextResponse.json({ error: "Invalid slug format. Expected: {pathSlug}--{lessonSlug}" }, { status: 400 });
  }

  const pathSlug   = raw.slice(0, sep);
  const lessonSlug = raw.slice(sep + 2);

  const found = findLesson(pathSlug, lessonSlug);
  if (!found) {
    return NextResponse.json({ error: `Lesson not found: ${pathSlug}/${lessonSlug}` }, { status: 404 });
  }

  const cacheKey = raw;
  if (cache.has(cacheKey)) {
    return NextResponse.json(cache.get(cacheKey));
  }

  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    const stub = buildStub(found.lesson.title, found.lesson.topic);
    stub.lessonSlug = lessonSlug;
    cache.set(cacheKey, stub);
    return NextResponse.json(stub);
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

    const parsed = JSON.parse(rawJson) as { pages: LessonPage[]; quiz: LessonQuizQuestion[] };

    const result: GeneratedLesson = {
      lessonSlug,
      lessonTitle: found.lesson.title,
      pages: parsed.pages,
      quiz: parsed.quiz,
    };

    cache.set(cacheKey, result);
    return NextResponse.json(result);
  } catch (err) {
    console.error("[lessons API]", err);
    const stub = buildStub(found.lesson.title, found.lesson.topic);
    stub.lessonSlug = lessonSlug;
    return NextResponse.json(stub);
  }
}
