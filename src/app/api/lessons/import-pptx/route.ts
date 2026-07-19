import OpenAI from "openai";
import { requireAdmin } from "@/lib/auth/apiGuard";
import type { GeneratedLesson } from "../generate/route";
import type { ExtractedSlide } from "@/lib/lessons/importPptx";

export const maxDuration = 60;

// ─── Types ────────────────────────────────────────────────────────────────────

interface ImportPptxRequest {
  topic:  string;
  slides: ExtractedSlide[];
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

// ─── Minimal lesson fallback (if AI fails) ────────────────────────────────────

function buildFallbackLesson(
  topic: string,
  slides: ExtractedSlide[],
): GeneratedLesson {
  const title = `${topic} — Imported Lesson`;
  return {
    id:   `imported-${Date.now()}`,
    slug: `${slugify(title)}-${Date.now()}`,
    title,
    topic,
    difficulty: "intermediate",
    kind:       "lesson",
    intro: slides[0]?.text ?? "Imported from presentation.",
    sections: slides.map(s => ({
      heading:     s.title || "Slide",
      content:     s.text  || "(No content)",
      codeExample: undefined,
    })),
    keyTakeaways: slides.slice(0, 5).map(s => s.title).filter(Boolean),
    quiz: [],
    references: [],
    xp: calcXp(slides.length, "intermediate"),
    estimatedMinutes: calcMinutes(slides.length),
    published_at: new Date().toISOString(),
    createdAt:    new Date().toISOString(),
    researchUsed: false,
  };
}

// ─── Prompt ──────────────────────────────────────────────────────────────────

function buildImportPrompt(topic: string, slides: ExtractedSlide[]): string {
  const slideSummary = slides
    .map((s, i) => `--- Slide ${i + 1}: "${s.title}" ---\n${s.text}`)
    .join("\n\n");

  return `You are converting a PowerPoint presentation into a structured cybersecurity lesson.

Topic: "${topic}"

Here is the extracted slide content:

${slideSummary}

---

Convert this into a professional cybersecurity lesson. Return ONLY valid JSON in this exact shape:

{
  "title": "Clear, specific lesson title (8-14 words)",
  "difficulty": "beginner" | "intermediate" | "advanced" | "expert",
  "intro": "Three paragraphs (300+ words total). Para 1: introduce the topic from scratch. Para 2: real-world relevance and stakes. Para 3: what this lesson covers.",
  "sections": [
    {
      "heading": "Section title (5-10 words)",
      "content": "Expand the slide content into 3-5 full paragraphs (400-600 words). Define every technical term. Use second-person voice. Do not invent facts not present in the slides.",
      "codeExample": "Include ONLY if the slide contained code, CLI commands, log lines, or queries. Otherwise omit this field."
    }
  ],
  "keyTakeaways": [
    "Action-verb bullet (e.g. 'Identify...' / 'Configure...' / 'Detect...')"
  ],
  "references": []
}

Rules:
- One section per original slide (merge very short slides if needed)
- Infer difficulty from the complexity and depth of the slide language
- keyTakeaways: 4-6 items starting with action verbs
- Do NOT add quiz questions
- Do NOT add technical claims not supported by the slide text
- Return ONLY the JSON object — no markdown fences, no preamble`;
}

// ─── Route ────────────────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;

  if (!process.env.OPENAI_API_KEY) {
    return Response.json({ error: "OPENAI_API_KEY not configured" }, { status: 400 });
  }

  const body = await req.json().catch(() => ({})) as Partial<ImportPptxRequest>;
  const { topic = "Imported Lesson", slides = [] } = body;

  if (!slides.length) {
    return Response.json({ error: "No slides provided" }, { status: 400 });
  }

  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  try {
    const response = await client.chat.completions.create({
      model:      "gpt-4o-mini",
      max_tokens: 6000,
      messages: [
        {
          role:    "system",
          content: "You are a professional cybersecurity curriculum designer. Convert presentation slides into structured lessons. Return only valid JSON.",
        },
        {
          role:    "user",
          content: buildImportPrompt(topic, slides.slice(0, 30)),
        },
      ],
    });

    const text    = response.choices[0]?.message?.content ?? "";
    const stripped = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");
    const jsonMatch = stripped.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("Model did not return valid JSON");

    const parsed = JSON.parse(jsonMatch[0]);
    const sectionCount = (parsed.sections ?? []).length;
    const difficulty   = parsed.difficulty ?? "intermediate";

    const lesson: GeneratedLesson = {
      id:    `imported-${Date.now()}`,
      slug:  `${slugify(parsed.title ?? topic)}-${Date.now()}`,
      title: parsed.title ?? topic,
      topic,
      difficulty,
      kind:  "lesson",
      intro: parsed.intro ?? "",
      sections: (parsed.sections ?? []).map((s: { heading: string; content: string; codeExample?: string }) => ({
        heading:     s.heading,
        content:     s.content,
        codeExample: s.codeExample || undefined,
      })),
      keyTakeaways: parsed.keyTakeaways ?? [],
      quiz:         [],
      references:   (parsed.references ?? []).filter(Boolean).slice(0, 8),
      xp:               calcXp(sectionCount, difficulty),
      estimatedMinutes: calcMinutes(sectionCount),
      published_at:     new Date().toISOString(),
      createdAt:        new Date().toISOString(),
      researchUsed:     false,
    };

    return Response.json(lesson);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[import-pptx] Failed:", message);
    return Response.json(buildFallbackLesson(topic, slides));
  }
}
