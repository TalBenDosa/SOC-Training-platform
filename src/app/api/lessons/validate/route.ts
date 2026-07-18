/**
 * POST /api/lessons/validate
 * ─────────────────────────
 * Validation agent — reviews a generated lesson and returns a quality report.
 *
 * Request body: { lesson: SyllabusLesson }
 *
 * Response:
 *   { score: number; recommendation: "publish" | "review" | "regenerate"; issues: string[]; strengths: string[] }
 */

export const dynamic = "force-dynamic";

import OpenAI from "openai";

const MODEL = "gpt-4o-mini";

function getClient() {
  return new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function withRetry<T>(
  fn: () => Promise<T>,
  maxRetries = 3,
  baseDelay = 6000,
): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try { return await fn(); } catch (err) {
      lastErr = err;
      const msg = err instanceof Error ? err.message : String(err);
      const isRateLimit = msg.includes("429") || msg.includes("quota") || msg.includes("rate");
      if (!isRateLimit || attempt === maxRetries) throw err;
      const delay = baseDelay * Math.pow(1.8, attempt);
      await sleep(delay);
    }
  }
  throw lastErr;
}

function parseJson<T>(text: string, fallback: T): T {
  try {
    const stripped = text.replace(/^```(?:json)?\s*/i, "").replace(/\s*```\s*$/, "");
    const m = stripped.match(/\{[\s\S]*\}/);
    if (!m) return fallback;
    return JSON.parse(m[0]) as T;
  } catch {
    return fallback;
  }
}

interface ValidationResult {
  score: number;
  recommendation: "publish" | "review" | "regenerate";
  issues: string[];
  strengths: string[];
}

interface LessonInput {
  title?: string;
  topic?: string;
  difficulty?: string;
  intro?: string;
  sections?: { heading: string; content: string; codeExample?: string }[];
  keyTakeaways?: string[];
}

export async function POST(req: Request) {
  if (!process.env.OPENAI_API_KEY) {
    return Response.json(
      { error: "OPENAI_API_KEY not configured" },
      { status: 500 }
    );
  }

  let body: { lesson?: LessonInput };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const lesson = body?.lesson;
  if (!lesson) {
    return Response.json({ error: "Missing lesson in request body" }, { status: 400 });
  }

  // Build a compact lesson summary for the validator
  const sectionSummary = (lesson.sections ?? []).map((s, i) =>
    `Section ${i + 1}: "${s.heading}" (${s.content?.length ?? 0} chars${s.codeExample ? ", has code example" : ""})`
  ).join("\n");

  const totalWords = (lesson.sections ?? []).reduce((acc, s) => {
    return acc + (s.content ?? "").split(/\s+/).filter(Boolean).length;
  }, 0);

  const prompt = `You are a senior SOC curriculum quality reviewer at a professional cybersecurity training company (think SANS Institute level).

Your job is to score the following lesson and return a structured quality report.

LESSON METADATA:
- Title: ${lesson.title ?? "(no title)"}
- Topic: ${lesson.topic ?? "(no topic)"}
- Difficulty: ${lesson.difficulty ?? "(unknown)"}
- Total word count across all sections: ~${totalWords} words
- Number of sections: ${(lesson.sections ?? []).length}

SECTION OUTLINE:
${sectionSummary || "(no sections)"}

INTRO PREVIEW (first 400 chars):
${(lesson.intro ?? "").slice(0, 400)}

FIRST SECTION PREVIEW:
Title: ${lesson.sections?.[0]?.heading ?? "(none)"}
Content (first 600 chars): ${(lesson.sections?.[0]?.content ?? "").slice(0, 600)}
Code example: ${lesson.sections?.[0]?.codeExample ? "Present ✓" : "Missing ✗"}

KEY TAKEAWAYS:
${(lesson.keyTakeaways ?? []).map((t, i) => `${i + 1}. ${t}`).join("\n") || "(none)"}

SCORING CRITERIA (evaluate each on a 1–10 scale, then compute overall):
1. Topic relevance — does the content clearly match the stated topic and difficulty?
2. Section depth — are sections substantive? (Target: 500+ words per section for beginner, 700+ for intermediate/advanced)
3. SOC analyst applicability — practical, real-world focus with actionable detection/response guidance?
4. Technical accuracy — real MITRE ATT&CK IDs, real tool names, realistic log fields?
5. Teaching quality — does it explain WHY, not just WHAT? Does it define terms? Use analogies?

SCORING THRESHOLDS:
- 8–10 → "publish" (high quality, ready for students)
- 5–7  → "review"  (usable but has gaps — human review recommended)
- 1–4  → "regenerate" (significant problems — should be regenerated)

Return ONLY this exact JSON (no markdown, no extra keys):
{
  "score": <integer 1-10>,
  "recommendation": "<publish|review|regenerate>",
  "issues": [
    "<specific problem found, e.g. 'Section 3 is only 150 words — too thin for intermediate level'>",
    "<another specific issue if any>"
  ],
  "strengths": [
    "<specific strength, e.g. 'Excellent MITRE ATT&CK T1558.003 reference in section 2'>",
    "<another strength>"
  ]
}

If the lesson is excellent, issues can be an empty array.
List 2–4 items in each array. Be specific and actionable.`;

  try {
    const client = getClient();

    const res = await withRetry(() => client.chat.completions.create({
      model: MODEL,
      max_tokens: 1000,
      temperature: 0.3,
      messages: [
        {
          role: "system",
          content: "You are a strict but fair curriculum quality reviewer. Return only valid JSON.",
        },
        { role: "user", content: prompt },
      ],
    }));

    const text = res.choices[0]?.message?.content ?? "";
    const parsed = parseJson<Partial<ValidationResult>>(text, {});

    const score = Math.min(10, Math.max(1, Math.round(parsed.score ?? 5)));
    const recommendation: ValidationResult["recommendation"] =
      score >= 8 ? "publish" :
      score >= 5 ? "review"  :
      "regenerate";

    const result: ValidationResult = {
      score,
      recommendation: parsed.recommendation ?? recommendation,
      issues:    Array.isArray(parsed.issues)    ? parsed.issues.slice(0, 5)    : [],
      strengths: Array.isArray(parsed.strengths) ? parsed.strengths.slice(0, 5) : [],
    };

    return Response.json(result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[validate] OpenAI error:", msg);
    return Response.json({ error: msg }, { status: 500 });
  }
}
