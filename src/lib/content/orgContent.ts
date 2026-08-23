import "server-only";
import { randomUUID } from "crypto";

/**
 * Server-side validation + normalization for per-org, manually-authored content
 * (Phase 2 — migration 0040). This is the ONLY producer of the `content` jsonb
 * and the row id that go into content_lessons / content_quizzes for an org, so
 * it is where every safety invariant is enforced:
 *
 *  1. Ids are namespaced `org-<org8>-…` and stamped into BOTH the DB primary key
 *     and the inner content id/slug. A global built-in id is a plain word or a
 *     bare uuid — it never starts with "org-", so an org row can never collide
 *     with, overwrite, or shadow a built-in (the /learn dedupe is by inner id).
 *  2. New items always get a random suffix, so authoring two items with the same
 *     title never silently overwrites the first.
 *  3. Output is an allowlist rebuild, not a spread of the client body — a field
 *     the client invents cannot ride along into the stored content.
 *
 * These editors are manual-only; there is deliberately no AI generation here
 * (the super-admin keeps global AI authoring in /admin).
 */

export type OrgContentType = "lessons" | "quizzes" | "scenarios";
export const ORG_CONTENT_TABLE: Record<OrgContentType, string> = {
  lessons: "content_lessons",
  quizzes: "content_quizzes",
  scenarios: "content_scenarios",
};
export function isOrgContentType(t: string): t is OrgContentType {
  return t === "lessons" || t === "quizzes" || t === "scenarios";
}

export type NormalizeResult =
  | { ok: true; id: string; content: Record<string, unknown> }
  | { ok: false; error: string };

// ── id helpers ───────────────────────────────────────────────────────────────
function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "untitled";
}
/** Namespaced, URL-safe, collision-proof id for a NEW item. */
function newId(orgId: string, title: string): string {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  const rand = randomUUID().slice(0, 4);
  return `org-${ns}-${slugify(title)}-${rand}`;
}
/** True iff `id` is a well-formed org-namespaced id for THIS org. */
export function isOrgIdFor(id: string, orgId: string): boolean {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return typeof id === "string" && id.startsWith(`org-${ns}-`);
}

// ── small field coercers ─────────────────────────────────────────────────────
const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const strArr = (v: unknown, max: number, cap = 30) =>
  Array.isArray(v) ? v.map(x => str(x, max)).filter(Boolean).slice(0, cap) : [];
const num = (v: unknown, def: number, min: number, maxV: number) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? Math.min(maxV, Math.max(min, Math.round(n))) : def;
};

const LESSON_DIFFS = ["beginner", "intermediate", "advanced", "expert"];
const QUIZ_DIFFS = ["Beginner", "Intermediate", "Advanced"];

/**
 * Resolve the row id: reuse an existing org id when editing, mint a fresh
 * namespaced one when creating. `existingId` is trusted only after the caller
 * has confirmed the row belongs to this org.
 */
function resolveId(orgId: string, title: string, existingId?: string): string {
  if (existingId && isOrgIdFor(existingId, orgId)) return existingId;
  return newId(orgId, title);
}

// ── Lessons ──────────────────────────────────────────────────────────────────
function normalizeLesson(orgId: string, body: Record<string, unknown>): NormalizeResult {
  const title = str(body.title, 160);
  if (!title) return { ok: false, error: "Give the lesson a title." };
  const intro = str(body.intro, 4000);
  if (!intro) return { ok: false, error: "Write a short intro for the lesson." };

  const rawSections = Array.isArray(body.sections) ? body.sections : [];
  const sections = rawSections
    .map(s => {
      const o = (s ?? {}) as Record<string, unknown>;
      const heading = str(o.heading, 160);
      const content = str(o.content, 8000);
      const codeExample = str(o.codeExample, 4000);
      if (!heading || !content) return null;
      return codeExample ? { heading, content, codeExample } : { heading, content };
    })
    .filter(Boolean)
    .slice(0, 30);
  if (sections.length === 0) return { ok: false, error: "Add at least one section (heading + content)." };

  const rawQuiz = Array.isArray(body.quiz) ? body.quiz : [];
  const quiz = rawQuiz
    .map(q => {
      const o = (q ?? {}) as Record<string, unknown>;
      const question = str(o.question, 500);
      const opts = strArr(o.options, 300, 6).map(v => ({ label: v, value: v }));
      const answer = str(o.answer, 300);
      const explanation = str(o.explanation, 1000);
      if (!question || opts.length < 2) return null;
      // answer must be one of the option values; default to the first option.
      const ans = opts.some(op => op.value === answer) ? answer : opts[0].value;
      return { question, options: opts, answer: ans, explanation };
    })
    .filter(Boolean)
    .slice(0, 20);

  const difficulty = LESSON_DIFFS.includes(str(body.difficulty, 20)) ? str(body.difficulty, 20) : "beginner";
  const id = resolveId(orgId, title, str(body.id, 120) || undefined);

  return {
    ok: true,
    id,
    content: {
      id,
      slug: id,
      kind: "lesson",
      title,
      topic: str(body.topic, 80) || "General",
      difficulty,
      intro,
      sections,
      keyTakeaways: strArr(body.keyTakeaways, 300),
      quiz,
      references: strArr(body.references, 300),
      xp: num(body.xp, 50, 0, 1000),
      estimatedMinutes: num(body.estimatedMinutes, 10, 1, 240),
      createdAt: new Date().toISOString(),
    },
  };
}

// ── Quizzes ──────────────────────────────────────────────────────────────────
function normalizeQuiz(orgId: string, body: Record<string, unknown>): NormalizeResult {
  const title = str(body.title, 160);
  if (!title) return { ok: false, error: "Give the quiz a title." };

  const rawQs = Array.isArray(body.questions) ? body.questions : [];
  const id = resolveId(orgId, title, str(body.id, 120) || undefined);
  const questions = rawQs
    .map((q, i) => {
      const o = (q ?? {}) as Record<string, unknown>;
      const question = str(o.question, 600);
      const options = strArr(o.options, 400, 6);
      if (!question || options.length < 2) return null;
      const answer = num(o.answer, 0, 0, options.length - 1);
      return {
        id: `${id}-q${i + 1}`,
        question,
        options,
        answer,
        explanation: str(o.explanation, 1500),
        xp: num(o.xp, 10, 0, 200),
      };
    })
    .filter(Boolean)
    .slice(0, 50);
  if (questions.length === 0) {
    return { ok: false, error: "Add at least one question with two or more options." };
  }

  const difficulty = QUIZ_DIFFS.includes(str(body.difficulty, 20)) ? str(body.difficulty, 20) : "Beginner";

  return {
    ok: true,
    id,
    content: {
      slug: id,
      title,
      description: str(body.description, 300),
      difficulty,
      category: str(body.category, 60) || "General",
      icon: str(body.icon, 8) || "📝",
      estimatedMinutes: num(body.estimatedMinutes, Math.max(3, questions.length), 1, 180),
      questions,
    },
  };
}

/**
 * Validate + normalize a manual authoring payload for `type` into the stored
 * `content` jsonb and its row id. Scenarios are intentionally not authorable
 * this way yet — their safe path needs a server-side grading resolver (Phase 3).
 */
export function normalizeOrgContent(
  type: OrgContentType,
  orgId: string,
  body: Record<string, unknown>,
): NormalizeResult {
  if (type === "lessons") return normalizeLesson(orgId, body);
  if (type === "quizzes") return normalizeQuiz(orgId, body);
  return { ok: false, error: "Scenario authoring is not available yet." };
}
