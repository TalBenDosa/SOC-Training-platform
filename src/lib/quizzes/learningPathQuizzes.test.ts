/**
 * Alignment gate for the Learning Path module quizzes on the Quizzes page (Tal, 2026-10-14:
 * "every question must match the taught material, every answer must fit its question").
 *
 * Each question was written from one page of its module's lessons; the citation (lesson key,
 * page, verbatim quote) lives in learningPathSources.json. This test re-proves it on every
 * change: if a lesson page is edited so a quote no longer appears, the question that depends
 * on it fails here and must be re-checked.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { QUIZZES_LEARNING_PATH } from "./data-learning-path";
import { ALL_QUIZZES } from "./data";
import { PATH_LESSON_CONTENT } from "@/data/pathLessonContent";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import SOURCES from "./learningPathSources.json";

type Mod = { slug: string; lessons: { slug: string; kind: string }[] };
const paths = LESSON_PATHS as unknown as { slug: string; modules: Mod[] }[];
const norm = (s: string) => s.replace(/[*_`#]/g, "").replace(/\s+/g, " ").trim().toLowerCase();
const sources = SOURCES as Record<string, { id: string; lesson: string; page: number; quote: string }[]>;

describe("Learning Path module quizzes (Quizzes page)", () => {
  it("one quiz per module that has no in-path quiz, all listed on the Quizzes page", () => {
    const expected = paths.flatMap(p => p.modules.filter(m => !m.lessons.some(l => l.kind === "quiz")).map(m => `lp-${m.slug}`));
    expect(QUIZZES_LEARNING_PATH.map(q => q.slug).sort()).toEqual(expected.sort());
    for (const q of QUIZZES_LEARNING_PATH) expect(ALL_QUIZZES).toContain(q);
  });

  it.each(QUIZZES_LEARNING_PATH.map(q => [q.slug, q] as const))("%s: every question is backed by a verbatim quote from its module", (slug, quiz) => {
    const moduleSlug = slug.replace(/^lp-/, "");
    const p = paths.find(x => x.modules.some(m => m.slug === moduleSlug))!;
    const own = new Set(p.modules.find(m => m.slug === moduleSlug)!.lessons.map(l => `${p.slug}--${l.slug}`));
    const srcs = sources[slug];
    expect(srcs.map(s => s.id)).toEqual(quiz.questions.map(q => q.id));
    for (const s of srcs) {
      expect(own.has(s.lesson), `${s.id} cites ${s.lesson}, outside the module`).toBe(true);
      const page = PATH_LESSON_CONTENT[s.lesson]?.pages.find(pg => pg.pageNumber === s.page);
      const hay = norm(`${page?.body ?? ""} ${(page?.keyPoints ?? []).join(" ")} ${page?.codeExample ?? ""}`);
      expect(hay.includes(norm(s.quote)), `${s.id}: quote no longer on ${s.lesson} p${s.page}`).toBe(true);
    }
  });

  it.each(QUIZZES_LEARNING_PATH.map(q => [q.slug, q] as const))("%s: well-formed multiple choice", (_slug, quiz) => {
    expect(quiz.questions.length).toBe(10);
    const pos: Record<number, number> = {};
    for (const q of quiz.questions) {
      expect(q.options.length).toBe(4);
      expect(new Set(q.options).size).toBe(4);
      expect(q.answer).toBeGreaterThanOrEqual(0);
      expect(q.answer).toBeLessThan(4);
      expect([10, 15, 20]).toContain(q.xp);
      pos[q.answer] = (pos[q.answer] ?? 0) + 1;
      // Explanations name options by content: no "Option 2" (number) references.
      expect(/\b[Oo]ptions? [1-4]\b/.test(q.explanation), q.id).toBe(false);
      expect(/—/.test(JSON.stringify(q)), q.id).toBe(false);
    }
    expect(Math.max(...Object.values(pos))).toBeLessThanOrEqual(4);
  });
});
