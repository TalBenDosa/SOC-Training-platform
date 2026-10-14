/**
 * Alignment gate for the end-of-module Learning Path quizzes (Tal, 2026-10-14: "every
 * question must match the taught material, every answer must fit its question").
 *
 * Each module-quiz question was written from one page of its own module's lessons; the
 * citation (lesson key, page, verbatim quote) is kept in __alignment__/module-quiz-sources.json.
 * This test re-proves it on every change: if a lesson page is edited so the quote no longer
 * appears, the quiz question that depends on it fails here and must be re-checked.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { PATH_LESSON_CONTENT } from "./index";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import SOURCES from "./__alignment__/module-quiz-sources.json";

type Mod = { slug: string; lessons: { slug: string; kind: string }[] };
const paths = LESSON_PATHS as unknown as { slug: string; modules: Mod[] }[];
const norm = (s: string) => s.replace(/[*_`#]/g, "").replace(/\s+/g, " ").trim().toLowerCase();
const sources = SOURCES as Record<string, { question: string; lesson: string; page: number; quote: string }[]>;

describe("Learning Path module quizzes", () => {
  it("every module ends with exactly one quiz that has content", () => {
    const missing: string[] = [];
    for (const p of paths) for (const m of p.modules) {
      const quizzes = m.lessons.filter(l => l.kind === "quiz");
      if (quizzes.length !== 1 || m.lessons[m.lessons.length - 1].kind !== "quiz") missing.push(`${p.slug}/${m.slug}`);
      for (const q of quizzes) if (!PATH_LESSON_CONTENT[`${p.slug}--${q.slug}`]) missing.push(`${p.slug}--${q.slug} (no content)`);
    }
    expect(missing).toEqual([]);
  });

  const cited = Object.entries(sources);
  it("has citations for every new module quiz", () => {
    expect(cited.length).toBe(15);
  });

  it.each(cited)("%s: every question is backed by a verbatim quote from its own module", (key, srcs) => {
    const [pathSlug, quizSlug] = key.split("--");
    const mod = paths.find(p => p.slug === pathSlug)!.modules.find(m => m.lessons.some(l => l.slug === quizSlug))!;
    const own = new Set(mod.lessons.filter(l => l.kind !== "quiz").map(l => `${pathSlug}--${l.slug}`));
    const quiz = PATH_LESSON_CONTENT[key].quiz;
    expect(srcs.length).toBe(quiz.length);
    srcs.forEach((s, i) => {
      expect(quiz[i].question.startsWith(s.question), `${key} Q${i + 1} citation out of order`).toBe(true);
      expect(own.has(s.lesson), `${key} Q${i + 1} cites ${s.lesson}, outside the module`).toBe(true);
      const page = PATH_LESSON_CONTENT[s.lesson].pages.find(p => p.pageNumber === s.page);
      const hay = norm(`${page?.body ?? ""} ${(page?.keyPoints ?? []).join(" ")} ${page?.codeExample ?? ""}`);
      expect(hay.includes(norm(s.quote)), `${key} Q${i + 1}: quote no longer on ${s.lesson} p${s.page}`).toBe(true);
    });
  });

  it.each(cited)("%s: well-formed multiple choice", (key) => {
    const quiz = PATH_LESSON_CONTENT[key].quiz;
    expect(quiz.length).toBe(10);
    const dist: Record<string, number> = {};
    for (const q of quiz) {
      expect(q.options.map(o => o.value)).toEqual(["a", "b", "c", "d"]);
      dist[q.answer] = (dist[q.answer] ?? 0) + 1;
      // Options render shuffled and without letters, so an explanation must name options by content.
      expect(/\b[Oo]ptions? [a-dA-D1-4]\b|\([a-d]\)|\b[Cc]hoices? [a-d]\b/.test(q.explanation), q.question).toBe(false);
      expect(/—/.test(JSON.stringify(q)), q.question).toBe(false);
    }
    expect(Math.max(...Object.values(dist))).toBeLessThanOrEqual(4);
  });
});
