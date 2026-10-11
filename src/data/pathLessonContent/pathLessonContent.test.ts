/**
 * Quality gate for hand-written Learning Path lessons (customer report
 * 2026-09-28: lessons showed AI stub filler + a developer note). Every
 * authored lesson must be complete, gradeable and free of placeholder text.
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { PATH_LESSON_CONTENT } from "./index";
import { LESSON_PATHS } from "@/lib/lessons/paths";

const pathKeys = (LESSON_PATHS as unknown as { slug: string; modules: { lessons: { slug: string }[] }[] }[])
  .flatMap(p => p.modules.flatMap(m => m.lessons.map(l => `${p.slug}--${l.slug}`)));

const PLACEHOLDER = /stub content|\.env(\.local)?\b|ANTHROPIC_API_KEY|OPENAI_API_KEY|lorem ipsum|\bTODO\b|\bTBD\b|Core concept \d|placeholder/i;
const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

describe("authored Learning Path lessons", () => {
  const entries = Object.entries(PATH_LESSON_CONTENT);

  it("covers EVERY Learning Path lesson (none may fall back to 'in preparation')", () => {
    expect(pathKeys.filter(k => !(k in PATH_LESSON_CONTENT))).toEqual([]);
  });

  it("only uses keys that exist in the Learning Path catalog", () => {
    expect(entries.map(([k]) => k).filter(k => !pathKeys.includes(k))).toEqual([]);
  });

  it.each(entries)("%s is complete and gradeable", (_key, lesson) => {
    expect(lesson.pages.length).toBeGreaterThanOrEqual(6);
    lesson.pages.forEach((p, i) => {
      expect(p.pageNumber).toBe(i + 1);
      expect(p.title.trim().length).toBeGreaterThan(3);
      expect(words(p.body)).toBeGreaterThanOrEqual(150);
      expect(p.keyPoints.length).toBeGreaterThanOrEqual(2);
      expect(PLACEHOLDER.test(`${p.title}\n${p.body}\n${p.codeExample ?? ""}\n${p.keyPoints.join("\n")}`)).toBe(false);
    });
    expect(lesson.quiz.length).toBeGreaterThanOrEqual(4);
    lesson.quiz.forEach(q => {
      const values = q.options.map(o => o.value);
      expect(q.options.length).toBeGreaterThanOrEqual(3);
      expect(new Set(values).size).toBe(values.length);
      expect(values).toContain(q.answer);
      expect(q.explanation.trim().length).toBeGreaterThan(20);
      expect(PLACEHOLDER.test(`${q.question}\n${q.explanation}\n${q.options.map(o => o.label).join("\n")}`)).toBe(false);
    });
  });
});
