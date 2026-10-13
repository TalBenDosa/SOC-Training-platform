/**
 * Which skill area (lib/skills/taxonomy) each built-in content item belongs to, and its
 * display title. Built from the answer-free meta files only, so it is client-safe.
 * Unknown ids (org-authored content) fall back to a per-kind default rather than vanishing.
 */
import { ROOMS_META } from "@/data/roomsMeta";
import { QUIZZES_META, SCENARIOS_META } from "@/data/catalogMeta";
import { findLesson } from "@/lib/lessons/paths";
import { areaFor, areaForLesson, type SkillArea } from "./taxonomy";

export type ContentKind = "room" | "quiz" | "lesson" | "scenario";

const ROOM_AREA = new Map<string, SkillArea>(ROOMS_META.map(r => [r.id, areaFor({ title: r.title, category: r.category })]));
const QUIZ_AREA = new Map<string, SkillArea>(QUIZZES_META.map(q => [q.slug, areaFor({ title: q.title, category: q.category })]));
const SCENARIO_AREA = new Map<string, SkillArea>(SCENARIOS_META.map(s => [s.slug, areaFor({ title: s.title }, "detection")]));

export function areaOf(kind: ContentKind, id: string): SkillArea {
  switch (kind) {
    case "room": return ROOM_AREA.get(id) ?? "soc_fundamentals";
    case "quiz": return QUIZ_AREA.get(id) ?? "soc_fundamentals";
    case "scenario": return SCENARIO_AREA.get(id) ?? "detection";
    case "lesson": {
      const sep = id.indexOf("--");
      const found = sep > 0 ? findLesson(id.slice(0, sep), id.slice(sep + 2)) : null;
      return found ? areaForLesson(found.path.slug, found.module.title, found.lesson.title) : "soc_fundamentals";
    }
  }
}

/** Every built-in room per area, for recommendations ("not done yet, in your weakest area"). */
export function roomsInArea(area: SkillArea): { id: string; title: string; difficulty: string }[] {
  return ROOMS_META.filter(r => ROOM_AREA.get(r.id) === area).map(r => ({ id: r.id, title: r.title, difficulty: r.difficulty }));
}

export const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS_META.map(r => [r.id, r.title]));
export const QUIZ_TITLE: Record<string, string> = Object.fromEntries(QUIZZES_META.map(q => [q.slug, q.title]));
export const SCENARIO_TITLE: Record<string, string> = Object.fromEntries(SCENARIOS_META.map(s => [s.slug, s.title]));
