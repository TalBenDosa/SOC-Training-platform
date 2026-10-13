/**
 * Mastery per skill area: right-first-try across every graded question a student answered,
 * from rooms (task_attempts → items, lib/org/firstTry) and from quizzes, lesson knowledge
 * checks and scenario questions (graded_first_answers, 0078 — one row per question, the first
 * answer only). Isomorphic and pure; the routes load the rows.
 */
import { SKILL_AREAS, SKILL_LABEL, type SkillArea } from "@/lib/skills/taxonomy";
import { areaOf } from "@/lib/skills/contentArea";
import type { ItemResult } from "./firstTry";

export interface FirstAnswerRow { kind: "quiz" | "lesson" | "scenario"; content_id: string; question_id: string; correct: boolean }

export interface AreaStat {
  area: SkillArea;
  label: string;
  items: number;
  firstTryCorrect: number;
  accuracy: number | null;
  sources: { room: number; quiz: number; lesson: number; scenario: number };
}

/** Below this many answered questions an area is "not enough to judge". */
export const MIN_ITEMS = 5;

export function skillStats(roomItems: ItemResult[], firsts: FirstAnswerRow[]): AreaStat[] {
  const by = new Map<SkillArea, AreaStat>(SKILL_AREAS.map(a => [a.id, { area: a.id, label: a.label, items: 0, firstTryCorrect: 0, accuracy: null, sources: { room: 0, quiz: 0, lesson: 0, scenario: 0 } }]));
  const add = (area: SkillArea, ok: boolean, src: keyof AreaStat["sources"]) => {
    const s = by.get(area)!;
    s.items++; if (ok) s.firstTryCorrect++; s.sources[src]++;
  };
  for (const it of roomItems) add(areaOf("room", it.room_id), it.firstTryCorrect, "room");
  for (const f of firsts) add(areaOf(f.kind, f.content_id), f.correct, f.kind);
  return [...by.values()].map(s => ({ ...s, accuracy: s.items ? Math.round((s.firstTryCorrect / s.items) * 100) : null }));
}

/** Areas with enough answers to judge, weakest first. */
export const judged = (stats: AreaStat[]) => stats.filter(s => s.items >= MIN_ITEMS).sort((a, b) => (a.accuracy ?? 0) - (b.accuracy ?? 0));

export { SKILL_LABEL };
