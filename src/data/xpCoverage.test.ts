/**
 * XP coverage gate: every graded piece of built-in content must carry points the
 * server actually awards — no question, task or lesson may be worth 0 by mistake.
 * (Audit 2026-09-28: learners reported practising "without getting points".)
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));

import { ROOMS } from "./rooms";
import { ALL_QUIZZES } from "@/lib/quizzes/data";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { LESSON_PATHS } from "@/lib/lessons/paths";

const posInt = (n: unknown) => typeof n === "number" && Number.isInteger(n) && n > 0;
/** Task types the room grader awards XP for (src/lib/rooms/grading.ts). */
const GRADED = new Set(["question", "flag", "analyst_choice", "query_fill", "matching", "ordering", "written_report"]);
/** A room's stored xp_earned is capped at 1000 by the DB (migration 0025). */
const ROOM_CAP = 1000;

type AnyTask = { id: string; type: string; xp?: number; questions?: { xp?: number }[] };

describe("XP coverage — rooms", () => {
  const rooms = ROOMS as unknown as { id: string; tasks: AnyTask[] }[];
  it("every task type has an XP rule and every graded task/question carries positive XP", () => {
    const missing: string[] = [];
    for (const r of rooms) for (const t of r.tasks) {
      if (t.type === "reading") continue;                       // reading = xp ?? 5 (client + room_progress)
      if (t.type === "log_analysis") {
        if (!t.questions?.length) missing.push(`${r.id}:${t.id} (no questions)`);
        t.questions?.forEach((q, i) => { if (!posInt(q.xp)) missing.push(`${r.id}:${t.id}#q${i + 1}`); });
      } else if (GRADED.has(t.type)) {
        if (!posInt(t.xp)) missing.push(`${r.id}:${t.id}`);
      } else missing.push(`${r.id}:${t.id} (unknown type ${t.type})`);
    }
    expect(missing).toEqual([]);
  });
  it("no room is worth more than the per-room DB cap, and none is worth 0", () => {
    const off = rooms.map(r => ({ id: r.id, total: r.tasks.reduce((s, t) => s + (t.type === "reading" ? (t.xp ?? 5) : t.type === "log_analysis" ? (t.questions ?? []).reduce((a, q) => a + (q.xp ?? 0), 0) : (t.xp ?? 0)), 0) }))
      .filter(r => r.total <= 0 || r.total > ROOM_CAP);
    expect(off).toEqual([]);
  });
});

describe("XP coverage — quizzes, scenarios, lessons", () => {
  it("every quiz question carries positive XP", () => {
    const missing = (ALL_QUIZZES as unknown as { slug: string; questions: { xp?: number }[] }[])
      .flatMap(q => (q.questions.length ? q.questions : [{ xp: 0 }]).map((qq, i) => (posInt(qq.xp) ? null : `${q.slug}#q${i + 1}`))).filter(Boolean);
    expect(missing).toEqual([]);
  });
  it("every scenario builds and every scenario question carries positive XP", () => {
    const missing: string[] = [];
    for (const s of SCENARIOS as unknown as { slug: string; build?: () => { questions?: { xp?: number }[] }; questions?: { xp?: number }[] }[]) {
      const full = typeof s.build === "function" ? s.build() : s;
      const qs = full.questions ?? [];
      if (!qs.length) missing.push(`${s.slug} (no questions)`);
      qs.forEach((q, i) => { if (!posInt(q.xp)) missing.push(`${s.slug}#q${i + 1}`); });
    }
    expect(missing).toEqual([]);
  });
  it("every Learning Path lesson carries positive XP within the complete_lesson cap", () => {
    const off = (LESSON_PATHS as unknown as { slug: string; modules: { lessons: { slug: string; xp?: number }[] }[] }[])
      .flatMap(p => p.modules.flatMap(m => m.lessons.map(l => ({ key: `${p.slug}--${l.slug}`, xp: l.xp }))))
      .filter(l => !posInt(l.xp) || (l.xp as number) > 1000);
    expect(off).toEqual([]);
  });
});
