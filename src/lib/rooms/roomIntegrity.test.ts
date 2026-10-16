// Every room, guarded against the issues learners reported in Oct 2026:
//  - "There's two similar answers": options that differ only by letter case,
//    spacing or punctuation (sentinel-q1 had "where" vs "Where").
//  - "It won't let me pass even when I answer everything right": every room must be
//    passable once the learner corrects the auto-graded tasks in a review
//    (the gate counts mastery, src/lib/rooms/mastery.ts).
//  - A matching task whose right side repeats an answer must show it once.
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));
const { ROOMS } = await import("@/data/rooms");
const { gradeTask } = await import("./grading");
const { taskMaxXp, ROOM_PASS_THRESHOLD } = await import("./xp");
const { roomPassScore } = await import("./mastery");
const { sanitizeRoom } = await import("./sanitize");

const norm = (s: string) => s.toLowerCase().replace(/[\s"'`.,;:()[\]{}|]+/g, " ").trim();

describe("room options are distinguishable", () => {
  it("no two options of a question differ only by case, spacing or punctuation", () => {
    const bad: string[] = [];
    const check = (where: string, options: string[]) => {
      const seen = new Map<string, number>();
      options.forEach((o, i) => {
        const k = norm(o);
        if (seen.has(k)) bad.push(`${where}: [${seen.get(k)}] vs [${i}] "${o}"`);
        seen.set(k, i);
      });
    };
    for (const r of ROOMS) for (const t of r.tasks) {
      if (t.type === "question") check(`${r.id}/${t.id}`, t.options);
      if (t.type === "log_analysis") t.questions.forEach((q, qi) => check(`${r.id}/${t.id} Q${qi + 1}`, q.options));
    }
    expect(bad).toEqual([]);
  });

  it("a matching task lists each right-side answer once", () => {
    for (const r of ROOMS) for (const t of r.tasks) {
      if (t.type !== "matching") continue;
      const safe = sanitizeRoom(r).tasks.find(x => x.id === t.id) as unknown as { right: string[] };
      expect(new Set(safe.right).size, `${r.id}/${t.id}`).toBe(safe.right.length);
      expect(new Set(safe.right), `${r.id}/${t.id}`).toEqual(new Set(t.pairs.map(p => p.right)));
    }
  });
});

describe("every room can be passed", () => {
  it("each answer key is graded correct, and correcting every auto-graded task reaches the gate", () => {
    const issues: string[] = [];
    for (const room of ROOMS) {
      const attempts: { task_id: string; question_index: number | null; correct: boolean; xp_awarded: number }[] = [];
      for (const t of room.tasks) {
        if (taskMaxXp(t) <= 0 || t.type === "written_report") continue;   // reports: rubric-graded, counted as never correct
        if (t.type === "log_analysis") {
          t.questions.forEach((q, qi) => {
            const g = gradeTask(t, { questionIndex: qi, selectedIndex: q.answer }, room);
            if (!g.ok || !g.correct) issues.push(`${room.id}/${t.id} Q${qi + 1}: key not accepted`);
            attempts.push({ task_id: t.id, question_index: qi, correct: true, xp_awarded: 0 });
          });
          continue;
        }
        const sub =
          t.type === "question" ? { selectedIndex: t.answer } :
          t.type === "flag" ? { value: t.answer } :
          t.type === "analyst_choice" ? { verdict: t.correct_verdict } :
          t.type === "matching" ? { connections: Object.fromEntries(t.pairs.map(p => [p.id, p.right])) } :
          t.type === "ordering" ? { placed: t.correct_order } :
          t.type === "query_fill" ? { values: Object.fromEntries(t.blanks.map(b => [b.id, b.answers[0]])) } : null;
        if (!sub) { issues.push(`${room.id}/${t.id}: unhandled type ${t.type}`); continue; }
        const g = gradeTask(t, sub, room);
        if (!g.ok || !g.correct) issues.push(`${room.id}/${t.id}: key not accepted`);
        attempts.push({ task_id: t.id, question_index: null, correct: true, xp_awarded: 0 });
      }
      const { score, max } = roomPassScore(room, attempts);
      if (max > 0 && score / max < ROOM_PASS_THRESHOLD) issues.push(`${room.id}: only ${Math.round((score / max) * 100)}% reachable by review`);
    }
    expect(issues).toEqual([]);
  });
});
