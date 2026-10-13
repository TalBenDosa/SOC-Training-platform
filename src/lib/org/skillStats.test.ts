import { describe, it, expect } from "vitest";
import { groupItems } from "./firstTry";
import { skillStats, judged, MIN_ITEMS } from "./skillStats";
import { commonMistakes } from "./commonMistakes";
import type { StoredAttempt } from "./mistakeView";
import { ROOMS } from "@/data/rooms";
import { areaOf } from "@/lib/skills/contentArea";

const at = (room_id: string, task_id: string, correct: boolean, t: number, submitted: unknown = {}): StoredAttempt =>
  ({ room_id, task_id, task_type: "question", question_index: null, attempt_no: 1, correct, submitted, latency_ms: 1, created_at: new Date(Date.UTC(2026, 9, 1, 0, 0, t)).toISOString() });

describe("skill stats", () => {
  it("combines rooms with quiz, lesson and scenario first answers in the content's area", () => {
    const room = ROOMS.find(r => r.id === "encoding-encryption-hashing")!;
    const area = areaOf("room", room.id);
    const stats = skillStats(groupItems([at(room.id, "q1", true, 1), at(room.id, "q2", false, 2)]),
      [{ kind: "quiz", content_id: "mitre-attack", question_id: "1", correct: true }]);
    const a = stats.find(s => s.area === area)!;
    expect(a.items).toBe(2);
    expect(a.sources.room).toBe(2);
    const quizArea = stats.find(s => s.area === areaOf("quiz", "mitre-attack"))!;
    expect(quizArea.sources.quiz).toBe(1);
    expect(stats).toHaveLength(12);
  });

  it("only areas with enough answers are judged, weakest first", () => {
    const rows = Array.from({ length: MIN_ITEMS }, (_, i) => at("encoding-encryption-hashing", `t${i}`, i < 2, i));
    const j = judged(skillStats(groupItems(rows), []));
    expect(j).toHaveLength(1);
    expect(j[0].accuracy).toBe(40);
  });
});

describe("common mistakes", () => {
  it("ranks a question most students miss and names the wrong answer most of them chose", async () => {
    const room = ROOMS.find(r => r.id === "encoding-encryption-hashing")!;
    const task = room.tasks.find(t => t.type === "question")!;
    if (task.type !== "question") throw new Error("expected a question");
    const wrong = (task.answer + 1) % task.options.length;
    const by = new Map([
      ["a", groupItems([at(room.id, task.id, false, 1, { selectedIndex: wrong })])],
      ["b", groupItems([at(room.id, task.id, false, 2, { selectedIndex: wrong })])],
      ["c", groupItems([at(room.id, task.id, true, 3, { selectedIndex: task.answer })])],
    ]);
    const [m] = await commonMistakes(by, "org");
    expect(m).toMatchObject({ attempted: 3, wrong_first: 2, rate: 67 });
    expect(m.common_wrong?.count).toBe(2);
    expect(m.correct).toBe(task.options[task.answer].replace(/\s+/g, " ").trim().slice(0, 400));
  });
});
