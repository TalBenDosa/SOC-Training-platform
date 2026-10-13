import { describe, it, expect } from "vitest";
import { groupItems, summarize } from "./firstTry";
import { describe as describeMistake, type StoredAttempt } from "./mistakeView";
import { ROOMS } from "@/data/rooms";

const at = (o: Partial<StoredAttempt> & { t: number }): StoredAttempt => ({
  room_id: "r1", task_id: "t1", task_type: "question", question_index: null, attempt_no: 1, correct: false,
  created_at: new Date(Date.UTC(2026, 9, 1, 10, 0, o.t)).toISOString(), submitted: {}, latency_ms: 1000, ...o,
});

describe("first-try accuracy", () => {
  it("one item per question: wrong then right is a first-try miss that was solved on try 2", () => {
    const items = groupItems([at({ t: 2, correct: true, attempt_no: 2 }), at({ t: 1, correct: false })]);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({ firstTryCorrect: false, solved: true, triesToSolve: 2 });
  });

  it("readings are ungraded and never count; retries don't inflate the item count", () => {
    const s = summarize(groupItems([
      at({ t: 1, task_id: "read", task_type: "reading" }),
      at({ t: 2, task_id: "q1", correct: true }),
      at({ t: 3, task_id: "flag", task_type: "flag" }), at({ t: 4, task_id: "flag", task_type: "flag" }), at({ t: 5, task_id: "flag", task_type: "flag", correct: true }),
    ]));
    expect(s).toEqual({ items: 2, firstTryCorrect: 1, accuracy: 50, unsolved: 0 });
  });

  it("each question of a multi-question log task is its own item", () => {
    const s = summarize(groupItems([
      at({ t: 1, task_type: "log_analysis", question_index: 0, correct: true }),
      at({ t: 2, task_type: "log_analysis", question_index: 1, correct: false }),
    ]));
    expect(s.items).toBe(2);
    expect(s.accuracy).toBe(50);
    expect(s.unsolved).toBe(1);
  });

  it("nothing graded → accuracy is null, not 0", () => {
    expect(summarize(groupItems([at({ t: 1, task_type: "reading" })])).accuracy).toBeNull();
  });
});

describe("a readable mistake", () => {
  const room = ROOMS.find(r => r.id === "encoding-encryption-hashing")!;
  it("an analyst verdict shows the question, the verdict chosen, the right verdict and the explanation", () => {
    const task = room.tasks.find(t => t.id === "enc-ac1")!;
    const [item] = groupItems([at({ t: 1, room_id: room.id, task_id: "enc-ac1", task_type: "analyst_choice", submitted: { verdict: "true_positive" } })]);
    const m = describeMistake(task, item);
    expect(m.prompt).toContain("Scheduled Task");
    expect(m.chosen).toBe("True positive");
    expect(m.correct).toBe("False positive");
    expect(m.explanation).toMatch(/Decode it first/);
  });

  it("a multiple-choice question maps the chosen and correct indexes to their option text", () => {
    const task = room.tasks.find(t => t.type === "question")!;
    if (task.type !== "question") throw new Error("expected a question task");
    const wrong = (task.answer + 1) % task.options.length;
    const [item] = groupItems([at({ t: 1, room_id: room.id, task_id: task.id, submitted: { selectedIndex: wrong } })]);
    const m = describeMistake(task, item);
    expect(m.chosen).toBe(task.options[wrong].replace(/\s+/g, " ").trim().slice(0, 400));
    expect(m.correct).toBe(task.options[task.answer].replace(/\s+/g, " ").trim().slice(0, 400));
  });
});
