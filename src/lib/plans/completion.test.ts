import { describe, it, expect } from "vitest";
import { buildProgressIndex, countDone, isComplete, isOverdue, isTrackedItem, itemStatus, planMatrix } from "./completion";
import type { PlanItem } from "./types";

const A = "user-a", B = "user-b";

const idx = buildProgressIndex({
  rooms: [
    { user_id: A, room_id: "intro", completed_at: "2026-01-01T00:00:00Z" },
    { user_id: A, room_id: "siem-101", completed_at: null },
    { user_id: B, room_id: "intro", completed_at: null },
  ],
  scenarios: [{ user_id: A, slug: "phish" }, { user_id: A, slug: "phish" }],
  quizzes: [
    { user_id: A, quiz_slug: "mitre-attack", passed: true },
    { user_id: B, quiz_slug: "mitre-attack", passed: false },
  ],
  lessons: [
    { user_id: A, lesson_key: "soc-analyst--what-is-a-soc", completed_at: "2026-01-02T00:00:00Z" },
    { user_id: B, lesson_key: "soc-analyst--what-is-a-soc", completed_at: null, quiz_passed_at: "2026-01-02T00:00:00Z" },
  ],
});

const ITEMS: PlanItem[] = [
  { kind: "room", id: "intro" },
  { kind: "room", id: "siem-101" },
  { kind: "scenario", id: "phish" },
  { kind: "quiz", id: "mitre-attack" },
  { kind: "lesson", id: "soc-analyst--what-is-a-soc" },
];

describe("itemStatus", () => {
  it("derives done / in progress / not started per kind", () => {
    expect(ITEMS.map(i => itemStatus(idx, A, i))).toEqual(["done", "in_progress", "done", "done", "done"]);
    expect(ITEMS.map(i => itemStatus(idx, B, i))).toEqual(["in_progress", "not_started", "not_started", "in_progress", "in_progress"]);
  });

  it("an unknown user has nothing started", () => {
    expect(itemStatus(idx, "nobody", ITEMS[0])).toBe("not_started");
  });

  it("org-authored library lessons are untracked (no completion record exists)", () => {
    expect(isTrackedItem({ kind: "lesson", id: "org-abcd1234-my-lesson-x1y2" })).toBe(false);
    expect(isTrackedItem({ kind: "room", id: "org-abcd1234-my-room-x1y2" })).toBe(true);
    expect(itemStatus(idx, A, { kind: "lesson", id: "org-abcd1234-my-lesson-x1y2" })).toBe("untracked");
  });

  it("done wins over in progress regardless of row order", () => {
    const i2 = buildProgressIndex({
      rooms: [
        { user_id: A, room_id: "r", completed_at: "2026-01-01T00:00:00Z" },
        { user_id: A, room_id: "r", completed_at: null },
      ],
    });
    expect(itemStatus(i2, A, { kind: "room", id: "r" })).toBe("done");
  });
});

describe("completion roll-ups", () => {
  it("complete = every tracked item done, ignoring untracked; empty is never complete", () => {
    expect(isComplete(["done", "untracked", "done"])).toBe(true);
    expect(isComplete(["done", "in_progress"])).toBe(false);
    expect(isComplete(["untracked"])).toBe(false);
    expect(isComplete([])).toBe(false);
    expect(countDone(["done", "untracked", "not_started"])).toEqual({ done: 1, tracked: 2 });
  });

  it("overdue = past due and not complete", () => {
    const now = Date.parse("2026-06-01T00:00:00Z");
    expect(isOverdue("2026-05-01T00:00:00Z", ["done", "not_started"], now)).toBe(true);
    expect(isOverdue("2026-05-01T00:00:00Z", ["done"], now)).toBe(false);
    expect(isOverdue("2026-07-01T00:00:00Z", ["not_started"], now)).toBe(false);
    expect(isOverdue(null, ["not_started"], now)).toBe(false);
  });

  it("planMatrix encodes one status char per item and counts finishers", () => {
    const items: PlanItem[] = [{ kind: "room", id: "intro" }, { kind: "quiz", id: "mitre-attack" }, { kind: "lesson", id: "org-x" }];
    const m = planMatrix(items, [A, B], idx);
    expect(m.rows).toEqual([
      { user_id: A, statuses: "ddu" },
      { user_id: B, statuses: "ppu" },
    ]);
    expect(m.completed).toBe(1);
  });
});
