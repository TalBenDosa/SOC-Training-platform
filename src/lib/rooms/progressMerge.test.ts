import { describe, it, expect } from "vitest";
import { mergeRoomEntry, mergeTaskXpMax, roomScoreXp, clampRoomXp, ROOM_XP_DB_CAP } from "./progressMerge";

describe("mergeRoomEntry — a save can never lower earned room progress", () => {
  const stored = {
    completedTaskIds: ["t1", "t2", "t3"],
    xpEarned: 90,
    perTaskXp: { t1: 40, t2: 30, t3: 20 },
    telemetry: [{ taskId: "t1" }, { taskId: "t2" }, { taskId: "t3" }],
    completedAt: "2026-09-20T10:00:00.000Z",
  };

  it("stale empty-state save (hard-reload race) keeps the stored row", () => {
    // RoomClient mounted before hydrate → state was empty → user did one task.
    const next = { completedTaskIds: ["t4"], xpEarned: 10, perTaskXp: { t4: 10 }, telemetry: [{ taskId: "t4" }] };
    const m = mergeRoomEntry(stored, next);
    expect(m.perTaskXp).toEqual({ t1: 40, t2: 30, t3: 20, t4: 10 });
    expect(m.xpEarned).toBe(100);
    expect(m.completedTaskIds.sort()).toEqual(["t1", "t2", "t3", "t4"]);
    expect(m.completedAt).toBe(stored.completedAt);
    expect(m.telemetry).toHaveLength(4);
  });

  it("a lower re-attempt never lowers a per-task best or the total", () => {
    const next = { ...stored, xpEarned: 60, perTaskXp: { t1: 10, t2: 30, t3: 20 } };
    const m = mergeRoomEntry(stored, next);
    expect(m.perTaskXp!.t1).toBe(40);
    expect(m.xpEarned).toBe(90);
  });

  it("never clears completedAt; keeps the FIRST pass date", () => {
    const { completedAt: _drop, ...noDate } = stored;
    expect(mergeRoomEntry(stored, noDate).completedAt).toBe(stored.completedAt);
    expect(mergeRoomEntry(stored, { ...stored, completedAt: "2026-09-27T00:00:00.000Z" }).completedAt).toBe(stored.completedAt);
  });

  it("review-missed mode replaces the id list but still keeps the XP", () => {
    const next = { ...stored, completedTaskIds: ["t1"] };
    const m = mergeRoomEntry(stored, next, { replaceIds: true });
    expect(m.completedTaskIds).toEqual(["t1"]);
    expect(m.xpEarned).toBe(90);
  });

  it("an improvement raises the total to the per-task sum", () => {
    const m = mergeRoomEntry(stored, { ...stored, perTaskXp: { ...stored.perTaskXp, t3: 50 }, xpEarned: 120 });
    expect(m.xpEarned).toBe(120);
  });

  it("clamps to the DB cap (0025: 0..1000) so one room can't wedge saves", () => {
    const m = mergeRoomEntry(undefined, { completedTaskIds: ["a"], xpEarned: 4000, perTaskXp: { a: 4000 } });
    expect(m.xpEarned).toBe(ROOM_XP_DB_CAP);
    expect(clampRoomXp(-5)).toBe(0);
    expect(clampRoomXp(Number.NaN)).toBe(0);
    expect(clampRoomXp(12.6)).toBe(13);
  });

  it("first save with nothing stored passes through (xp = per-task sum)", () => {
    const m = mergeRoomEntry(undefined, { completedTaskIds: ["a", "b"], xpEarned: 0, perTaskXp: { a: 5, b: 20 } });
    expect(m.xpEarned).toBe(25);
    expect(m.completedAt).toBeUndefined();
  });
});

describe("mergeTaskXpMax", () => {
  it("takes the max per key and ignores non-numbers", () => {
    expect(mergeTaskXpMax({ a: 1, b: 5 }, { a: 3, c: 2, d: "x" as unknown as number })).toEqual({ a: 3, b: 5, c: 2 });
    expect(mergeTaskXpMax(undefined, undefined)).toEqual({});
  });
});

describe("roomScoreXp — the 65% gate counts gradeable tasks only", () => {
  const gradeable = { q1: 40, q2: 60 }; // r1 is a reading task (not gradeable)

  it("reading engagement XP is stored but doesn't help pass", () => {
    expect(roomScoreXp({ xpEarned: 45, perTaskXp: { r1: 5, q1: 40 } }, gradeable)).toBe(40);
  });

  it("caps a task at its max", () => {
    expect(roomScoreXp({ xpEarned: 0, perTaskXp: { q1: 400 } }, gradeable)).toBe(40);
  });

  it("legacy entries without perTaskXp fall back to xpEarned", () => {
    expect(roomScoreXp({ xpEarned: 77, perTaskXp: {} }, gradeable)).toBe(77);
    expect(roomScoreXp({ xpEarned: 77 }, gradeable)).toBe(77);
  });
});
