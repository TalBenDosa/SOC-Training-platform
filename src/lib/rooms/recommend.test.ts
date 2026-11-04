import { describe, it, expect } from "vitest";
import { ROOMS_META } from "@/data/roomsMeta";
import { orderRoomsForLearning, recommendNextRoom } from "./recommend";
import { orgRoomsLocked } from "@/lib/org/roomLock";

const RANK: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2 };

describe("room levels and learning order", () => {
  it("no room is a lower level than a room it builds on", () => {
    const byId = new Map(ROOMS_META.map(r => [r.id, r]));
    const bad: string[] = [];
    for (const r of ROOMS_META) for (const p of r.prerequisites) {
      const q = byId.get(p);
      expect(q, `${r.id} -> missing prerequisite ${p}`).toBeTruthy();
      if (q && RANK[q.difficulty] > RANK[r.difficulty]) bad.push(`${r.id} (${r.difficulty}) needs ${p} (${q.difficulty})`);
    }
    expect(bad).toEqual([]);
  });

  it("the rooms list puts every room after the rooms it builds on", () => {
    const order = orderRoomsForLearning(ROOMS_META);
    expect(order).toHaveLength(ROOMS_META.length);
    const pos = new Map(order.map((r, i) => [r.id, i]));
    for (const r of order) for (const p of r.prerequisites) expect(pos.get(p)!, `${p} before ${r.id}`).toBeLessThan(pos.get(r.id)!);
    // Levels come in order: all beginner, then intermediate, then advanced.
    const ranks = order.map(r => RANK[r.difficulty]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it("a new learner is pointed at a room with no prerequisites", () => {
    const rec = recommendNextRoom({});
    expect(rec?.room.prerequisites).toEqual([]);
    expect(rec?.room.difficulty).toBe("beginner");
  });
});

describe("org room lock (0102)", () => {
  it("is open by default and locks only when the admin turned it on", () => {
    expect(orgRoomsLocked(null)).toBe(false);
    expect(orgRoomsLocked({})).toBe(false);
    expect(orgRoomsLocked({ rooms_locked: false })).toBe(false);
    expect(orgRoomsLocked({ rooms_locked: true })).toBe(true);
  });
  it("the older all_rooms_unlocked override keeps rooms open", () => {
    expect(orgRoomsLocked({ rooms_locked: true, all_rooms_unlocked: true })).toBe(false);
  });
});
