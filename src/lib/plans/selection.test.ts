import { describe, it, expect } from "vitest";
import { applyToggle, capNotice } from "./selection";
import type { CatalogNode, PlanItem } from "./types";

const leaf = (id: string): CatalogNode => ({ key: `room:${id}`, label: id, item: { kind: "room", id } });
const leaves = new Map(["a", "b", "c", "d"].map(id => [`room:${id}`, leaf(id)]));

describe("applyToggle", () => {
  it("appends newly ticked leaves in tree order, skipping ones already chosen", () => {
    const start: PlanItem[] = [{ kind: "room", id: "b", priority: 1 }];
    const r = applyToggle(start, ["room:a", "room:b", "room:c"], true, leaves);
    expect(r.items).toEqual([{ kind: "room", id: "b", priority: 1 }, { kind: "room", id: "a" }, { kind: "room", id: "c" }]);
    expect(r.dropped).toBe(0);
  });

  it("unticking removes exactly those leaves and keeps the rest (with their settings)", () => {
    const start: PlanItem[] = [{ kind: "room", id: "a", note: "x" }, { kind: "room", id: "b" }, { kind: "room", id: "c" }];
    expect(applyToggle(start, ["room:b", "room:c"], false, leaves).items).toEqual([{ kind: "room", id: "a", note: "x" }]);
  });

  it("reports what the cap dropped instead of silently truncating", () => {
    const r = applyToggle([{ kind: "room", id: "a" }], ["room:b", "room:c", "room:d"], true, leaves, 2);
    expect(r.items.map(i => i.id)).toEqual(["a", "b"]);
    expect(r.dropped).toBe(2);
    expect(capNotice(r.dropped, 2)).toMatch(/at most 2 items — 2 more were not added/);
    expect(capNotice(0)).toBeNull();
  });

  it("ignores keys that are not leaves", () => {
    expect(applyToggle([], ["grp:rooms", "room:zzz"], true, leaves)).toEqual({ items: [], dropped: 0 });
  });
});
