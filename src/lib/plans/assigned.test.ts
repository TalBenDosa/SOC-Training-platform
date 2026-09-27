import { describe, it, expect } from "vitest";
import { deriveAssignedKeys } from "./assigned";
import type { LearnerPlan, ResolvedPlanItem } from "./types";

const item = (kind: ResolvedPlanItem["kind"], id: string, extra: Partial<ResolvedPlanItem> = {}): ResolvedPlanItem =>
  ({ kind, id, title: id, href: `/${kind}/${id}`, status: "not_started", ...extra });

const plan = (p: Partial<LearnerPlan> & { items: ResolvedPlanItem[] }): LearnerPlan => ({
  id: p.id ?? "p", title: "t", instructions: null, due_at: null, priority: 2, personal: false, via: ["Everyone"],
  created_at: "2026-09-01T00:00:00Z", ...p,
});

describe("deriveAssignedKeys", () => {
  it("returns an empty map for no plans", () => {
    expect(deriveAssignedKeys([])).toEqual({});
  });

  it("keys items as kind:id with the plan's priority when the item has none", () => {
    const m = deriveAssignedKeys([plan({ priority: 3, items: [item("room", "intro"), item("quiz", "mitre", { priority: 1 })] })]);
    expect(m["room:intro"]).toEqual({ priority: 3, due_at: null, done: false, personal: false });
    expect(m["quiz:mitre"].priority).toBe(1);   // the item's own priority wins over the plan's
  });

  it("merges an item in several plans: highest priority, earliest due date, done, personal", () => {
    const m = deriveAssignedKeys([
      plan({ id: "a", priority: 2, due_at: "2026-11-01T23:59:59.999Z", items: [item("lesson", "soc--intro")] }),
      plan({ id: "b", priority: 1, due_at: "2026-10-01T23:59:59.999Z", personal: true, items: [item("lesson", "soc--intro", { status: "done" })] }),
      plan({ id: "c", priority: 3, items: [item("lesson", "soc--intro", { priority: 3 })] }),
    ]);
    expect(m["lesson:soc--intro"]).toEqual({ priority: 1, due_at: "2026-10-01T23:59:59.999Z", done: true, personal: true });
  });

  it("a plan without a due date doesn't erase another plan's", () => {
    const m = deriveAssignedKeys([
      plan({ id: "a", due_at: "2026-10-01T23:59:59.999Z", items: [item("room", "x")] }),
      plan({ id: "b", due_at: null, items: [item("room", "x")] }),
    ]);
    expect(m["room:x"].due_at).toBe("2026-10-01T23:59:59.999Z");
  });

  it("in-progress / untracked items are not done", () => {
    const m = deriveAssignedKeys([plan({ items: [item("room", "a", { status: "in_progress" }), item("lesson", "org-x-1", { status: "untracked" })] })]);
    expect(m["room:a"].done).toBe(false);
    expect(m["lesson:org-x-1"].done).toBe(false);
  });

  it("skips an archived plan defensively", () => {
    const m = deriveAssignedKeys([{ ...plan({ items: [item("scenario", "s1")] }), archived_at: "2026-09-02T00:00:00Z" }]);
    expect(m).toEqual({});
  });
});
