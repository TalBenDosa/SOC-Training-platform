import { describe, it, expect } from "vitest";
import { isRecipient, resolveRecipients, sortItemsByPriority, sortPlansForLearner, viaLabels, type TargetRow } from "./targeting";
import type { PlanItem, Priority } from "./types";

const S1 = "s1", S2 = "s2", S3 = "s3", GONE = "gone";
const TIER1 = "g-tier1", TIER2 = "g-tier2";

const orgPlan = { audience: "org" as const, personal_user_id: null };
const groupPlan = { audience: "targeted" as const, personal_user_id: null };
const groupTargets: TargetRow[] = [{ group_id: TIER1, user_id: null }];
const directTargets: TargetRow[] = [{ group_id: null, user_id: S2 }];

describe("isRecipient (mirrors the 0075 RLS read policy)", () => {
  it("org-wide plans reach everyone in the org", () => {
    expect(isRecipient(S3, orgPlan, [], new Set())).toBe(true);
  });

  it("a group plan reaches group members only", () => {
    expect(isRecipient(S1, groupPlan, groupTargets, new Set([TIER1]))).toBe(true);
    expect(isRecipient(S3, groupPlan, groupTargets, new Set([TIER2]))).toBe(false);
  });

  it("a direct target reaches that user only", () => {
    expect(isRecipient(S2, groupPlan, directTargets, new Set())).toBe(true);
    expect(isRecipient(S1, groupPlan, directTargets, new Set([TIER1]))).toBe(false);
  });

  it("a personal plan reaches its owner only — even if it were mislabelled org-wide", () => {
    expect(isRecipient(S1, { audience: "targeted", personal_user_id: S1 }, [], new Set())).toBe(true);
    expect(isRecipient(S2, { audience: "targeted", personal_user_id: S1 }, [], new Set())).toBe(false);
    expect(isRecipient(S2, { audience: "org", personal_user_id: S1 }, [], new Set())).toBe(false);
  });

  it("archived plans reach nobody", () => {
    expect(isRecipient(S1, { ...orgPlan, archived_at: "2026-01-01T00:00:00Z" }, [], new Set())).toBe(false);
  });

  it("a targeted plan with no targets reaches nobody", () => {
    expect(isRecipient(S1, groupPlan, [], new Set([TIER1]))).toBe(false);
  });
});

describe("resolveRecipients", () => {
  const members = new Map([[TIER1, [S1, S2, GONE]], [TIER2, [S3]]]);
  const eligible = new Set([S1, S2, S3]);

  it("org-wide → the org's students, filtered by eligibility", () => {
    expect(resolveRecipients(orgPlan, [], members, eligible, [S1, S3, GONE])).toEqual([S1, S3]);
  });

  it("targeted → direct users ∪ group members, deduped, ineligible dropped", () => {
    const targets: TargetRow[] = [{ group_id: TIER1, user_id: null }, { group_id: null, user_id: S2 }, { group_id: null, user_id: S3 }];
    expect(resolveRecipients(groupPlan, targets, members, eligible, [])).toEqual([S1, S2, S3]);
  });

  it("personal → the owner, only while eligible", () => {
    expect(resolveRecipients({ audience: "targeted", personal_user_id: S2 }, [], members, eligible, [S1])).toEqual([S2]);
    expect(resolveRecipients({ audience: "targeted", personal_user_id: GONE }, [], members, eligible, [S1])).toEqual([]);
  });

  it("orders by the supplied roster rank", () => {
    const rank = new Map([[S3, 0], [S1, 1], [S2, 2]]);
    expect(resolveRecipients(orgPlan, [], members, eligible, [S1, S2, S3], id => rank.get(id)!)).toEqual([S3, S1, S2]);
  });
});

describe("viaLabels", () => {
  const name = (id: string) => ({ [TIER1]: "Tier-1 analysts", [TIER2]: "Tier-2" } as Record<string, string>)[id];
  it("explains why a learner sees a plan", () => {
    expect(viaLabels(S1, orgPlan, [], new Set(), name)).toEqual(["Everyone"]);
    expect(viaLabels(S1, { audience: "targeted", personal_user_id: S1 }, [], new Set(), name)).toEqual(["You"]);
    const t: TargetRow[] = [{ group_id: TIER1, user_id: null }, { group_id: TIER2, user_id: null }, { group_id: null, user_id: S1 }];
    // Only the learner's OWN groups are named — never other groups on the plan.
    expect(viaLabels(S1, groupPlan, t, new Set([TIER1]), name)).toEqual(["You", "Tier-1 analysts"]);
  });
});

describe("ordering", () => {
  const p = (id: string, personal: boolean, priority: Priority, due_at: string | null, created_at = "2026-01-01T00:00:00Z") =>
    ({ id, personal, priority, due_at, created_at });

  it("personal plan first, then priority, then soonest due (undated last), then newest", () => {
    const sorted = sortPlansForLearner([
      p("low", false, 3, "2026-01-02T00:00:00Z"),
      p("high-undated", false, 1, null),
      p("high-soon", false, 1, "2026-01-05T00:00:00Z"),
      p("mine", true, 2, null),
      p("high-soon-newer", false, 1, "2026-01-05T00:00:00Z", "2026-02-01T00:00:00Z"),
    ]);
    expect(sorted.map(x => x.id)).toEqual(["mine", "high-soon-newer", "high-soon", "high-undated", "low"]);
  });

  it("items sort by priority, stable within a priority", () => {
    const items: PlanItem[] = [
      { kind: "room", id: "a" }, { kind: "room", id: "b", priority: 1 }, { kind: "room", id: "c", priority: 3 },
      { kind: "room", id: "d" }, { kind: "room", id: "e", priority: 1 },
    ];
    expect(sortItemsByPriority(items).map(i => i.id)).toEqual(["b", "e", "a", "d", "c"]);
  });
});
