import { describe, expect, it } from "vitest";
import {
  ANNOUNCEMENT_HEADING, MAX_POPUP_ITEMS, SHOWN_CAP, SHOWN_KEY,
  buildAnnouncementView, findPlan, pendingPlanNotices, readShown, rememberShown, selectAnnouncement, unreadPlanNoticeIds,
} from "./planAnnouncement";
import type { NotificationItem } from "./types";
import type { LearnerPlan, ResolvedPlanItem } from "@/lib/plans/types";

const A1 = "11111111-1111-4111-8111-111111111111";
const A2 = "22222222-2222-4222-8222-222222222222";

function n(id: string, over: Partial<NotificationItem> = {}): NotificationItem {
  return {
    id, kind: "plan_assigned", title: `New learning plan: ${id}`, body: `body ${id}`, link: "/learn",
    assignment_id: A1, created_at: "2026-09-20T10:00:00Z", read_at: null, ...over,
  };
}

function item(i: number, over: Partial<ResolvedPlanItem> = {}): ResolvedPlanItem {
  return { kind: "room", id: `r${i}`, title: `Room ${i}`, href: `/rooms/r${i}`, status: "not_started", ...over };
}

function plan(over: Partial<LearnerPlan> = {}): LearnerPlan {
  return {
    id: A1, title: "Phishing week", instructions: "Do the phishing rooms first.", due_at: "2026-10-01T23:59:59Z",
    priority: 1, personal: false, via: ["Blue team"], items: [item(1), item(2)], created_at: "2026-09-19T00:00:00Z", ...over,
  };
}

class MemStorage {
  data = new Map<string, string>();
  getItem(k: string) { return this.data.get(k) ?? null; }
  setItem(k: string, v: string) { this.data.set(k, v); }
}
const throwing = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };

describe("which notification to announce", () => {
  it("picks the newest unread plan notice", () => {
    const items = [
      n("a", { created_at: "2026-09-20T10:00:00Z" }),
      n("b", { created_at: "2026-09-22T10:00:00Z", kind: "plan_updated" }),
      n("c", { created_at: "2026-09-21T10:00:00Z" }),
    ];
    const g = selectAnnouncement(items, new Set());
    expect(g?.notice.id).toBe("b");
    expect(g?.ids).toEqual(["b", "c", "a"]);
  });

  it("ignores read notices and returns null when nothing is pending", () => {
    expect(selectAnnouncement([n("a", { read_at: "2026-09-21T00:00:00Z" })], new Set())).toBeNull();
    expect(selectAnnouncement([], new Set())).toBeNull();
  });

  it("ignores kinds that aren't plan notices", () => {
    const odd = n("x", { kind: "something_else" as NotificationItem["kind"] });
    expect(pendingPlanNotices([odd, n("a")], new Set()).map(x => x.id)).toEqual(["a"]);
    expect(unreadPlanNoticeIds([odd, n("a"), n("r", { read_at: "2026-09-21T00:00:00Z" })])).toEqual(["a"]);
  });

  it("breaks created_at ties deterministically by id", () => {
    const g = selectAnnouncement([n("a"), n("c"), n("b")], new Set());
    expect(g?.ids).toEqual(["c", "b", "a"]);
  });
});

describe("grouping count", () => {
  it("counts the OTHER pending plan notices as 'more'", () => {
    const g = selectAnnouncement([n("a"), n("b", { created_at: "2026-09-21T00:00:00Z" }), n("c", { kind: "personal_plan" })], new Set());
    expect(g?.more).toBe(2);
  });

  it("is 0 for a single notice and excludes read / shown ones", () => {
    const g = selectAnnouncement([n("a"), n("b", { read_at: "2026-09-21T00:00:00Z" }), n("c")], new Set(["c"]));
    expect(g?.notice.id).toBe("a");
    expect(g?.more).toBe(0);
  });
});

describe("session dismiss filtering", () => {
  it("never re-announces a notice already shown this session", () => {
    const items = [n("a"), n("b", { created_at: "2026-09-22T00:00:00Z" })];
    const first = selectAnnouncement(items, new Set())!;
    const shown = rememberShown(new MemStorage(), first.ids);
    expect(selectAnnouncement(items, shown)).toBeNull();
    // a NEW notice arriving later is announced on its own
    const later = selectAnnouncement([...items, n("c", { created_at: "2026-09-23T00:00:00Z" })], shown);
    expect(later?.notice.id).toBe("c");
    expect(later?.more).toBe(0);
  });

  it("round-trips the shown set through storage", () => {
    const s = new MemStorage();
    rememberShown(s, ["a", "b"]);
    rememberShown(s, ["c"]);
    expect([...readShown(s)].sort()).toEqual(["a", "b", "c"]);
    expect(JSON.parse(s.getItem(SHOWN_KEY)!)).toEqual(["a", "b", "c"]);
  });

  it("is fail-safe when storage throws, is missing or holds junk", () => {
    expect(readShown(throwing).size).toBe(0);
    expect(readShown(null).size).toBe(0);
    expect([...rememberShown(throwing, ["a"])]).toEqual(["a"]);
    expect([...rememberShown(throwing, ["b"], new Set(["a"]))]).toEqual(["a", "b"]);
    const s = new MemStorage();
    s.setItem(SHOWN_KEY, "{not json");
    expect(readShown(s).size).toBe(0);
    s.setItem(SHOWN_KEY, JSON.stringify({ a: 1 }));
    expect(readShown(s).size).toBe(0);
    s.setItem(SHOWN_KEY, JSON.stringify(["a", 3, null]));
    expect([...readShown(s)]).toEqual(["a"]);
  });

  it("caps the stored set, keeping the newest ids", () => {
    const s = new MemStorage();
    const ids = Array.from({ length: SHOWN_CAP + 10 }, (_, i) => `id${i}`);
    const out = rememberShown(s, ids);
    expect(out.size).toBe(SHOWN_CAP);
    expect(out.has(`id${SHOWN_CAP + 9}`)).toBe(true);
    expect(out.has("id0")).toBe(false);
  });
});

describe("announcement view", () => {
  it("renders the live plan matched by assignment_id", () => {
    const v = buildAnnouncementView(n("a", { assignment_id: A1.toUpperCase() }), [plan({ id: A2, title: "Other" }), plan()]);
    expect(v.fallback).toBe(false);
    expect(v.heading).toBe(ANNOUNCEMENT_HEADING.plan_assigned);
    expect(v.title).toBe("Phishing week");
    expect(v.via).toBe("Blue team");
    expect(v.priority).toBe(1);
    expect(v.priorityLabel).toBe("High");
    expect(v.dueAt).toBe("2026-10-01T23:59:59Z");
    expect(v.instructions).toBe("Do the phishing rooms first.");
    expect(v.items.map(i => i.href)).toEqual(["/rooms/r1", "/rooms/r2"]);
    expect(v.fallbackBody).toBeNull();
    expect(v.link).toBe("/learn");
  });

  it("labels personal plans 'Personal' and uses the matching heading per kind", () => {
    const v = buildAnnouncementView(n("a", { kind: "personal_plan" }), [plan({ personal: true, via: ["You"] })]);
    expect(v.via).toBe("Personal");
    expect(v.heading).toBe("Your personal priorities were updated");
    expect(buildAnnouncementView(n("a", { kind: "plan_updated" }), [plan()]).heading).toBe("Your plan was updated");
  });

  it("lists at most 5 items, open work first, and counts the rest", () => {
    const items = [item(1, { status: "done" }), ...Array.from({ length: 7 }, (_, i) => item(i + 2))];
    const v = buildAnnouncementView(n("a"), [plan({ items })]);
    expect(v.items).toHaveLength(MAX_POPUP_ITEMS);
    expect(v.items[0].title).toBe("Room 2");
    expect(v.items.some(i => i.status === "done")).toBe(false);
    expect(v.moreItems).toBe(3);
  });

  it("never renders an unsafe item link", () => {
    const v = buildAnnouncementView(n("a"), [plan({ items: [item(1, { href: "//evil.example" })] })]);
    expect(v.items[0].href).toBe("/learn");
  });

  it("falls back to the notification text when the plan is gone", () => {
    const notice = n("a", { assignment_id: A2, title: "New learning plan: Old", body: "3 items to complete", link: "/rooms/x" });
    const v = buildAnnouncementView(notice, [plan()]);
    expect(v.fallback).toBe(true);
    expect(v.title).toBe("New learning plan: Old");
    expect(v.fallbackBody).toBe("3 items to complete");
    expect(v.items).toEqual([]);
    expect(v.via).toBeNull();
    expect(v.link).toBe("/rooms/x");
  });

  it("falls back when plans couldn't be loaded, the notice has no plan id, or the plan is archived", () => {
    expect(buildAnnouncementView(n("a"), null).fallback).toBe(true);
    expect(buildAnnouncementView(n("a", { assignment_id: null }), [plan()]).fallback).toBe(true);
    expect(findPlan(n("a"), [{ ...plan(), archived_at: "2026-09-21T00:00:00Z" } as LearnerPlan])).toBeNull();
  });

  it("sends 'Open my plan' to /learn when the notice link is missing or unsafe", () => {
    expect(buildAnnouncementView(n("a", { link: null }), null).link).toBe("/learn");
    expect(buildAnnouncementView(n("a", { link: "//evil.example" }), null).link).toBe("/learn");
  });
});
