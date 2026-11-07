import { describe, it, expect } from "vitest";
import { sentinelActivity } from "./sentinelActivity";
import type { Ev } from "@/lib/team/types";

const ev = (seq: number, type: string, actor_id: string, payload: Record<string, unknown> = {}): Ev => ({ seq, type, actor_id, role: "t2", payload });

describe("sentinelActivity", () => {
  it("counts one analyst's work and leaves out everyone else's", () => {
    const log = [
      ev(1, "sentinel.query_run", "a", { ok: true }),
      ev(2, "sentinel.query_run", "a", { ok: false }),
      ev(3, "sentinel.query_run", "b", { ok: true }),
      ev(4, "sentinel.bookmark_added", "a"),
      ev(5, "sentinel.comment_added", "a"),
      ev(6, "sentinel.incident_updated", "a", { patch: { status: "Closed" } }),
      ev(7, "sentinel.incident_updated", "a", { patch: { status: "Active" } }),
    ];
    expect(sentinelActivity(log, "a")).toEqual({ queries: 2, queriesOk: 1, bookmarks: 1, comments: 1, closed: 1, judged: 0, judgedRight: 0 });
  });

  it("judges a closing classification against the attack logs behind the incident", () => {
    const close = (seq: number, classification: string, event_ids: string[]) => ev(seq, "sentinel.incident_updated", "a", { patch: { status: "Closed", classification }, event_ids });
    const log = [close(1, "True Positive - suspicious activity", ["x"]), close(2, "False Positive - incorrect data", ["x"]), close(3, "Benign Positive - suspicious but expected", ["y"]), close(4, "Undetermined", ["x"])];
    expect(sentinelActivity(log, "a", new Set(["x"]))).toMatchObject({ closed: 4, judged: 3, judgedRight: 2 });
  });

  it("is null for someone who never used Sentinel, so an EDR session's report does not change", () => {
    expect(sentinelActivity([ev(1, "disposition.set", "a")], "a")).toBeNull();
  });
});
