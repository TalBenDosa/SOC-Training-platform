import { describe, expect, it } from "vitest";
import { DEFAULT_TASKS, foldIncidentState } from "./state";
import type { SentinelIncident } from "./types";

const incident: SentinelIncident = {
  number: 4001, id: "inc-1", title: "t", severity: "Medium", created: "2026-01-01T08:00:00.000Z", lastUpdate: "2026-01-01T08:10:00.000Z", alertIds: [], entityIds: [], tactics: [], techniques: [], products: [], description: "", eventCount: 0, eventsQuery: "",
};
const at = (m: number) => `2026-01-01T09:${String(m).padStart(2, "0")}:00.000Z`;
const ev = (type: string, payload: unknown, m: number, actor_name = "Dana") => ({ type, actor_name, payload, occurred_at: at(m) });

describe("foldIncidentState", () => {
  it("starts New, unassigned, with the triage list", () => {
    const s = foldIncidentState([], incident);
    expect(s.status).toBe("New");
    expect(s.owner).toBeNull();
    expect(s.severity).toBe("Medium");
    expect(s.tasks.map(t => t.title)).toEqual(DEFAULT_TASKS);
    expect(s.tasks.every(t => !t.done)).toBe(true);
  });

  it("reads like the real activity log", () => {
    const s = foldIncidentState([
      ev("sentinel.incident_updated", { incident_id: "inc-1", patch: { owner: "Dana", status: "Active" } }, 1),
      ev("sentinel.incident_updated", { incident_id: "inc-1", patch: { severity: "High" } }, 2),
      ev("sentinel.comment_added", { incident_id: "inc-1", text: "Looking at the host" }, 3),
      ev("sentinel.incident_updated", { incident_id: "inc-1", patch: { status: "Closed", classification: "Undetermined", closingComment: "Not enough data" } }, 4, "Noa"),
    ], incident);
    expect(s.status).toBe("Closed");
    expect(s.owner).toBe("Dana");
    expect(s.severity).toBe("High");
    expect(s.classification).toBe("Undetermined");
    expect(s.closingComment).toBe("Not enough data");
    expect(s.comments).toHaveLength(1);
    expect(s.activity.map(a => a.text)).toEqual([
      "Incident created", "Status changed from New to Active", "Incident assigned to Dana", "Severity changed from Medium to High", "Comment added",
      "Status changed from Active to Closed", "Classification set to Undetermined",
    ]);
    expect(s.activity.at(-1)?.actor).toBe("Noa");
  });

  it("ignores other incidents and folds in time order", () => {
    const s = foldIncidentState([
      ev("sentinel.incident_updated", { incident_id: "inc-1", patch: { status: "Closed" } }, 5),
      ev("sentinel.incident_updated", { incident_id: "other", patch: { status: "Active" } }, 1),
      ev("sentinel.incident_updated", { incident_id: "inc-1", patch: { status: "Active" } }, 2),
    ], incident);
    expect(s.status).toBe("Closed");
    expect(s.activity.map(a => a.text)).toEqual(["Incident created", "Status changed from New to Active", "Status changed from Active to Closed"]);
  });

  it("tasks: default ones tick, new ones are added, and unticking clears the name", () => {
    const title = DEFAULT_TASKS[0];
    const s = foldIncidentState([
      ev("sentinel.task_set", { incident_id: "inc-1", title, done: true }, 1),
      ev("sentinel.task_set", { incident_id: "inc-1", title: "Call the user", done: true }, 2),
      ev("sentinel.task_set", { incident_id: "inc-1", title, done: false }, 3),
    ], incident);
    expect(s.tasks.find(t => t.title === title)).toMatchObject({ done: false });
    expect(s.tasks.find(t => t.title === title)?.by).toBeUndefined();
    expect(s.tasks.find(t => t.title === "Call the user")).toMatchObject({ done: true, by: "Dana" });
  });

  it("bookmarks attach to their incident", () => {
    const b = { name: "Odd logon", query: "SigninLogs", columns: ["A"], rows: [{ A: "1" }], notes: "n", entityIds: [], incidentId: "inc-1" };
    const s = foldIncidentState([
      ev("sentinel.bookmark_added", b, 1),
      ev("sentinel.bookmark_added", { ...b, incidentId: "other" }, 2),
      ev("sentinel.bookmark_added", { ...b, incidentId: undefined }, 3),
    ], incident);
    expect(s.bookmarks).toHaveLength(1);
    expect(s.bookmarks[0]).toMatchObject({ name: "Odd logon", author: "Dana", at: at(1) });
    expect(s.activity.at(-1)?.text).toBe('Bookmark "Odd logon" added');
  });
});
