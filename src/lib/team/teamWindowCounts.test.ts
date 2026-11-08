// What waits for a player, counted the same in the team room title and the Sentinel strip (2026-11 review).
import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { titleWithCount, visibleMessages, waitingCounts } from "./teamWindowCounts";
import { isolationError, latestRequestByHost, approverNames } from "./useIsolationRequest";
import { NO_APPROVER, isolationRequests } from "./isolationApproval";

let seq = 0;
const ev = (type: string, payload: Record<string, unknown>, actor: string | null, role: string | null = null): Ev => ({ seq: ++seq, type, actor_id: actor, role, payload, occurred_at: "2026-11-07T10:00:00Z" });
const members = [
  { user_id: "t2", role: "t2", status: "active", active: true },
  { user_id: "t3", role: "t3", status: "active", active: true },
  { user_id: "mgr", role: "mgr", status: "active", active: true },
  { user_id: "ins", role: "instructor", status: "active", active: true },
];

describe("waitingCounts", () => {
  it("counts untaken escalations, isolation requests for the approver, and unread chat", () => {
    const events = [
      ev("escalation.requested", { event_id: "a" }, "t1", "t1"),
      ev("escalation.requested", { event_id: "b" }, "t1", "t1"),
      ev("escalation.acknowledged", { event_id: "b" }, "t2", "t2"),
      ev("isolation.requested", { host: "WS-1", reason: "shell" }, "t2", "t2"),
      ev("message.sent", { text: "look at WS-1" }, "t3", "t3"),
    ];
    const t2 = waitingCounts(events, { meId: "t2", role: "t2", isStaff: false, members, chatReadSeq: 0 });
    expect(t2.escalations).toBe(1);
    expect(t2.approvals).toBe(0);              // nobody approves their own request
    expect(t2.unreadChat).toBe(1);
    const mgr = waitingCounts(events, { meId: "mgr", role: "mgr", isStaff: false, members, chatReadSeq: 999 });
    expect(mgr.approvals).toBe(1);             // the Manager is the senior on shift
    expect(mgr.unreadChat).toBe(0);
    const t3 = waitingCounts(events, { meId: "t3", role: "t3", isStaff: false, members, chatReadSeq: 0 });
    expect(t3.approvals).toBe(0);              // a Manager is online: Tier-3 is not the approver
  });
  it("a coach message is shown only to its addressee and staff", () => {
    const events = [ev("message.sent", { text: "take the oldest alert", kind: "coach", to: "t2" }, "ins", "instructor")];
    expect(visibleMessages(events, "t2", false)).toHaveLength(1);
    expect(visibleMessages(events, "t3", false)).toHaveLength(0);
    expect(visibleMessages(events, "other-staff", true)).toHaveLength(1);
  });
  it("an approved containment on my case waits for me to carry it out", () => {
    const events = [
      ev("escalation.requested", { event_id: "c" }, "t1", "t1"),
      ev("escalation.acknowledged", { event_id: "c" }, "t2", "t2"),
      ev("containment.requested", { event_id: "c", target: "svc", containment_type: "disable_account" }, "t2", "t2"),
    ];
    const req = events[2];
    events.push(ev("containment.approved", { event_id: "c", request_seq: req.seq }, "mgr", "mgr"));
    expect(waitingCounts(events, { meId: "t2", role: "t2", isStaff: false, members, chatReadSeq: 0 }).approved).toBe(1);
  });
});

describe("titleWithCount", () => {
  it("adds, replaces and drops the count", () => {
    expect(titleWithCount("Team session", 3)).toBe("(3) Team session");
    expect(titleWithCount("(3) Team session", 1)).toBe("(1) Team session");
    expect(titleWithCount("(3) Team session", 0)).toBe("Team session");
  });
});

describe("isolation request helpers", () => {
  it("maps the database refusals to plain words", () => {
    expect(isolationError("isolation_pending: WS-1")).toBe("A request to isolate WS-1 is already waiting for approval.");
    expect(isolationError("already_isolated: WS-1")).toBe("WS-1 is already isolated.");
    expect(isolationError("not_approver")).toContain("senior on shift");
  });
  it("keeps the latest request per host and names the approver", () => {
    const events = [
      ev("isolation.requested", { host: "WS-1", reason: "a" }, "t2", "t2"),
      ev("isolation.denied", { request_seq: seq, reason: "capture memory first" }, "mgr", "mgr"),
      ev("isolation.requested", { host: "ws-1", reason: "b" }, "t2", "t2"),
    ];
    const latest = latestRequestByHost(isolationRequests(events)).get("ws-1")!;
    expect(latest.reason).toBe("b");
    expect(latest.state).toBe("pending");
    const roster = [{ user_id: "mgr", role: "mgr", status: "active", name: "Noa", handle: null }, { user_id: "t2", role: "t2", status: "active", name: "Avi", handle: null }];
    expect(approverNames(roster, "t2", new Set(["mgr", "t2"]))).toBe("Noa (SOC Manager)");
    // Nobody senior online and no instructor seat: nobody but the requester could approve it.
    expect(approverNames(roster, "t2", new Set(["t2"]))).toBe(NO_APPROVER);
    // The exercise admin in the instructor seat is the fallback approver.
    expect(approverNames([...roster, { user_id: "ins", role: "instructor", status: "active", name: "Tal", handle: null }], "t2", new Set(["t2"]))).toBe("Tal (exercise admin)");
  });
});
