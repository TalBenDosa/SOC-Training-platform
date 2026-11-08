// The team room's "Investigate in Sentinel" opens the incident of the case the analyst works, and the
// incident list when they work none (2026-11-08 review: it opened whichever incident came last).
import { describe, it, expect } from "vitest";
import type { Ev } from "./types";
import { workingCaseEid } from "./projections";
import { incidentForCase, type TeamRoomIncident } from "./useSentinelIncidents";
import { at, sampleEvents } from "./__fixtures__/handoffEvents";

const incidents: TeamRoomIncident[] = [
  { id: "inc-a", number: 101, title: "Rule incident on WS-FIN-2847", hosts: ["ws-fin-2847"], eventIds: ["e9"] },
  { id: "inc-b", number: 102, title: "The escalated log", hosts: ["ws-fin-2847"], eventIds: ["e1", "e2"] },
  { id: "inc-c", number: 103, title: "Latest incident", hosts: ["srv-1"], eventIds: ["e7"] },
];

describe("workingCaseEid", () => {
  it("is the open case the analyst took last", () => {
    expect(workingCaseEid(sampleEvents(), "u2")).toBe("e1");
  });
  it("is null for someone who owns no case, or once the case is resolved or bounced", () => {
    expect(workingCaseEid(sampleEvents(), "u1")).toBeNull();
    expect(workingCaseEid(sampleEvents(), null)).toBeNull();
    const resolved: Ev[] = [...sampleEvents(), { seq: 40, type: "escalation.resolved", actor_id: "u2", role: "t2", payload: { event_id: "e1" }, occurred_at: at(40) }];
    expect(workingCaseEid(resolved, "u2")).toBeNull();
    const bounced: Ev[] = [...sampleEvents(), { seq: 40, type: "escalation.bounced", actor_id: "u2", role: "t2", payload: { event_id: "e1", reason: "x" }, occurred_at: at(40) }];
    expect(workingCaseEid(bounced, "u2")).toBeNull();
  });
});

describe("incidentForCase", () => {
  it("opens the incident holding the case's log, before any other on the same host", () => {
    expect(incidentForCase(incidents, { eventId: "e1", host: "WS-FIN-2847" })).toBe("inc-b");
  });
  it("falls back to the host's incident, and to none (the list), never to the latest incident", () => {
    expect(incidentForCase(incidents, { eventId: "zzz", host: "SRV-1.corp.example" })).toBe("inc-c");
    expect(incidentForCase(incidents, {})).toBeUndefined();
  });
});
