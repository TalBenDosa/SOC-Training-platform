import { describe, it, expect } from "vitest";
import { teamIndexGate, teamRoomGate } from "./gating";

describe("team index gating (owner decision 2026-11)", () => {
  it("an org admin gets the Session Builder", () => {
    const g = teamIndexGate({ orgRole: "org_admin", orgId: "org1", isPlatformAdmin: false });
    expect(g.canCreate).toBe(true);
    expect(g.adminOnlyNote).toBeNull();
    expect(g.emptyText).toMatch(/Create one above/);
  });
  it("the platform owner gets it too", () => {
    expect(teamIndexGate({ orgRole: null, orgId: null, isPlatformAdmin: true }).canCreate).toBe(true);
  });
  it("an org instructor gets no builder and the line where the create button was", () => {
    const g = teamIndexGate({ orgRole: "instructor", orgId: "org1", isPlatformAdmin: false });
    expect(g.canCreate).toBe(false);
    expect(g.adminOnlyNote).toBe("Team exercises are run by your organization admin.");
    expect(g.emptyText).not.toMatch(/Create/);
  });
  it("a student gets neither the builder nor the note", () => {
    const g = teamIndexGate({ orgRole: "student", orgId: "org1", isPlatformAdmin: false });
    expect(g.canCreate).toBe(false);
    expect(g.adminOnlyNote).toBeNull();
    expect(g.emptyText).toMatch(/organization admin/);
  });
});

describe("team room gating (owner decision 2026-11)", () => {
  it("a team admin in the instructor seat runs the room and sends injects", () => {
    expect(teamRoomGate({ is_staff: true, role: "instructor" })).toEqual({ admin: true, runsRoom: true, canInject: true, canRunShift: true });
  });
  it("a team admin with no seat runs the room but injects only from the seat", () => {
    expect(teamRoomGate({ is_staff: true, role: null })).toEqual({ admin: true, runsRoom: true, canInject: false, canRunShift: true });
  });
  it("an org instructor holding a legacy instructor seat gets no admin control", () => {
    // The server reports such a seat as an observer; even if it did not, is_staff is false.
    expect(teamRoomGate({ is_staff: false, role: "instructor" })).toEqual({ admin: false, runsRoom: false, canInject: false, canRunShift: false });
  });
  it("an org instructor seated as t1 has a player's controls only", () => {
    expect(teamRoomGate({ is_staff: false, role: "t1" })).toEqual({ admin: false, runsRoom: false, canInject: false, canRunShift: false });
  });
  it("the trainee SOC Manager may pause and end, nothing else", () => {
    expect(teamRoomGate({ is_staff: false, role: "mgr" })).toEqual({ admin: false, runsRoom: false, canInject: false, canRunShift: true });
  });
  it("no viewer: nothing", () => {
    expect(teamRoomGate(null)).toEqual({ admin: false, runsRoom: false, canInject: false, canRunShift: false });
  });
});
