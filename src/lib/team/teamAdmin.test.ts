import { describe, it, expect } from "vitest";
import { isTeamAdmin, TEAM_ADMIN_ONLY } from "./teamAdmin";

describe("isTeamAdmin (owner decision 2026-11)", () => {
  it("an org admin of the session's org is a team admin", () => {
    expect(isTeamAdmin({ orgRole: "org_admin", orgId: "org1", isPlatformAdmin: false }, "org1")).toBe(true);
  });
  it("an org instructor is not, in their own org or any other", () => {
    expect(isTeamAdmin({ orgRole: "instructor", orgId: "org1", isPlatformAdmin: false }, "org1")).toBe(false);
    expect(isTeamAdmin({ orgRole: "instructor", orgId: "org1", isPlatformAdmin: false }, "org2")).toBe(false);
  });
  it("a student is not", () => {
    expect(isTeamAdmin({ orgRole: "student", orgId: "org1" }, "org1")).toBe(false);
  });
  it("an org admin of ANOTHER org is not", () => {
    expect(isTeamAdmin({ orgRole: "org_admin", orgId: "org2" }, "org1")).toBe(false);
  });
  it("the platform owner always is, whatever the org", () => {
    expect(isTeamAdmin({ isPlatformAdmin: true, orgRole: null, orgId: null }, "org1")).toBe(true);
    expect(isTeamAdmin({ isPlatformAdmin: true, orgRole: "student", orgId: "org9" }, null)).toBe(true);
  });
  it("fails closed: no user, no org on either side", () => {
    expect(isTeamAdmin(null, "org1")).toBe(false);
    expect(isTeamAdmin(undefined, "org1")).toBe(false);
    expect(isTeamAdmin({ orgRole: "org_admin", orgId: null }, null)).toBe(false);
    expect(isTeamAdmin({ orgRole: "org_admin", orgId: "org1" }, null)).toBe(false);
    expect(isTeamAdmin({ orgRole: "org_admin", orgId: "org1" }, "")).toBe(false);
  });
  it("the refusal line names the organization admin", () => {
    expect(TEAM_ADMIN_ONLY).toBe("Team exercises are run by your organization admin.");
  });
});
