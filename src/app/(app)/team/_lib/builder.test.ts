import { describe, it, expect } from "vitest";
import { builderStatus, filterCandidates, looksLikeEmail, matchesCandidate, MAX_INVITES, type Candidate } from "./builder";

const M: Candidate[] = [
  { user_id: "u1", display_name: "Dana Levi", handle: "dana_l", role: "student" },
  { user_id: "u2", display_name: "Omer Cohen", handle: "omerc", role: "student" },
  { user_id: "u3", display_name: null, handle: "night_owl", role: "instructor" },
  { user_id: "u4", display_name: null, handle: null, role: "student" },
];
const base = { rosterLoading: false, rosterError: null, rosterCount: M.length, orgName: "Cyber College", picked: {} };

describe("Session Builder search (#18)", () => {
  it("matches name or handle, case-insensitively, with or without @", () => {
    expect(matchesCandidate(M[0], "dana")).toBe(true);
    expect(matchesCandidate(M[0], "LEVI")).toBe(true);
    expect(matchesCandidate(M[1], "@omer")).toBe(true);
    expect(matchesCandidate(M[2], "owl")).toBe(true);
    expect(matchesCandidate(M[1], "dana")).toBe(false);
    expect(matchesCandidate(M[3], "x")).toBe(false);
    expect(matchesCandidate(M[3], "   ")).toBe(true);   // empty query shows everyone
  });

  it("keeps already-picked members visible whatever the query", () => {
    const out = filterCandidates(M, "omer", { u1: "t1" });
    expect(out.map(m => m.user_id)).toEqual(["u1", "u2"]);
  });

  it("an e-mail query shows only the server-resolved match (the list has no addresses)", () => {
    expect(looksLikeEmail("dana@college.test")).toBe(true);
    expect(looksLikeEmail("dana@")).toBe(false);
    expect(looksLikeEmail("dana")).toBe(false);
    expect(filterCandidates(M, "dana@college.test", {}, "u2").map(m => m.user_id)).toEqual(["u2"]);
    expect(filterCandidates(M, "dana@college.test", {}, null)).toEqual([]);
    expect(filterCandidates(M, "dana@college.test", { u3: "t2" }, null).map(m => m.user_id)).toEqual(["u3"]);
  });
});

describe("Create & open lobby — why it is disabled (#18)", () => {
  it("while the roster loads it says so (never a false 'no members')", () => {
    const s = builderStatus({ ...base, rosterLoading: true, rosterCount: 0 });
    expect(s.canCreate).toBe(false);
    expect(s.blocker).toMatch(/Loading the members of Cyber College/);
  });

  it("empty org → tells staff to add students first", () => {
    const s = builderStatus({ ...base, rosterCount: 0 });
    expect(s.canCreate).toBe(false);
    expect(s.blocker).toMatch(/Nobody else in Cyber College/);
  });

  it("a roster load error is surfaced, not hidden", () => {
    const s = builderStatus({ ...base, rosterError: "Organisation admin access required." });
    expect(s.canCreate).toBe(false);
    expect(s.blocker).toMatch(/Organisation admin access required/);
  });

  it("nobody picked → explains that selecting a member unlocks it", () => {
    const s = builderStatus(base);
    expect(s.canCreate).toBe(false);
    expect(s.blocker).toMatch(/Select at least one member/);
    expect(s.warnings).toEqual([]);
  });

  it("over the server's invite cap → blocks instead of silently dropping invitees", () => {
    const picked = Object.fromEntries(Array.from({ length: MAX_INVITES + 2 }, (_, i) => [`x${i}`, "t1"]));
    const s = builderStatus({ ...base, rosterCount: 20, picked });
    expect(s.canCreate).toBe(false);
    expect(s.blocker).toMatch(/Remove 2/);
  });

  it("a picked team enables the button; T1/T2 gaps are warnings, not blockers", () => {
    expect(builderStatus({ ...base, picked: { u1: "t1", u2: "t2" } })).toEqual({ canCreate: true, blocker: null, warnings: [] });
    const noT1 = builderStatus({ ...base, picked: { u1: "t2" } });
    expect(noT1.canCreate).toBe(true);
    expect(noT1.warnings[0]).toMatch(/No Tier-1/);
    const noT2 = builderStatus({ ...base, picked: { u1: "t1", u2: "mgr" } });
    expect(noT2.canCreate).toBe(true);
    expect(noT2.warnings[0]).toMatch(/No Tier-2 or Tier-3/);
    expect(builderStatus({ ...base, picked: { u1: "t1", u2: "t3" } }).warnings).toEqual([]);
  });
});
