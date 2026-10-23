import { describe, it, expect } from "vitest";
import { teamSessionClosed } from "./edrLock";

describe("team EDR lock", () => {
  it("closes when the session ended, was debriefed, or the analyst lost access", () => {
    expect(teamSessionClosed(200, "ended")).toBe(true);
    expect(teamSessionClosed(200, "debriefed")).toBe(true);
    expect(teamSessionClosed(403, null)).toBe(true);
    expect(teamSessionClosed(404, null)).toBe(true);
  });
  it("stays open while the exercise runs or is paused, and on a transient error", () => {
    expect(teamSessionClosed(200, "running")).toBe(false);
    expect(teamSessionClosed(200, "paused")).toBe(false);
    expect(teamSessionClosed(200, "lobby")).toBe(false);
    expect(teamSessionClosed(500, null)).toBe(false);
    expect(teamSessionClosed(0, null)).toBe(false);
  });
});
