// Team Training is limited per organization (Tal, 2026-10-18).
import { describe, it, expect } from "vitest";
import { sanitizeTeamLimit, quotaOf, quotaExhausted, quotaMessage } from "./quota";

describe("team exercise quota", () => {
  it("reads the super-admin's field: blank = unlimited, a whole number otherwise", () => {
    expect(sanitizeTeamLimit(undefined)).toBeUndefined();
    expect(sanitizeTeamLimit("")).toBeNull();
    expect(sanitizeTeamLimit(null)).toBeNull();
    expect(sanitizeTeamLimit(0)).toBe(0);
    expect(sanitizeTeamLimit("5")).toBe(5);
    expect(sanitizeTeamLimit(-1)).toBe("invalid");
    expect(sanitizeTeamLimit(2.5)).toBe("invalid");
    expect(sanitizeTeamLimit("abc")).toBe("invalid");
  });
  it("counts what is left; unlimited never runs out", () => {
    expect(quotaOf(null, 40)).toEqual({ limit: null, used: 40, remaining: null });
    expect(quotaExhausted(quotaOf(null, 40))).toBe(false);
    expect(quotaOf(5, 3).remaining).toBe(2);
    expect(quotaExhausted(quotaOf(5, 5))).toBe(true);
    expect(quotaExhausted(quotaOf(5, 7))).toBe(true);
    expect(quotaExhausted(quotaOf(0, 0))).toBe(true);
  });
  it("says why, in the user's terms", () => {
    expect(quotaMessage(quotaOf(0, 0))).toMatch(/isn't part of your organization's plan/);
    expect(quotaMessage(quotaOf(5, 5))).toMatch(/used all 5/);
  });
});
