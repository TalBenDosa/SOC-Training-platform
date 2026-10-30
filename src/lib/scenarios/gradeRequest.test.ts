import { describe, expect, it } from "vitest";
import { parseGradeRequest } from "./gradeRequest";

const valid = {
  answers: { q1: "a", q2: ["b", "c"] },
  verdict: "tp",
  verdictReason: "Encoded PowerShell from a Word child process.",
  analystNotes: "Notes.",
  indicators: [{ type: "ip", value: "203.0.113.7", id: "client-uuid" }],
  timeTaken: 412,
  iocTagged: 3,
};

describe("parseGradeRequest", () => {
  it("accepts what the scenario client sends", () => {
    const r = parseGradeRequest(valid);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.verdict).toBe("tp");
      expect(r.data.indicators[0].value).toBe("203.0.113.7");
    }
  });

  it("defaults the optional text fields", () => {
    const r = parseGradeRequest({ answers: {}, verdict: "fp" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.data.verdictReason).toBe("");
      expect(r.data.analystNotes).toBe("");
      expect(r.data.indicators).toEqual([]);
    }
  });

  // The verdict oracle: a body with only a verdict used to be scored, and the
  // response said whether that verdict was right.
  it("rejects a verdict-only probe", () => {
    expect(parseGradeRequest({ verdict: "tp" }).ok).toBe(false);
  });

  it("rejects a missing or free-form verdict", () => {
    expect(parseGradeRequest({ answers: {} }).ok).toBe(false);
    expect(parseGradeRequest({ answers: {}, verdict: "malicious" }).ok).toBe(false);
    expect(parseGradeRequest({ answers: {}, verdict: null }).ok).toBe(false);
  });

  it("rejects non-object bodies", () => {
    for (const b of [null, "x", 42, [], undefined]) expect(parseGradeRequest(b).ok).toBe(false);
  });

  it("rejects wrongly-typed fields instead of coercing them", () => {
    expect(parseGradeRequest({ ...valid, verdictReason: 5 }).ok).toBe(false);
    expect(parseGradeRequest({ ...valid, indicators: "x" }).ok).toBe(false);
    expect(parseGradeRequest({ ...valid, answers: { q1: 1 } }).ok).toBe(false);
  });

  it("bounds payload size", () => {
    expect(parseGradeRequest({ ...valid, analystNotes: "a".repeat(10_001) }).ok).toBe(false);
    expect(parseGradeRequest({ ...valid, indicators: Array(201).fill({ type: "ip", value: "1.1.1.1" }) }).ok).toBe(false);
    const many = Object.fromEntries(Array.from({ length: 101 }, (_, i) => [`q${i}`, "a"]));
    expect(parseGradeRequest({ ...valid, answers: many }).ok).toBe(false);
  });

  it("names the failing field", () => {
    const r = parseGradeRequest({ ...valid, verdict: "maybe" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/verdict/);
  });
});
