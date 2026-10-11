// QA phase 7, E-18: AI errors are classified by HTTP status, not by substrings
// ("generate".includes("rate") made every failure look like a rate limit).
import { describe, it, expect } from "vitest";
import { isRateLimitError, aiFailureMessage, AiBudgetError } from "./errors";

const err = (status: number | undefined, message = "x", extra: Record<string, unknown> = {}) =>
  Object.assign(new Error(message), { status, ...extra });

describe("isRateLimitError", () => {
  it("only a real 429 that isn't an exhausted quota", () => {
    expect(isRateLimitError(err(429))).toBe(true);
    expect(isRateLimitError(err(429, "quota", { code: "insufficient_quota" }))).toBe(false);
    expect(isRateLimitError(err(500, "failed to generate an accurate moderate answer"))).toBe(false);
    expect(isRateLimitError(new Error("429 in the text but no status"))).toBe(false);
  });
});

describe("aiFailureMessage", () => {
  it("never echoes the provider's text", () => {
    const leaky = err(400, "Invalid request: org-abc123 key sk-proj-XXXX");
    expect(aiFailureMessage(leaky)).not.toMatch(/sk-|org-abc/);
    expect(aiFailureMessage(err(401))).toMatch(/temporarily unavailable/);
    expect(aiFailureMessage(err(429))).toMatch(/busy/);
    expect(aiFailureMessage(err(429, "q", { code: "insufficient_quota" }))).toMatch(/usage limit/);
    expect(aiFailureMessage(new AiBudgetError(), "Lesson generation")).toMatch(/Lesson generation took too long/);
    expect(aiFailureMessage(err(503))).toMatch(/provider had an error/);
  });
});
