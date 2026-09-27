import { describe, it, expect } from "vitest";
import { isSafeLink, timeAgo } from "./types";

describe("isSafeLink", () => {
  it("accepts in-app paths only", () => {
    expect(isSafeLink("/learn")).toBe(true);
    expect(isSafeLink("/rooms/org-ab12cd34-x%20y")).toBe(true);
    for (const bad of [
      "//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)", "learn", "", null, 42, "/" + "a".repeat(400),
      // control characters — URL parsers strip tab/newline, turning "/\t/host" into "//host"
      "/\t/evil.example", "/\n/evil.example", "/learn\r\n", "/learn\u0000", "/x\u007F",
    ]) {
      expect(isSafeLink(bad)).toBe(false);
    }
  });
});

describe("timeAgo", () => {
  const now = Date.parse("2026-09-27T12:00:00Z");
  it("renders short relative times", () => {
    expect(timeAgo("2026-09-27T11:59:30Z", now)).toBe("just now");
    expect(timeAgo("2026-09-27T11:55:00Z", now)).toBe("5m ago");
    expect(timeAgo("2026-09-27T09:00:00Z", now)).toBe("3h ago");
    expect(timeAgo("2026-09-25T12:00:00Z", now)).toBe("2d ago");
    expect(timeAgo("2026-08-01T12:00:00Z", now)).toBe("01 Aug");
    expect(timeAgo("not a date", now)).toBe("");
  });
});
