// QA phase 7, E-16 / E-23: route segments decode once; non-UUID ids are 404s.
import { describe, it, expect } from "vitest";
import { paramOf, hasBadUuidSegment } from "./params";
import { asObject } from "./body";

const U = "0b6f1d2e-3c4a-4b5c-8d9e-0f1a2b3c4d5e";

describe("paramOf", () => {
  it("never throws on a stray %", () => {
    expect(paramOf("%")).toBe("%");
    expect(paramOf("a%20b")).toBe("a b");
  });
});

describe("hasBadUuidSegment", () => {
  it.each([
    [`/api/team/sessions/${U}/start`, false],
    [`/api/team/sessions/abc/start`, true],
    [`/api/team/sessions/${U}`, false],
    [`/api/feedback/x'--/reply`, true],
    [`/api/superadmin/orgs/${U}/invites/nope/resend`, true],
    [`/api/superadmin/orgs/${U}/members/${U}/sign-in-email`, false],
    [`/api/org/media/123/url`, true],
    [`/api/rooms/soc-101/tasks/t1/submit`, false],   // slugs, not UUID routes
    [`/api/team/sessions`, false],
  ])("%s → %s", (p, bad) => expect(hasBadUuidSegment(p)).toBe(bad));
});

describe("asObject", () => {
  it("null / arrays / scalars read as {}", () => {
    expect(asObject(null)).toEqual({});
    expect(asObject([1])).toEqual({});
    expect(asObject("x")).toEqual({});
    expect(asObject({ a: 1 })).toEqual({ a: 1 });
  });
});
