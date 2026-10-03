import { describe, it, expect } from "vitest";
import { normalizeEmail, emailDomain, disposableIssue, DISPOSABLE_DOMAINS } from "./emailBlocklist";

describe("emailBlocklist", () => {
  it("blocks the alias the client hit + classic throwaways", () => {
    expect(disposableIssue("hackthebox.anatomist122@passinbox.com")).toBeTruthy();
    expect(disposableIssue("X@Mailinator.com")).toBeTruthy();       // case-insensitive
    expect(disposableIssue("  x@10minutemail.com ")).toBeTruthy();  // trims
    expect(disposableIssue("x@duck.com")).toBeTruthy();
  });
  it("allows real providers, incl. iCloud (Hide My Email must not be blocked)", () => {
    for (const d of ["gmail.com", "outlook.com", "icloud.com", "privaterelay.appleid.com", "proton.me", "walla.co.il"]) {
      expect(disposableIssue(`x@${d}`)).toBeNull();
    }
  });
  it("does not choke on malformed input", () => {
    expect(disposableIssue("")).toBeNull();
    expect(disposableIssue("no-at")).toBeNull();
    expect(disposableIssue(undefined as unknown as string)).toBeNull();
  });
  it("helpers normalize and extract the last @-domain", () => {
    expect(normalizeEmail("  A@B.COM ")).toBe("a@b.com");
    expect(emailDomain("a@b@c.com")).toBe("c.com");
  });
  it("the list is lowercase apex domains", () => {
    for (const d of DISPOSABLE_DOMAINS) expect(d).toBe(d.toLowerCase());
  });
});
