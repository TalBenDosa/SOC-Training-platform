import { describe, it, expect } from "vitest";
import { isProgressReady } from "./progressReady";

// The #1 root cause in one table: a signed-in learner must NOT be treated as
// ready (and shown the localStorage backend's zeros) until the remote hydrate
// has landed.
describe("isProgressReady", () => {
  it("no auth backend configured → localStorage is authoritative immediately", () => {
    expect(isProgressReady({ authEnabled: false, authLoading: false, userId: null, hydrated: false })).toBe(true);
  });

  it("auth still resolving → not ready (we don't know which source to read yet)", () => {
    expect(isProgressReady({ authEnabled: true, authLoading: true, userId: null, hydrated: false })).toBe(false);
    expect(isProgressReady({ authEnabled: true, authLoading: true, userId: "u1", hydrated: false })).toBe(false);
  });

  it("guest → ready as soon as auth resolves", () => {
    expect(isProgressReady({ authEnabled: true, authLoading: false, userId: null, hydrated: false })).toBe(true);
  });

  it("signed in but remote not hydrated → NOT ready (this is where /progress used to show 0)", () => {
    expect(isProgressReady({ authEnabled: true, authLoading: false, userId: "u1", hydrated: false })).toBe(false);
  });

  it("signed in and hydrated → ready", () => {
    expect(isProgressReady({ authEnabled: true, authLoading: false, userId: "u1", hydrated: true })).toBe(true);
  });
});
