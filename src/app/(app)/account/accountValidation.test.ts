import { describe, it, expect } from "vitest";
import {
  validateFullName,
  validateHandle,
  validatePasswordChange,
  hasForbiddenChars,
  normaliseHandle,
  RESERVED_HANDLES,
} from "./accountValidation";

describe("validateFullName", () => {
  it("accepts a normal name and trims/collapses spaces", () => {
    expect(validateFullName("  Tal   Ben  Dosa ")).toEqual({ ok: true, value: "Tal Ben Dosa" });
  });

  it("accepts Hebrew and counts code points, not UTF-16 units", () => {
    const r = validateFullName("טל");
    expect(r).toEqual({ ok: true, value: "טל" });
  });

  it("rejects too short / too long", () => {
    expect(validateFullName("a").ok).toBe(false);
    expect(validateFullName("   ").ok).toBe(false);
    expect(validateFullName("x".repeat(61)).ok).toBe(false);
    expect(validateFullName("x".repeat(60)).ok).toBe(true);
  });

  it("rejects names with no letters", () => {
    expect(validateFullName("!!!").ok).toBe(false);
    expect(validateFullName("12345").ok).toBe(false);
  });

  it("rejects control, zero-width and bidi-override characters", () => {
    expect(validateFullName("Tal\nAdmin").ok).toBe(false);
    expect(validateFullName("Tal\u0000").ok).toBe(false);
    expect(validateFullName("Ta​l").ok).toBe(false);
    expect(validateFullName("‮nimda").ok).toBe(false);
    expect(validateFullName("Tal⁦x⁩").ok).toBe(false);
  });

  it("rejects non-strings", () => {
    expect(validateFullName(undefined).ok).toBe(false);
    expect(validateFullName(42).ok).toBe(false);
  });
});

describe("validateHandle", () => {
  it("normalises case and whitespace", () => {
    expect(validateHandle("  NightOwl_7 ")).toEqual({ ok: true, value: "nightowl_7" });
    expect(normaliseHandle(" AbC ")).toBe("abc");
  });

  it("enforces 3–20 chars", () => {
    expect(validateHandle("ab").ok).toBe(false);
    expect(validateHandle("a".repeat(21)).ok).toBe(false);
    expect(validateHandle("abc").ok).toBe(true);
    expect(validateHandle("a".repeat(20)).ok).toBe(true);
  });

  it("allows only lowercase alnum + underscore after normalising", () => {
    expect(validateHandle("night-owl").ok).toBe(false);
    expect(validateHandle("night owl").ok).toBe(false);
    expect(validateHandle("טלטל").ok).toBe(false);
    expect(validateHandle("a.b.c").ok).toBe(false);
  });

  it("rejects every reserved name (matches migration 0006)", () => {
    for (const r of RESERVED_HANDLES) {
      expect(validateHandle(r).ok).toBe(false);
      expect(validateHandle(r.toUpperCase()).ok).toBe(false);
    }
  });

  it("rejects non-strings", () => {
    expect(validateHandle(null).ok).toBe(false);
  });
});

describe("validatePasswordChange", () => {
  const good = { current: "old-password", next: "brand-new-pass", confirm: "brand-new-pass" };

  it("accepts a valid change", () => {
    expect(validatePasswordChange(good)).toEqual({
      ok: true,
      value: { current: "old-password", next: "brand-new-pass" },
    });
  });

  it("requires the current password", () => {
    const r = validatePasswordChange({ ...good, current: "" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/current password/i);
  });

  it("enforces the same minimum length as signup (8)", () => {
    const r = validatePasswordChange({ ...good, next: "short12", confirm: "short12" });
    expect(r.ok).toBe(false);
    expect(validatePasswordChange({ ...good, next: "exactly8", confirm: "exactly8" }).ok).toBe(true);
  });

  it("caps at 72 UTF-8 bytes (bcrypt limit)", () => {
    const long = "a".repeat(73);
    expect(validatePasswordChange({ ...good, next: long, confirm: long }).ok).toBe(false);
    const hebrew = "ש".repeat(37); // 74 bytes, 37 chars
    expect(validatePasswordChange({ ...good, next: hebrew, confirm: hebrew }).ok).toBe(false);
  });

  it("requires a matching confirmation", () => {
    const r = validatePasswordChange({ ...good, confirm: "something-else" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/match/i);
  });

  it("requires the new password to differ from the current one", () => {
    const r = validatePasswordChange({ current: "same-pass-1", next: "same-pass-1", confirm: "same-pass-1" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/different/i);
  });
});

describe("hasForbiddenChars", () => {
  it("ignores ordinary text in any script", () => {
    expect(hasForbiddenChars("Tal Ben-Dosa")).toBe(false);
    expect(hasForbiddenChars("טל בן דוסה")).toBe(false);
    expect(hasForbiddenChars("José Ñúñez")).toBe(false);
  });
  it("flags the BOM and C1 controls", () => {
    expect(hasForbiddenChars("﻿Tal")).toBe(true);
    expect(hasForbiddenChars("Tal\u0085")).toBe(true);
  });
});
