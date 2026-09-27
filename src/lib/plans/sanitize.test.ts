import { describe, it, expect } from "vitest";
import {
  cleanLine, cleanText, parseDueDate, parsePriority, sanitizeMemberIds, sanitizePlanItems, sanitizeTargets,
} from "./sanitize";
import type { PlanItemKind } from "./types";

const KNOWN = new Set(["room:intro", "room:siem-101", "scenario:phish", "lesson:soc-analyst--what-is-a-soc", "quiz:mitre-attack", "room:org-abcd1234-custom-x1y2"]);
const isKnown = (k: PlanItemKind, id: string) => KNOWN.has(`${k}:${id}`);

const G1 = "11111111-0000-4000-8000-000000000001";
const U1 = "22222222-0000-4000-8000-000000000001";
const U2 = "22222222-0000-4000-8000-000000000002";

describe("sanitizePlanItems", () => {
  it("keeps v1 rows ({kind,id}) byte-for-byte", () => {
    const v1 = [{ kind: "room", id: "intro" }, { kind: "scenario", id: "phish" }];
    expect(sanitizePlanItems(v1, isKnown)).toEqual(v1);
  });

  it("accepts the v2 kinds and org-authored ids known to the catalogue", () => {
    const out = sanitizePlanItems([
      { kind: "lesson", id: "soc-analyst--what-is-a-soc" },
      { kind: "quiz", id: "mitre-attack" },
      { kind: "room", id: "org-abcd1234-custom-x1y2" },
    ], isKnown);
    expect(out.map(i => i.kind)).toEqual(["lesson", "quiz", "room"]);
  });

  it("drops unknown ids, unknown kinds and malformed entries", () => {
    const out = sanitizePlanItems([
      { kind: "room", id: "does-not-exist" },
      { kind: "video", id: "intro" },
      { kind: "room" },
      null, "room:intro", 42,
      { kind: "room", id: "x".repeat(201) },
      { kind: "room", id: "intro" },
    ], isKnown);
    expect(out).toEqual([{ kind: "room", id: "intro" }]);
  });

  it("dedupes by kind:id keeping the first position (order is meaningful)", () => {
    const out = sanitizePlanItems([
      { kind: "room", id: "siem-101" },
      { kind: "room", id: "intro", priority: 1 },
      { kind: "room", id: "siem-101", priority: 1 },
    ], isKnown);
    expect(out).toEqual([{ kind: "room", id: "siem-101" }, { kind: "room", id: "intro", priority: 1 }]);
  });

  it("keeps a valid non-default priority and a trimmed, capped note; drops the rest", () => {
    const [a, b, c] = sanitizePlanItems([
      { kind: "room", id: "intro", priority: 3, note: "  Read section 2 first  " },
      { kind: "room", id: "siem-101", priority: 2, note: "   " },
      { kind: "scenario", id: "phish", priority: 9, note: "n".repeat(500), extra: "ignored" },
    ], isKnown);
    expect(a).toEqual({ kind: "room", id: "intro", priority: 3, note: "Read section 2 first" });
    expect(b).toEqual({ kind: "room", id: "siem-101" });
    expect(c.priority).toBeUndefined();
    expect(c.note).toHaveLength(300);
    expect(c).not.toHaveProperty("extra");
  });

  it("strips control characters from notes", () => {
    const [a] = sanitizePlanItems([{ kind: "room", id: "intro", note: "a\u0000b\u0007c\nd" }], isKnown);
    expect(a.note).toBe("abc\nd");
  });

  it("caps the number of items", () => {
    const many = Array.from({ length: 10 }, () => ({ kind: "room", id: "intro" }))
      .concat([{ kind: "room", id: "siem-101" }, { kind: "scenario", id: "phish" }]);
    expect(sanitizePlanItems(many, isKnown, 2)).toHaveLength(2);
  });

  it("returns [] for non-arrays", () => {
    expect(sanitizePlanItems({ kind: "room", id: "intro" }, isKnown)).toEqual([]);
    expect(sanitizePlanItems(null, isKnown)).toEqual([]);
  });
});

describe("sanitizeTargets", () => {
  it("keeps only this org's groups and members, deduped and lower-cased", () => {
    const out = sanitizeTargets(
      { group_ids: [G1, G1.toUpperCase(), "not-a-uuid", "33333333-0000-4000-8000-000000000009"], user_ids: [U1, U2, U1] },
      new Set([G1]),
      new Set([U1]),
    );
    expect(out).toEqual({ group_ids: [G1], user_ids: [U1] });
  });

  it("tolerates garbage input", () => {
    expect(sanitizeTargets(null, new Set([G1]), new Set([U1]))).toEqual({ group_ids: [], user_ids: [] });
    expect(sanitizeTargets({ group_ids: "x", user_ids: 7 }, new Set(), new Set())).toEqual({ group_ids: [], user_ids: [] });
  });

  it("sanitizeMemberIds applies the same membership rule", () => {
    expect(sanitizeMemberIds([U1, U2, "x"], new Set([U2]))).toEqual([U2]);
  });
});

describe("scalar parsers", () => {
  it("parsePriority accepts 1..3 (numbers or numeric strings) only", () => {
    expect(parsePriority(1)).toBe(1);
    expect(parsePriority("3")).toBe(3);
    expect(parsePriority(0)).toBe(2);
    expect(parsePriority(2.5)).toBe(2);
    expect(parsePriority("high", 1)).toBe(1);
  });

  it("parseDueDate clears on empty and rejects nonsense", () => {
    expect(parseDueDate("")).toEqual({ ok: true, value: null });
    expect(parseDueDate(null)).toEqual({ ok: true, value: null });
    expect(parseDueDate("2026-10-01")).toEqual({ ok: true, value: "2026-10-01T00:00:00.000Z" });
    expect(parseDueDate("not a date")).toEqual({ ok: false });
    expect(parseDueDate("20266-10-01")).toEqual({ ok: false });
    expect(parseDueDate({})).toEqual({ ok: false });
  });

  it("cleanLine collapses whitespace; cleanText keeps newlines", () => {
    expect(cleanLine("  Tier-1\n  analysts \t ", 80)).toBe("Tier-1 analysts");
    expect(cleanText(" a\nb ", 80)).toBe("a\nb");
    expect(cleanText(5, 80)).toBe("");
  });
});
