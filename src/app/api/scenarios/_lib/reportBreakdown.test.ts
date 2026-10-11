import { describe, it, expect } from "vitest";
import { scoreScenarioReport } from "@/lib/scenarios/reportScoring";
import {
  buildReportBreakdown, DEPTH_FULL_WORDS, REASONING_FULL_WORDS, REASONING_PARTIAL_WORDS,
} from "./reportBreakdown";

const EVENTS = [
  { id: "e1", raw: { src_ip: "10.20.7.33", RemoteAddressIP4: "203.0.113.45", SHA256HashData: "a".repeat(64) } },
];
const IOCS = [{ value: "203.0.113.45" }, { value: "a".repeat(64) }, { value: "svc_backup" }];
const words = (n: number, w = "alpha") => Array.from({ length: n }, (_, i) => `${w}${i}`).join(" ");

function run(o: {
  verdict?: string | null; verdictReason?: string; analystNotes?: string;
  indicators?: { value: string }[]; revealKey?: boolean; attackKind?: string;
}) {
  const verdict = o.verdict === undefined ? "tp" : o.verdict;
  const verdictReason = o.verdictReason ?? words(25, "r");
  const analystNotes = o.analystNotes ?? words(160);
  const indicators = o.indicators ?? [];
  const scored = scoreScenarioReport({
    verdict, verdictReason, analystNotes, indicators,
    iocs: IOCS, events: EVENTS, attackKind: o.attackKind ?? "malicious",
  });
  return { scored, b: buildReportBreakdown({ scored, verdict, verdictReason, indicators, iocs: IOCS, revealKey: o.revealKey ?? true }) };
}

describe("buildReportBreakdown (#16)", () => {
  it("item points are exactly the rubric's — the score formula is only exposed, never changed", () => {
    const { scored, b } = run({ indicators: [{ value: "203.0.113.45" }] });
    const byKey = Object.fromEntries(b.items.map(i => [i.key, i.points]));
    expect(byKey).toEqual(scored.reportRubric);
    expect(b.items.map(i => i.max)).toEqual([25, 25, 30, 20]);
  });

  it("the 80/100 case explains the missing 20 points specifically", () => {
    // Correct verdict, long notes, full reasoning, 1 of 3 key indicators → 80.
    const { scored, b } = run({ indicators: [{ value: "203.0.113.45" }] });
    expect(scored.reportScore).toBe(80);
    const ev = b.items.find(i => i.key === "evidence")!;
    expect(ev.points).toBe(10);
    expect(ev.detail).toContain("1/3 key indicators cited");
    expect(b.missedIndicators).toEqual(["a".repeat(64), "svc_backup"]);
    expect(b.improvements.some(l => l.includes("svc_backup"))).toBe(true);
    expect(b.summary).toContain("evidence 10/30");
    expect(b.summary).not.toMatch(/thin/i);
  });

  it("does NOT reveal missed key indicators unless the attempt is genuine", () => {
    const { b } = run({ indicators: [{ value: "203.0.113.45" }], revealKey: false });
    expect(b.missedIndicators).toBeNull();
    const all = [...b.improvements, b.summary, ...b.items.map(i => i.detail)].join(" ");
    expect(all).not.toContain("svc_backup");
    expect(all).not.toContain("a".repeat(64));
    expect(all).toContain("1 of 3 key indicators");
  });

  it("a wrong verdict is called out and the cap is flagged", () => {
    const { scored, b } = run({ verdict: "fp" });
    expect(scored.reportScore).toBeLessThanOrEqual(49);
    expect(b.cappedByVerdict).toBe(true);
    expect(b.items[0].detail).toMatch(/called it benign; the evidence shows malicious/);
    expect(b.improvements[0]).toMatch(/Re-check the verdict/);
  });

  it("names fabricated indicators (the learner's own input) and caps evidence", () => {
    const { b } = run({ analystNotes: words(160) + " the C2 was 198.51.100.77" });
    expect(b.fabricatedValues).toEqual(["198.51.100.77"]);
    expect(b.items.find(i => i.key === "evidence")!.detail).toMatch(/Capped/);
    expect(b.improvements.some(l => l.includes("198.51.100.77"))).toBe(true);
  });

  it("short reasoning and a thin write-up produce concrete, thresholded advice", () => {
    const { b } = run({ verdictReason: words(5, "r"), analystNotes: words(10) });
    expect(b.items.find(i => i.key === "reasoning")!.detail).toContain("5 words");
    expect(b.items.find(i => i.key === "depth")!.detail).toContain(`${DEPTH_FULL_WORDS}+`);
    expect(b.improvements.some(l => l.startsWith("Justify the verdict"))).toBe(true);
    expect(b.improvements.some(l => l.startsWith("Write up the full chain"))).toBe(true);
  });

  it("the thresholds quoted in the advice match the scoring maths", () => {
    const at = (n: number) => run({ verdictReason: words(n, "r") }).scored.reportRubric.reasoning;
    expect(at(REASONING_FULL_WORDS)).toBe(20);
    expect(at(REASONING_FULL_WORDS - 1)).toBe(12);
    expect(at(REASONING_PARTIAL_WORDS)).toBe(12);
    expect(at(REASONING_PARTIAL_WORDS - 1)).toBe(0);
    // depth counts notes + reasoning words together
    const depth = (notes: number) => run({ verdictReason: "", analystNotes: words(notes) }).scored.reportRubric.depth;
    expect(depth(DEPTH_FULL_WORDS)).toBe(25);
    expect(depth(DEPTH_FULL_WORDS - 1)).toBe(18);
  });

  it("a complete report has no gaps", () => {
    const { scored, b } = run({ indicators: IOCS });
    expect(scored.reportScore).toBe(100);
    expect(b.improvements).toEqual([]);
    expect(b.missedIndicators).toEqual([]);
    expect(b.summary).toContain("Nothing major missed");
  });
});
