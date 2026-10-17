// QA-DASH-2 / QA-DASH-3: the grader's ground truth is the ACTIVE incident's attack
// events already in the feed, without baseline / decoy rows or benign process names.
import { describe, it, expect } from "vitest";
import { extractIndicators, incidentGroundTruth, isAttackEvent, isBenignProcessName } from "./groundTruth";
import type { TelemetryEvent } from "@/lib/sim/types";

const ev = (o: Partial<TelemetryEvent>): TelemetryEvent => ({
  id: o.id ?? "e", ts: "2026-10-17T10:00:00Z", source: "edr", event_type: "process_create", severity: "high", ...o,
} as TelemetryEvent);

describe("incident ground truth", () => {
  it("is empty before the attack starts", () => {
    expect(incidentGroundTruth(null)).toEqual({ realIndicators: [], storyTitle: null, storyMitre: [] });
    // An incident whose injected rows are all baseline context has nothing to grade yet.
    const base = ev({ id: "b", is_baseline: true, expected_verdict: "informational", hostname: "WKS-9" });
    expect(incidentGroundTruth({ title: "X", storyMitre: ["T1"], injected: [base] }).realIndicators).toEqual([]);
  });

  it("uses only the injected attack rows, not baseline / decoys", () => {
    const injected = [
      ev({ id: "b", is_baseline: true, src_ip: "10.9.9.9" }),
      ev({ id: "fp", expected_verdict: "fp", fp_explanation: "IT patching", src_ip: "10.8.8.8" }),
      ev({ id: "a1", src_ip: "203.0.113.7", hostname: "WKS-01", mitre_technique: "T1059.001",
        process: { name: "powershell.exe", pid: 1, parent_name: "explorer.exe", cmdline: "x" } as TelemetryEvent["process"] }),
    ];
    const gt = incidentGroundTruth({ title: "Story", storyMitre: ["T1059.001", "T1486"], injected });
    expect(gt.realIndicators).toContain("203.0.113.7");
    expect(gt.realIndicators).toContain("WKS-01");
    expect(gt.realIndicators).toContain("powershell.exe");
    expect(gt.realIndicators).not.toContain("10.9.9.9");
    expect(gt.realIndicators).not.toContain("10.8.8.8");
    // Techniques come from what was injected, not the story's future phases.
    expect(gt.storyMitre).toEqual(["T1059.001"]);
    expect(gt.storyTitle).toBe("Story");
  });

  it("drops well-known benign process names from indicators", () => {
    const names = ["explorer.exe", "chrome.exe", "OUTLOOK.EXE", "msedge.exe"];
    const out = extractIndicators(names.map((n, i) => ev({ id: `p${i}`, process: { name: n, pid: i } as TelemetryEvent["process"] })));
    expect(out).toEqual([]);
    expect(isBenignProcessName("OUTLOOK.EXE")).toBe(true);
    expect(isBenignProcessName("rundll32.exe")).toBe(false);
  });

  it("classifies attack vs context rows", () => {
    expect(isAttackEvent(ev({}))).toBe(true);
    expect(isAttackEvent(ev({ is_baseline: true }))).toBe(false);
    expect(isAttackEvent(ev({ expected_verdict: "fp" }))).toBe(false);
    expect(isAttackEvent(ev({ it_verify_result: "confirmed" }))).toBe(false);
  });
});
