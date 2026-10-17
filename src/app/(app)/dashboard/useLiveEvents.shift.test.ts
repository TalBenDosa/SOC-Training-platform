// Shift lifecycle of the REAL hook under fake timers:
//  - QA-DASH-10: the incident opens on the first ATTACK row, not on warm-up baseline rows;
//  - QA-DASH-2/9: the incident only carries events already injected (no future phase);
//  - QA-DASH-5: reset() mid-shift (even after the story fully injected) re-arms a
//    catchable attack from phase 0;
//  - QA-DASH-8: endSession() reads live counters, saves once per shift, counts a
//    missed attack in fnCount, and skips an idle shift.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import type { AttackStory } from "./attackStories";
import type { TelemetryEvent } from "@/lib/sim/types";

const saved: unknown[] = [];
vi.mock("@/lib/storage/progress", () => ({
  appendDashboardSession: (r: unknown) => { saved.push(r); },
}));

import { useLiveEvents, type LiveEventsApi } from "./useLiveEvents";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const ev = (id: string, baseline = false): TelemetryEvent => ({
  id, ts: new Date().toISOString(), source: "edr", event_type: "process_create",
  severity: baseline ? "low" : "high", mitre_technique: baseline ? undefined : "T1059.001", hostname: "WKS-01",
  description: `${baseline ? "context" : "malicious"} activity ${id}`,
  ...(baseline ? { is_baseline: true, expected_verdict: "informational" } : {}),
  process: { name: "powershell.exe", pid: 1000, parent_name: "winword.exe", parent_pid: 500, cmdline: `powershell ${id}` },
} as unknown as TelemetryEvent);

// With Math.random = 0.5 every phase is 2 events: [b1,b2] [s1,s2] [s3,s4].
const STORY: AttackStory = {
  id: "shift-story", title: "Shift Story", complexity: "core", mitre: ["T1059.001"],
  events: [ev("b1", true), ev("b2", true), ev("s1"), ev("s2"), ev("s3"), ev("s4")],
} as unknown as AttackStory;
const POOL: TelemetryEvent[] = [ev("noise1"), ev("noise2"), ev("noise3")];

let latest: LiveEventsApi | null = null;
function Harness() {
  latest = useLiveEvents({ eventPool: POOL, intervalMs: 3_600_000, autoStart: false, isInvestigating: () => false });
  return null;
}
const PHASE1 = 151_000;   // first phase due at 150 s (random = 0.5)
const GAP    = 181_000;   // later phases 180 s apart

describe("live shift lifecycle", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    saved.length = 0;
    latest = null;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
    act(() => { root.render(React.createElement(Harness)); });
    act(() => { latest!.reset(POOL, STORY); });
  });
  afterEach(() => {
    act(() => { root.unmount(); });
    container.remove();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("opens the incident on the first attack row, never on warm-up baseline rows", () => {
    act(() => { vi.advanceTimersByTime(PHASE1); });
    expect(latest!.activeIncident).toBeNull();          // baseline-only phase: no incident, no clock
    expect(latest!.attackTimerSeconds).toBeNull();
    act(() => { vi.advanceTimersByTime(GAP); });
    const inc = latest!.activeIncident!;
    expect(inc).not.toBeNull();
    // Already-injected events only: the 2 baseline rows + the 2 attack rows, not s3/s4.
    expect(inc.injected.map(e => e.description)).toEqual([
      "context activity b1", "context activity b2", "malicious activity s1", "malicious activity s2",
    ]);
    expect(inc.story).toBe(STORY);
    // The incident's ids are attack rows only (baseline rows are not part of it).
    const byId = new Map(latest!.events.map(e => [e.id, e]));
    expect(inc.eventIds.every(id => !byId.get(id)?.is_baseline)).toBe(true);
  });

  it("reset() after the story fully injected re-arms a catchable attack from phase 0", () => {
    act(() => { vi.advanceTimersByTime(PHASE1 + GAP * 2); });
    expect(latest!.activeIncident?.injected.length).toBe(6);
    act(() => { latest!.reset(); });
    expect(latest!.activeIncident).toBeNull();
    act(() => { vi.advanceTimersByTime(PHASE1 + GAP); });
    const inc = latest!.activeIncident!;
    expect(inc).not.toBeNull();
    expect(inc.injected).toHaveLength(4);               // restarted from phase 0
    act(() => { latest!.markCaught(inc.eventIds[0]); });
    expect(latest!.attacksCaughtCount).toBe(1);
  });

  it("endSession reads same-tick counters, saves once per shift, and skips idle shifts", () => {
    expect(latest!.endSession()).toBeNull();            // nothing happened yet
    act(() => { vi.advanceTimersByTime(PHASE1 + GAP); });
    const inc = latest!.activeIncident!;
    let rec: ReturnType<LiveEventsApi["endSession"]> = null;
    act(() => {
      latest!.markCaught(inc.eventIds[0]);
      latest!.addXp(120);
      latest!.addXp(250);                                // mission bonus in the same tick
      rec = latest!.endSession();
    });
    expect(rec).not.toBeNull();
    expect(rec!.xpEarned).toBe(370);
    expect(rec!.attacksCaughtCount).toBe(1);
    expect(rec!.attacksPresentedCount).toBe(1);
    expect(saved).toHaveLength(1);
    expect(latest!.endSession()).toBeNull();            // same shift: not saved twice
    expect(saved).toHaveLength(1);
    act(() => { latest!.reset(POOL, STORY); });
    act(() => { latest!.recordEventOpened(); });
    expect(latest!.endSession()).not.toBeNull();        // a new shift saves again
    expect(saved).toHaveLength(2);
  });

  it("counts a missed attack in fnCount when the debrief fires", () => {
    act(() => { vi.advanceTimersByTime(PHASE1 + GAP * 2); });  // whole story in, uncaught
    act(() => { vi.advanceTimersByTime(600_000); });           // past the 9-min grace
    expect(latest!.missedAttack).toBe(true);
    expect(latest!.fnCount).toBe(1);
    const rec = latest!.endSession();
    expect(rec!.fnCount).toBe(1);
    expect(rec!.detectRate).toBe(0);
  });
});
