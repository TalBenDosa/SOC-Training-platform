// Verifies the response-clock pause: the clock is now an ELAPSED timer that
// counts UP from 0 (not a countdown, and never a fail). While the analyst is
// investigating (report drawer open OR EDR console in play — both feed the same
// `isInvestigating` flag), the clock must FREEZE, then resume counting up when
// they come back. Same pause guarantee as before, opposite direction. Runs the
// REAL useLiveEvents hook under fake timers (no JSX so vitest's *.test.ts
// include picks it up).
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import React from "react";
import { createRoot, type Root } from "react-dom/client";
import { act } from "react";
import { useLiveEvents, type LiveEventsApi } from "./useLiveEvents";
import type { AttackStory } from "./attackStories";
import type { TelemetryEvent } from "@/lib/sim/types";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true;

const ev = (id: string): TelemetryEvent => ({
  id, ts: new Date().toISOString(), source: "edr", event_type: "process_create",
  severity: "high", mitre_technique: "T1059.001", hostname: "WKS-01",
  description: `malicious activity ${id}`,
  process: { name: "powershell.exe", pid: 1000, parent_name: "winword.exe", parent_pid: 500, cmdline: "powershell -enc AAAA" },
} as unknown as TelemetryEvent);

const STORY: AttackStory = {
  id: "test-story", title: "Test Endpoint Attack", complexity: "core",
  mitre: ["T1059.001"], events: [ev("a"), ev("b"), ev("c"), ev("d")],
} as unknown as AttackStory;

const POOL: TelemetryEvent[] = [ev("noise1"), ev("noise2")];

// Module flag the harness's isInvestigating() closure reads at call time —
// flipping it mirrors the analyst opening the EDR console / report drawer.
let investigating = false;
let latest: LiveEventsApi | null = null;

function Harness() {
  latest = useLiveEvents({
    eventPool: POOL, story: STORY, intervalMs: 90_000, autoStart: true,
    isInvestigating: () => investigating,
  });
  return null;
}

describe("response clock (counts up) pause during investigation", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    investigating = false;
    latest = null;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });
  afterEach(() => {
    act(() => { root.unmount(); });
    container.remove();
    vi.useRealTimers();
  });

  it("counts up while running, freezes while investigating, and resumes after", () => {
    act(() => { root.render(React.createElement(Harness)); });

    // Advance past FIRST_PHASE_DELAY (120-180s) so the attack's first phase lands
    // and the response clock arms at 0 and starts counting UP.
    act(() => { vi.advanceTimersByTime(181_000); });
    const started = latest!.attackTimerSeconds;
    expect(started).not.toBeNull();
    expect(started!).toBeGreaterThanOrEqual(0); // elapsed, not a countdown

    // Running: 6 one-second ticks INCREMENT it.
    act(() => { vi.advanceTimersByTime(6_000); });
    const afterRunning = latest!.attackTimerSeconds!;
    expect(afterRunning).toBe(started! + 6);

    // Analyst opens EDR / report → investigating. The clock must FREEZE.
    investigating = true;
    act(() => { vi.advanceTimersByTime(30_000); });
    expect(latest!.attackTimerSeconds).toBe(afterRunning); // unchanged across 30s

    // Back from investigating → the clock resumes counting UP.
    investigating = false;
    act(() => { vi.advanceTimersByTime(4_000); });
    expect(latest!.attackTimerSeconds).toBe(afterRunning + 4);

    // The clock itself never fires the debrief — the attack is still unfolding
    // here and, either way, catching it would cancel the debrief.
    expect(latest!.missedAttack).toBe(false);
  });

  it("fires a positive Learning-Moment debrief after the generous grace when uncaught & not investigating", () => {
    act(() => { root.render(React.createElement(Harness)); });

    // Let the whole story inject (all phases complete within ~420s).
    act(() => { vi.advanceTimersByTime(500_000); });
    expect(latest!.missedAttack).toBe(false);     // debrief scheduled, grace not elapsed
    expect(latest!.missedIncident).toBeNull();

    // Advance past MISS_DEBRIEF_GRACE_MS (540s) — uncaught, not investigating.
    act(() => { vi.advanceTimersByTime(600_000); });
    expect(latest!.missedAttack).toBe(true);
    // …and it carries the teaching payload (what it was + technique + tell).
    expect(latest!.missedIncident).not.toBeNull();
    expect(latest!.missedIncident!.title).toBe(STORY.title);
    expect(latest!.missedIncident!.techniques).toContain("T1059.001");
    expect(typeof latest!.missedIncident!.tell).toBe("string");
    expect(latest!.missedIncident!.tell.length).toBeGreaterThan(0);
  });

  it("does NOT fire the debrief while investigating, then fires after they return", () => {
    act(() => { root.render(React.createElement(Harness)); });

    // Complete the story (the debrief is now scheduled ~540s out).
    act(() => { vi.advanceTimersByTime(500_000); });

    // Analyst is deep in an investigation as the grace elapses → never interrupt.
    investigating = true;
    act(() => { vi.advanceTimersByTime(600_000); }); // past the grace, but deferred
    expect(latest!.missedAttack).toBe(false);
    expect(latest!.missedIncident).toBeNull();

    // They finish investigating → the next ~60s re-check surfaces the debrief.
    investigating = false;
    act(() => { vi.advanceTimersByTime(61_000); });
    expect(latest!.missedAttack).toBe(true);
    expect(latest!.missedIncident).not.toBeNull();
  });
});
