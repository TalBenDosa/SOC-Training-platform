// Verifies the response-clock (SLA) pause: while the analyst is investigating
// (report drawer open OR EDR console in play — both feed the same
// `isInvestigating` flag), the SLA countdown must FREEZE, then resume when they
// come back. This is the exact behaviour requested for EDR investigation. Runs
// the REAL useLiveEvents hook under fake timers (no JSX so vitest's *.test.ts
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

describe("SLA response clock pause during investigation", () => {
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

  it("freezes the countdown while investigating, and resumes after", () => {
    act(() => { root.render(React.createElement(Harness)); });

    // Advance past FIRST_PHASE_DELAY (120-180s) so the attack's first phase lands
    // and the SLA countdown arms.
    act(() => { vi.advanceTimersByTime(181_000); });
    const started = latest!.attackTimerSeconds;
    expect(started).not.toBeNull();
    expect(started!).toBeGreaterThan(600); // SLA_SECONDS = 900

    // Running: 6 one-second ticks decrement it.
    act(() => { vi.advanceTimersByTime(6_000); });
    const afterRunning = latest!.attackTimerSeconds!;
    expect(afterRunning).toBe(started! - 6);

    // Analyst opens EDR / report → investigating. The clock must FREEZE.
    investigating = true;
    act(() => { vi.advanceTimersByTime(30_000); });
    expect(latest!.attackTimerSeconds).toBe(afterRunning); // unchanged across 30s

    // Back from investigating → the clock resumes counting down.
    investigating = false;
    act(() => { vi.advanceTimersByTime(4_000); });
    expect(latest!.attackTimerSeconds).toBe(afterRunning - 4);
  });
});
