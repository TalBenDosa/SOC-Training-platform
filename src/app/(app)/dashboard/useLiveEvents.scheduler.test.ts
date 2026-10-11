// P5-02 / P5-03 — the single-player attack scheduler. Runs the REAL hook under
// fake timers, the way the dashboard drives it (autoStart:false, then reset()).
//  - one phase chain only (reset()/startStory() + the streaming effect used to
//    arm two, so phases landed twice as fast);
//  - nothing is injected while the feed is paused;
//  - the response clock and the missed-attack debrief survive a pause.
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
  id: "sched-story", title: "Scheduler Story", complexity: "core",
  mitre: ["T1059.001"], events: [ev("s1"), ev("s2"), ev("s3"), ev("s4"), ev("s5"), ev("s6")],
} as unknown as AttackStory;
const POOL: TelemetryEvent[] = [ev("noise1"), ev("noise2"), ev("noise3")];

let latest: LiveEventsApi | null = null;
function Harness() {
  latest = useLiveEvents({ eventPool: POOL, intervalMs: 3_600_000, autoStart: false, isInvestigating: () => false });
  return null;
}
// Distinct story steps on screen (an EDR step can also get a SIEM mirror row).
const storyCount = () => new Set(latest!.events.map(e => /malicious activity (s\d)/.exec(String(e.description ?? ""))?.[1]).filter(Boolean)).size;

describe("attack scheduler", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    // Deterministic delays: every random gap lands at the same point, which is
    // exactly when a doubled chain used to fire twice.
    vi.spyOn(Math, "random").mockReturnValue(0.5);
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

  it("runs ONE phase chain after reset() — no doubled phases", () => {
    act(() => { vi.advanceTimersByTime(149_000); });
    expect(storyCount()).toBe(0);
    act(() => { vi.advanceTimersByTime(2_000); });   // the first phase is due at 150s
    const first = storyCount();
    expect(first).toBe(2);   // exactly ONE phase (2 events with random=0.5) — a doubled chain injected two
    // The next phase is 2–4 min later (180s with random=0.5) — nothing before that.
    act(() => { vi.advanceTimersByTime(170_000); });
    expect(storyCount()).toBe(first);
    act(() => { vi.advanceTimersByTime(15_000); });
    expect(storyCount()).toBeGreaterThan(first);
  });

  it("injects nothing while the feed is paused, and continues after resume", () => {
    act(() => { vi.advanceTimersByTime(151_000); });
    const before = storyCount();
    act(() => { latest!.pause(); });
    act(() => { vi.advanceTimersByTime(20 * 60_000); });
    expect(storyCount()).toBe(before);
    act(() => { latest!.resume(); });
    act(() => { vi.advanceTimersByTime(10 * 60_000); });
    expect(storyCount()).toBeGreaterThan(before);
  });

  it("the response clock pauses with the feed and keeps counting after resume", () => {
    act(() => { vi.advanceTimersByTime(151_000); });
    act(() => { vi.advanceTimersByTime(5_000); });
    const running = latest!.attackTimerSeconds!;
    expect(running).toBeGreaterThanOrEqual(5);
    act(() => { latest!.pause(); });
    act(() => { vi.advanceTimersByTime(30_000); });
    expect(latest!.attackTimerSeconds).toBe(running);          // paused, not counting
    act(() => { latest!.resume(); });
    act(() => { vi.advanceTimersByTime(4_000); });
    expect(latest!.attackTimerSeconds).toBe(running + 4);       // alive again (used to stay frozen)
  });

  it("the missed-attack debrief survives a pause and fires after resume", () => {
    // Step until the whole story is in (the debrief is scheduled from that moment).
    for (let i = 0; i < 60 && storyCount() < STORY.events.length; i++) act(() => { vi.advanceTimersByTime(30_000); });
    expect(storyCount()).toBe(STORY.events.length);
    expect(latest!.missedAttack).toBe(false);
    act(() => { latest!.pause(); });
    act(() => { vi.advanceTimersByTime(12 * 60_000); });         // grace elapses while paused → waits
    expect(latest!.missedAttack).toBe(false);
    act(() => { latest!.resume(); });
    act(() => { vi.advanceTimersByTime(70_000); });               // re-checked within a minute of resuming
    expect(latest!.missedAttack).toBe(true);
  });
});
