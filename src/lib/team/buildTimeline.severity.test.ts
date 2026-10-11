import { describe, expect, it } from "vitest";
import { buildTeamTimeline } from "./buildTimeline";
import { enrichEvent, LEVEL_BANDS } from "@/app/(app)/dashboard/liveEventEnrich";
import type { TelemetryEvent } from "@/lib/sim/types";

// Owner rule (2026-10-06, from the team-training review): the severity a player sees — and so the
// 3-15 rule level — must match what the event really is. Raw attack rows used to be collapsed to
// informational, so an event that demanded escalation showed rule level 1.
describe("team feed severity and rule level", () => {
  const seeds = ["sev-a", "sev-b", "sev-c"];
  const feed = seeds.flatMap(seed =>
    buildTeamTimeline("nexacorp", "medium", seed).filter(e => e.channel === "feed"));

  it("shows the authored severity on every row that has one", () => {
    const withAuthored = feed.filter(e => typeof (e.answer as Record<string, unknown>)?.authored_severity === "string");
    expect(withAuthored.length).toBeGreaterThan(20);
    for (const e of withAuthored) {
      expect((e.body as Record<string, unknown>).severity).toBe((e.answer as Record<string, unknown>).authored_severity);
    }
  });

  it("never puts a true-positive high/critical row below rule level 10", () => {
    const tp = feed.filter(e => {
      const a = e.answer as Record<string, unknown>;
      return a?.expected_verdict === "tp" && ["high", "critical"].includes(String((e.body as Record<string, unknown>).severity));
    });
    expect(tp.length).toBeGreaterThan(0);
    for (const e of tp) {
      const live = enrichEvent(e.body as unknown as TelemetryEvent, 1);
      expect(live.ruleLevel).toBeGreaterThanOrEqual(10);
    }
  });

  it("keeps every rule level on the 3-15 scale, inside its severity band", () => {
    for (const e of feed) {
      const body = e.body as unknown as TelemetryEvent;
      const live = enrichEvent(body, 1);
      const [lo, hi] = LEVEL_BANDS[body.severity ?? "informational"] ?? LEVEL_BANDS.informational;
      expect(live.ruleLevel).toBeGreaterThanOrEqual(3);
      expect(live.ruleLevel).toBeLessThanOrEqual(15);
      expect(live.ruleLevel).toBeGreaterThanOrEqual(lo);
      expect(live.ruleLevel).toBeLessThanOrEqual(hi);
    }
  });
});
