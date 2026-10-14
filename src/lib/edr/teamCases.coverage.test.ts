import { describe, it, expect, vi } from "vitest";

// buildTimeline is server-only in the app; stub the guard for the unit test.
vi.mock("server-only", () => ({}));

import { buildTeamTimeline, teamStoryPool } from "@/lib/team/buildTimeline";
import { DEFAULT_ENV } from "@/lib/team/environment";
import { buildTeamEdrCases } from "./teamCases";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * Every host that shows EDR / Sysmon rows in a team feed must open a case in the EDR console.
 * A team training (2026-10-13) hit "No endpoint (EDR/Sysmon) telemetry for WS-HR-1142": the
 * case builder only knew the pre-native raw keys, so native Sysmon (winlog.event_data.Image),
 * native SentinelOne (src.process.name), AV detections that name only the detected file, and
 * driver loads opened nothing. 137 of 830 endpoint hosts across the team feeds were dead ends.
 */
const COMPANIES = ["nexacorp", "quantumbank", "rocketstack", "medcore", "globallogis"];
const DIFFS = ["easy", "medium", "hard"] as const;

describe("team EDR: every endpoint host in the feed opens a case", () => {
  it("covers every story of every company, with and without an environment", () => {
    const dead: string[] = [];
    let checked = 0;
    for (const co of COMPANIES) {
      for (const diff of DIFFS) {
        for (const env of [null, DEFAULT_ENV]) {
          const stories = teamStoryPool(co, diff, env).map(s => s.id);
          for (const storyId of [null, ...stories]) {
            const tl = buildTeamTimeline(co, diff, `edr-cov-${co}-${diff}-${storyId ?? "auto"}`, storyId, undefined, {}, null, env);
            const evs = tl.filter(e => e.channel === "feed").map(e => e.body as unknown as TelemetryEvent);
            // A sensor-health row (the agent went offline, e.g. an encrypted ESXi guest) records
            // no process: such a host legitimately has no tree, and the page offers no EDR button.
            const sensorSilence = (e: TelemetryEvent) => e.raw?.["event.action"] === "agent_offline";
            const hosts = [...new Set(evs.filter(e => (e.source === "edr" || e.source === "sysmon") && !sensorSilence(e)).map(e => e.hostname).filter(Boolean) as string[])];
            for (const h of hosts) {
              checked++;
              if (buildTeamEdrCases(evs, { sessionId: "t", hosts: [h] }).length === 0) dead.push(`${co}/${diff}/${storyId ?? "auto"}: ${h}`);
            }
          }
        }
      }
    }
    expect(checked).toBeGreaterThan(500);
    expect(dead).toEqual([]);
  }, 600_000);
});
