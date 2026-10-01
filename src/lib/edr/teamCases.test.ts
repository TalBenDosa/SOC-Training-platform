/**
 * "Investigate in EDR" in the team exercise opens the host of the case the analyst
 * clicked — not whichever host happens to be busiest in the shared team feed.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { buildTeamEdrCases } from "./teamCases";
import { hostKey } from "@/lib/team/format";
import type { TelemetryEvent } from "@/lib/sim/types";

const ENDPOINT = new Set(["edr", "sysmon", "linux_audit", "windows_security"]);
function teamFeed(company: string, difficulty: "easy" | "medium" | "hard", seed: string): TelemetryEvent[] {
  const tl = buildTeamTimeline(company, difficulty, seed, null, teamLoad(difficulty, [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }]));
  const base = Date.parse("2026-10-01T09:00:00Z");
  return tl.filter(e => e.channel === "feed").map(e => withRebasedTime(e.body as unknown as TelemetryEvent, new Date(base + e.due_offset_ms).toISOString()));
}
/** Every host in the feed that has endpoint process telemetry. */
const endpointHosts = (evs: TelemetryEvent[]) =>
  [...new Set(evs.filter(e => ENDPOINT.has(e.source) && e.hostname && e.process?.name).map(e => e.hostname!))];

describe("buildTeamEdrCases", () => {
  it.each([["nexacorp", "hard", "a"], ["quantumbank", "medium", "b"], ["medcore", "hard", "c"], ["rocketstack", "easy", "a"]] as const)(
    "%s/%s: each requested host opens a case ON THAT HOST", (co, d, seed) => {
      const evs = teamFeed(co, d, seed);
      const hosts = endpointHosts(evs);
      expect(hosts.length).toBeGreaterThan(1);       // a real team feed interleaves several hosts
      for (const h of hosts) {
        const cases = buildTeamEdrCases(evs, { sessionId: "s1", hosts: [h], description: "Escalated: encoded PowerShell" });
        expect(cases).toHaveLength(1);
        expect(hostKey(cases[0].host.name)).toBe(hostKey(h));
        expect(cases[0].title).toBe("Escalated: encoded PowerShell");
        expect(cases[0].id).toBe(`team-s1-${hostKey(h)}`);
      }
    });

  it("several hosts → one case each (the console shows its Incidents list); duplicates by short name collapse", () => {
    const evs = teamFeed("nexacorp", "hard", "a");
    const [h1, h2] = endpointHosts(evs);
    const cases = buildTeamEdrCases(evs, { sessionId: "s1", hosts: [h1, h2, h1.toLowerCase()] });
    expect(cases.map(c => hostKey(c.host.name))).toEqual([hostKey(h1), hostKey(h2)]);
  });

  it("a host with no endpoint telemetry yields no case (the room says so instead of opening another host)", () => {
    const evs = teamFeed("nexacorp", "medium", "a");
    expect(buildTeamEdrCases(evs, { sessionId: "s1", hosts: ["NO-SUCH-HOST-99"] })).toEqual([]);
  });

  it("no host in hand (header button) → one case from the whole feed, as before", () => {
    const evs = teamFeed("nexacorp", "medium", "b");
    expect(buildTeamEdrCases(evs, { sessionId: "s1", hosts: [] })).toHaveLength(1);
  });
});
