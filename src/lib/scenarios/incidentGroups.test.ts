// Every scenario with endpoint telemetry opens in the EDR console (Tal, 2026-10-22), one case
// per host, never mixing hosts in one process tree.
import { describe, it, expect } from "vitest";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";
import { withDefaultIncidents } from "./incidentGroups";
import type { TelemetryEvent } from "@/lib/sim/types";

const ENDPOINT = new Set(["edr", "sysmon", "windows_security", "linux_audit"]);
// No process tree to walk, on purpose: an ESXi hypervisor runs no EDR sensor, and the
// help-desk MFA reset is an identity attack with a single benign endpoint line.
const NO_EDR_CASE = new Set(["esxi-ransomware", "helpdesk-mfa-reset"]);

const all = (SCENARIOS as unknown as { slug: string; build: () => { title: string; events: TelemetryEvent[] } }[])
  .map(sc => { const b = sc.build(); return { slug: sc.slug, title: b.title, events: withDefaultIncidents(b.events, sc.slug) }; });

describe("scenario EDR cases", () => {
  it("every scenario with endpoint logs has an EDR case", () => {
    const missing = all
      .filter(s => s.events.some(e => ENDPOINT.has(e.source)) && !NO_EDR_CASE.has(s.slug))
      .filter(s => buildInvestigationsFromScenario({ title: s.title, events: s.events }).length === 0)
      .map(s => s.slug);
    expect(missing).toEqual([]);
  });

  it("legacy scenarios get one case per host; authored incident ids are kept", () => {
    const usb = all.find(s => s.slug === "usb-malware-basic")!;
    expect(new Set(usb.events.map(e => e.incident_id))).toEqual(new Set(["inc:usb-malware-basic:WS-OPS-2214"]));
    const lockbit = all.find(s => s.slug === "ransomware-lockbit")!;
    const hosts = buildInvestigationsFromScenario({ title: lockbit.title, events: lockbit.events }).map(i => i.host.name);
    expect(hosts.length).toBeGreaterThan(1);
    expect(new Set(hosts).size).toBe(hosts.length);
    const authored = withDefaultIncidents([{ incident_id: "inc:x:1", hostname: "A" }, { hostname: "B" }], "x");
    expect(authored.map(e => e.incident_id)).toEqual(["inc:x:1", undefined]);
  });
});
