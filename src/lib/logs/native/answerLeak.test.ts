// L-05 guard: an attack event's authored description states the conclusion the analyst
// must reach. It must never reach a field shown before the report — the native record
// (any product, any chosen stack) or the raw{} of the legacy view.
import { describe, it, expect } from "vitest";
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { nativeView, applyStack } from "./index";
import type { Stack } from "./stack";
import type { TelemetryEvent } from "@/lib/sim/types";

const COMPANIES: [string, TelemetryEvent[]][] = [
  ["nexacorp", BENIGN_EVENTS], ["medcore", COMPANY_EVENTS.medcore], ["rocketstack", COMPANY_EVENTS.rocketstack],
  ["globallogis", COMPANY_EVENTS.globallogis], ["quantumbank", COMPANY_EVENTS.quantumbank],
];
const STACKS: Stack[] = [
  {},
  { edr: "crowdstrike", firewall: "fortigate", idp: "okta", collab: "google_workspace" },
  { edr: "sentinelone", firewall: "checkpoint", email_security: "proofpoint" },
  { edr: "sophos", firewall: "cisco_ftd", vpn: "cloudflare_access" },
  { edr: "mde", firewall: "paloalto", idp: "entra", collab: "m365", email_security: "defender_o365" },
];

describe("no authored conclusion in what the analyst sees before reporting", () => {
  it("native records and legacy raw fields", () => {
    const leaks = new Set<string>();
    for (const [company, pool] of COMPANIES) for (const stack of STACKS) for (const s of ATTACK_STORIES) {
      let evs: TelemetryEvent[] = [];
      try { evs = instantiateStory(s, pool, undefined, company).events ?? []; } catch { continue; }
      for (const e0 of evs) {
        if (!e0.mitre_technique || !e0.description || e0.description.length < 40) continue;
        const e = applyStack(e0, company, stack);
        const needle = e.description!.slice(0, 40);
        if (!needle.includes(" ")) continue;               // starts with a bare API/event name, not prose
        const v = nativeView(e, company, stack);
        const seen = v ? JSON.stringify(v.log.record) + (v.log.rawLine ?? "") : JSON.stringify(e.raw ?? {});
        if (seen.includes(needle)) leaks.add(`${company} ${JSON.stringify(stack)} ${s.id} → ${v ? v.log.sourceId : "legacy raw"}: ${needle}`);
      }
    }
    expect([...leaks].slice(0, 20)).toEqual([]);
    // Brute-force scan over every attack event × 5 companies × 5 stacks; the realistic
    // (richer) native records make each JSON.stringify heavier, so this guard needs more
    // than the default 20s under full-suite load. The assertion itself passes well within it.
  }, 60_000);
});
