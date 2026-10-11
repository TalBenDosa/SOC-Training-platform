// Within one story a workstation has one IP: the EDR record's local address equals the
// firewall's source address for that host (the analyst's first EDR ↔ firewall pivot).
import { describe, it, expect } from "vitest";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { applyStack, nativeView, storyHonoursLocks, storyFitsStack } from "./index";
import { PRODUCT_LABEL, type Stack } from "./stack";
import type { TelemetryEvent } from "@/lib/sim/types";

const RUNS: [string, TelemetryEvent[], Stack][] = [
  ["nexacorp", BENIGN_EVENTS, { edr: "crowdstrike", firewall: "fortigate" }],
  ["medcore", COMPANY_EVENTS.medcore, {}],
  ["quantumbank", COMPANY_EVENTS.quantumbank, { edr: "sentinelone", firewall: "paloalto" }],
  ["globallogis", COMPANY_EVENTS.globallogis, { edr: "mde", firewall: "checkpoint" }],
];
// Where each EDR record states the sensor host's own address.
const HOST_IP_PATHS: Record<string, string[]> = {
  crowdstrike: ["LocalAddressIP4", "aip_local", "device.local_ip"],
  sentinelone: ["agentRealtimeInfo.agentIpV4", "endpoint.ip", "agentDetectionInfo.agentIpV4"],
  mde: ["properties.LocalIP"],
};
const get = (o: unknown, path: string): unknown => path.split(".").reduce<unknown>((v, k) => (v && typeof v === "object" ? (v as Record<string, unknown>)[k] : undefined), o);

describe("one IP per host within a story", () => {
  for (const [company, pool, stack] of RUNS) {
    it(`${company} ${JSON.stringify(stack)}`, () => {
      const problems = new Set<string>();
      const edr = (stack.edr && PRODUCT_LABEL[stack.edr]) || COMPANY_PROFILES.find(c => c.id === company)?.architecture.edr;
      const chosen = Object.keys(stack).length > 0;
      for (const diff of ["easy", "medium", "hard"] as const) for (const s of storiesForCompany(company, diff)) {
        const evs = (instantiateStory(s, pool, edr, company).events ?? []).map(e => applyStack(e, company, stack));
        if (!(chosen ? storyFitsStack(evs, company, stack) : storyHonoursLocks(evs, company))) continue;
        const fwIp = new Map<string, string>();
        for (const e of evs) if (e.source === "firewall" && e.hostname && e.src_ip && /^(10|192\.168|172)\./.test(e.src_ip)) fwIp.set(e.hostname, e.src_ip);
        for (const e of evs) {
          if (e.source !== "edr" || !e.hostname || !fwIp.has(e.hostname)) continue;
          const v = nativeView(e, company, stack);
          if (!v) continue;
          for (const p of HOST_IP_PATHS[v.log.sourceId] ?? []) {
            const ip = get(v.log.record, p);
            if (typeof ip === "string" && /^(10|192\.168|172)\./.test(ip) && ip !== fwIp.get(e.hostname)) {
              problems.add(`${company} ${s.id} ${e.id} ${e.hostname}: ${v.log.sourceId}.${p}=${ip} but firewall src=${fwIp.get(e.hostname)}`);
            }
          }
        }
      }
      expect([...problems].slice(0, 20)).toEqual([]);
    });
  }
});
