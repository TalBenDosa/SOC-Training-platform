import { describe, it, expect } from "vitest";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan, planFromConfig } from "./attackPlan";
import { tenantFromConfig, tenantIdentity } from "./tenant";
import { envFromConfig } from "./environment";
import { nativeView, NATIVE_SOURCES, authoredOf } from "@/lib/logs/native";
import { makeCtx } from "@/lib/logs/native/ctx";
import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * Review 2026-11-08 (Sdema exercise, FINDINGS K5): nexacorp-chain-d could not be proven a password
 * spray (two failures, one lockout, "6 more lockouts" in the answer key that no row showed, undotted
 * account names, SMB from the internet to a DC with three IPs, an FTP threat id on SMB). The story now
 * sprays the internet-published Remote Desktop server: the evidence must hold in the exercise's own
 * config, re-homed to the named organization, whatever the seed.
 */
const CONFIG = {
  env: { industry: "general", platforms: ["azure", "linux"] },
  stack: { edr: "mde", detection_feed: "ms_graph" },
  tenant: { name: "sdemagroup" },
  attacks: { bonus: true, count: 3, slots: ["nexacorp-chain-d", "ai-rag-chatbot-document-injection", "ai-helpdesk-voice-reset"] },
};
const roster = [{ role: "t1" }, { role: "t2" }, { role: "mgr" }];

function chainD(seed: string) {
  const plan = planFromConfig(CONFIG);
  const tenant = tenantFromConfig(CONFIG);
  const { timeline } = buildFittedTimeline({
    companyId: "nexacorp", difficulty: "medium", seed, slots: plan.slots, load: loadWithPlan(withShiftMinutes(teamLoad("medium", roster), 30), plan),
    stack: CONFIG.stack as never, tenant, env: envFromConfig(CONFIG), opts: { bonus: false }, roster,
  });
  const identity = tenantIdentity(tenant);
  const oid = (r: (typeof timeline)[number]) => String((r.answer as { original_id?: string })?.original_id ?? "");
  const story = timeline.filter(r => r.channel === "feed" && /^nx_d\d/.test(oid(r)));
  // The authored rows, and the spray they close: since R7 (realism phase 3) every attempt is a feed row
  // of its own (nx_d4_b01..), the accounts drawn from the organization's people (authBursts.ts).
  const rows = story.filter(r => !/_b\d+(?:__\d+)?$/.test(oid(r)));
  const byId = (n: number) => rows.find(r => oid(r).startsWith(`nx_d${n}_`))!;
  const render = (r: (typeof timeline)[number]) => nativeView(r.body as unknown as TelemetryEvent, "nexacorp", CONFIG.stack as never, identity)!.log.record as Record<string, unknown>;
  const view = (n: number) => render(byId(n));
  const burst = story.filter(r => /_b\d+(?:__\d+)?$/.test(oid(r))).map(render);
  // The domain controller's side of each attempt (4776) stays with the 4740 for the XDR tables.
  const dcSide = (NATIVE_SOURCES.windows_security!.companions!(authoredOf(byId(3).body as unknown as TelemetryEvent), makeCtx("nexacorp", identity ?? {})) ?? [])
    .map(l => l.record as Record<string, unknown>);
  return { rows, view, burst, dcSide };
}

describe("nexacorp-chain-d is provable as a password spray in the Sdema config", () => {
  for (const seed of ["sdema-1", "sdema-a", "sdema-b", "sdema-c"]) {
    it(`seed ${seed}`, () => {
      const { rows, view, burst, dcSide } = chainD(seed);
      expect(rows).toHaveLength(5);
      const fails = burst.filter(r => r.EventID === 4625);
      // 10 to 20 failures across 8 to 12 accounts in 2 to 3 minutes, all from one client.
      expect(fails.length).toBeGreaterThanOrEqual(10);
      expect(fails.length).toBeLessThanOrEqual(20);
      const accounts = new Set(fails.map(r => r.TargetUserName));
      expect(accounts.size).toBeGreaterThanOrEqual(8);
      expect(accounts.size).toBeLessThanOrEqual(12);
      const t = fails.map(r => Date.parse(String(r.TimeCreated)));
      expect((Math.max(...t) - Math.min(...t)) / 1000).toBeLessThanOrEqual(180);
      expect(new Set(fails.map(r => r.IpAddress))).toEqual(new Set(["185.220.101.45"]));
      // sAMAccountNames are the session's dotted people, the same on every row of the story.
      for (const a of accounts) expect(String(a)).toMatch(/^[a-z]+\.[a-z]+$/);
      const locked = view(3);
      expect(locked.EventID).toBe(4740);
      expect(accounts.has(locked.TargetUserName)).toBe(true);
      expect(String(locked.Computer)).toMatch(/^SRV-SDE-DC01\./);
      const lockedFails = fails.filter(r => r.TargetUserName === locked.TargetUserName);
      expect(lockedFails).toHaveLength(3);
      expect(Date.parse(String(locked.TimeCreated))).toBeGreaterThan(Math.max(...lockedFails.map(r => Date.parse(String(r.TimeCreated)))));
      expect(view(4)).toMatchObject({ EventID: 4625, TargetUserName: locked.TargetUserName, Status: "0xc0000234" });
      // The DC validated every attempt (4776) and no longer re-logs the member server's 4625s.
      expect(dcSide.filter(r => r.EventID === 4776)).toHaveLength(burst.length);
      expect(dcSide.some(r => r.EventID === 4625)).toBe(false);
      expect(new Set(dcSide.map(r => r.TargetUserName))).toEqual(new Set(burst.map(r => r.TargetUserName)));
      const success = burst.filter(r => r.EventID === 4624);
      expect(success).toHaveLength(1);
      expect(view(5)).toMatchObject({ EventID: 4624, LogonType: "10", TargetUserName: success[0].TargetUserName, IpAddress: "185.220.101.45" });
      // The exposure and the firewall's own brute-force signature (alert only: nothing was blocked).
      expect(view(1)).toMatchObject({ type: "TRAFFIC", app: "ms-rdp", dport: "3389", action: "allow", natdst: "10.10.20.31" });
      expect(view(2)).toMatchObject({ type: "THREAT", threatid: "MS-RDP Brute Force Attempt(40021)", action: "alert", natdst: "10.10.20.31" });
      // The answer key names only what the rows hold: no lockout count the feed never shows.
      const key = JSON.stringify(rows.map(r => r.answer));
      expect(key).not.toMatch(/more lockouts|SMB|40001/);
      expect(key).not.toContain("—");
    });
  }
});
