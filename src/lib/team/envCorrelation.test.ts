// What the admin enters is what the feed shows (2026-10-18 report): in a named-organization exercise
// every log comes from a product or platform the admin chose. Sentinel (an Azure service), Purview,
// Guardium, Defender for Identity, a web proxy or Claude Enterprise must never appear unless chosen.
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { buildTeamTimeline, teamStoryFilter, teamStoryPool } from "./buildTimeline";
import { parseTenant, TENANT_TEMPLATE, type Tenant } from "./tenant";
import { teamLoad } from "./load";
import type { TeamEnv } from "./environment";
import type { Stack } from "@/lib/logs/native/stack";

const tenant = parseTenant("acme") as Tenant;
const team = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
const vendorsOf = (env: TeamEnv, stack: Stack) => {
  const out = new Set<string>();
  for (const d of ["easy", "medium", "hard"] as const) for (const seed of ["s1", "s2", "s3", "s4"]) {
    const tl = buildTeamTimeline(TENANT_TEMPLATE, d, seed, [null, null], teamLoad(d, team), stack, tenant, env, { bonus: true });
    for (const e of tl) { const b = (e as { body?: { vendor?: string } }).body; if (b?.vendor) out.add(b.vendor); }
  }
  return [...out];
};

// Each case builds 12 full timelines: slow under a parallel full-suite run.
describe("named organization: the feed only carries what the admin chose", { timeout: 120_000 }, () => {
  it("no Azure and only non-Microsoft products: no Microsoft cloud or unchosen tool in the feed", () => {
    const stack: Stack = { edr: "crowdstrike", firewall: "fortigate", vpn: "zscaler_zpa", idp: "okta", collab: "google_workspace", email_security: "proofpoint", dns: "infoblox" };
    const vendors = vendorsOf({ platforms: ["aws"], industry: "general" }, stack);
    const allowed = /^(CrowdStrike Falcon|Fortinet FortiGate|Zscaler Private Access|Okta|Google Workspace|Proofpoint TAP|Infoblox|AWS CloudTrail|AWS CloudWatch|AWS GuardDuty|Windows Security|Microsoft Sysmon|Windows DHCP Server|ServiceNow ITSM)$/;
    expect(vendors.filter(v => !allowed.test(v))).toEqual([]);
  });

  it("no Azure with the default Microsoft products: Entra ID and M365 yes, Sentinel and other unchosen tools no", () => {
    const vendors = vendorsOf({ platforms: ["linux"], industry: "general" }, {});
    expect(vendors).toContain("Microsoft Entra ID");
    // Defender for Identity comes WITH the default EDR here (Defender for Endpoint, storyEventChosen).
    expect(vendors.filter(v => /sentinel|azure|purview|guardium|zscaler internet|claude|waf/i.test(v))).toEqual([]);
  });

  it("Defender for Identity never appears when the chosen EDR is not Defender for Endpoint", () => {
    const vendors = vendorsOf({ platforms: ["linux"], industry: "general" }, { edr: "crowdstrike" });
    expect(vendors.filter(v => /defender for identity/i.test(v))).toEqual([]);
  });

  it("with Azure the Sentinel false-positive analytics come back", () => {
    expect(vendorsOf({ platforms: ["azure", "linux"], industry: "general" }, {})).toContain("Microsoft Sentinel");
  });

  it("the Session Builder still offers attacks for a non-Microsoft, no-Azure organization", () => {
    const stack: Stack = { edr: "crowdstrike", idp: "okta", collab: "google_workspace" };
    const env: TeamEnv = { platforms: [], industry: "general" };
    const offered = (d: "easy" | "medium" | "hard") => teamStoryPool(TENANT_TEMPLATE, d, env, stack).filter(teamStoryFilter(TENANT_TEMPLATE, stack, env)).length;
    expect(offered("easy")).toBeGreaterThanOrEqual(3);
    expect(offered("medium")).toBeGreaterThanOrEqual(3);
    expect(offered("hard")).toBeGreaterThanOrEqual(1);   // a bare environment has few advanced chains; adding platforms widens it
  });
});
