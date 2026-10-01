import { describe, it, expect } from "vitest";
import { rewriteProductText, sanitizeStack, categoryOf, STACK_CHOICES, type Stack } from "./stack";
import { applyStack, fitsStack, storyFitsStack, nativeView } from "./index";
import { corpus } from "./testing/corpus";
import { ATTACK_STORIES, storiesForCompany } from "@/app/(app)/dashboard/attackStories";

describe("vendor text rewrite", () => {
  it("switches product names within the event's category only", () => {
    expect(rewriteProductText("Outlook launched cmd.exe — Defender killed it automatically", "edr", "crowdstrike"))
      .toBe("Outlook launched cmd.exe — CrowdStrike Falcon killed it automatically");
    expect(rewriteProductText("Microsoft Defender for Endpoint quarantined the file", "edr", "sentinelone"))
      .toBe("SentinelOne quarantined the file");
    expect(rewriteProductText("Palo Alto blocked the session to a C2 domain", "firewall", "fortigate"))
      .toBe("Fortinet FortiGate blocked the session to a C2 domain");
    expect(rewriteProductText("Bulk download from SharePoint via Outlook link", "collab", "google_workspace"))
      .toBe("Bulk download from Google Drive via Gmail link");
    expect(rewriteProductText("No vendor named here", "edr", "mde")).toBe("No vendor named here");
  });
  it("sanitizeStack keeps only known categories and products", () => {
    expect(sanitizeStack({ edr: "crowdstrike", firewall: "nope", idp: "okta", evil: "x" })).toEqual({ edr: "crowdstrike", idp: "okta" });
    expect(sanitizeStack("x")).toEqual({});
  });
});

describe("applyStack", () => {
  it("re-labels an event and keeps the authored original for native rendering", () => {
    const c = corpus().find(x => x.ev.source === "edr" && /defender/i.test(x.ev.vendor ?? "") && /defender/i.test(x.ev.description ?? ""))!;
    const shown = applyStack(c.ev, "nexacorp", { edr: "crowdstrike" });
    expect(shown.vendor).toBe("CrowdStrike Falcon");
    expect(shown.description).not.toMatch(/Defender/);
    const v = nativeView(shown, "nexacorp", { edr: "crowdstrike" });
    expect(v?.log.sourceId).toBe("crowdstrike");
  });
  it("Google Workspace shops drop records Google does not have", () => {
    const rule = corpus().find(x => x.ev.source === "o365" && /New-InboxRule/.test(JSON.stringify(x.ev.raw ?? {})));
    if (rule) expect(fitsStack(rule.ev, "nexacorp", { collab: "google_workspace" })).toBe(false);
  });
});

describe("attack stories per stack", () => {
  const COMBOS: [string, Stack][] = [
    ["nexacorp", {}],
    ["nexacorp", { edr: "crowdstrike", firewall: "fortigate", idp: "okta" }],
    ["medcore", { edr: "crowdstrike", firewall: "fortigate", vpn: "globalprotect" }],
    ["medcore", { edr: "sophos", firewall: "cisco_asa" }],
    ["rocketstack", { collab: "m365", idp: "entra", edr: "mde" }],
    ["globallogis", { edr: "sentinelone", firewall: "checkpoint", vpn: "zscaler_zpa", email_security: "proofpoint" }],
    ["quantumbank", { firewall: "checkpoint", vpn: "cloudflare_access", dns: "infoblox" }],
  ];
  it("every company/stack combination still offers stories at every difficulty", () => {
    for (const [companyId, stack] of COMBOS) {
      const row: string[] = [];
      for (const d of ["easy", "medium", "hard"] as const) {
        const pool = storiesForCompany(companyId, d);
        const fit = pool.filter(s => storyFitsStack(s.events, companyId, stack));
        row.push(`${d} ${fit.length}/${pool.length}`);
        expect(fit.length, `${companyId} ${JSON.stringify(stack)} ${d}`).toBeGreaterThanOrEqual(1);
      }
      console.log(`[stack] ${companyId} ${JSON.stringify(stack)}: ${row.join(" · ")}`);
    }
  });
  it("STACK_CHOICES covers every switchable category exactly once", () => {
    expect(new Set(STACK_CHOICES.map(c => c.category)).size).toBe(STACK_CHOICES.length);
    expect(ATTACK_STORIES.length).toBeGreaterThan(50);
    expect(categoryOf(corpus()[0].ev) === null || typeof categoryOf(corpus()[0].ev) === "string").toBe(true);
  });
});
