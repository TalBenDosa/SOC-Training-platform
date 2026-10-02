import { describe, it, expect } from "vitest";
import { rewriteProductText, sanitizeStack, categoryOf, coherentStack, STACK_CHOICES, type Stack } from "./stack";
import { applyStack, fitsStack, storyFitsStack, storyHonoursLocks, stackFor, nativeView } from "./index";
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

describe("vendor consistency rules (found in the vendor-choice playthrough)", () => {
  it("keeps the Windows built-in AV under a third-party EDR, spelling out 'Defender AV'", () => {
    expect(rewriteProductText("Defender AV scan started on LT-DEV-0931", "edr", "crowdstrike")).toBe("Microsoft Defender Antivirus scan started on LT-DEV-0931");
    expect(rewriteProductText("Windows Defender real-time protection disabled via registry", "edr", "sentinelone")).toBe("Windows Defender real-time protection disabled via registry");
    expect(rewriteProductText("Microsoft Defender for Endpoint isolated the host", "edr", "sophos")).toBe("Sophos Intercept X isolated the host");
  });
  it("speaks Okta's language under Okta and Entra's under Entra", () => {
    expect(rewriteProductText("signed in to SharePoint Online — Conditional Access passed, managed device", "idp", "okta"))
      .toBe("signed in to SharePoint Online — Okta sign-on policy passed, managed device");
    expect(rewriteProductText("MFA push approved in Okta Verify", "idp", "entra")).toBe("MFA push approved in Microsoft Authenticator");
    expect(rewriteProductText("Assigned Global Administrator role in Azure AD", "idp", "okta")).toBe("Assigned Super Administrator role in Okta");
    expect(rewriteProductText("A second Entra sign-in from Moscow", "idp", "okta")).toBe("A second Okta sign-in from Moscow");
    expect(rewriteProductText("Sign-in from Germany blocked by a Conditional Access policy", "idp", "okta")).toBe("Sign-in from Germany blocked by an Okta sign-on policy");
    expect(rewriteProductText("Mail opened in an Outlook client", "collab", "google_workspace")).toBe("Mail opened in a Gmail client");
  });
  it("Defender for Office 365 can't front Gmail: a Google shop's mail security is Proofpoint", () => {
    expect(coherentStack({ collab: "google_workspace", email_security: "defender_o365" }).email_security).toBe("proofpoint");
    expect(coherentStack({ collab: "m365", email_security: "defender_o365" }).email_security).toBe("defender_o365");
    expect(stackFor("nexacorp", { collab: "google_workspace" }).email_security).toBe("proofpoint");
  });
  it("a Proofpoint row carries the mail-gateway badge, not Office 365", () => {
    const ev = corpus().map(c => c.ev).find(e => categoryOf(e) === "email_security" && e.source === "o365");
    expect(ev).toBeTruthy();
    expect(applyStack(ev!, "nexacorp", { email_security: "proofpoint" }).source).toBe("email_gateway");
  });
  it("a vendor-specific story (FortiOS API bypass) is never shown as another firewall", () => {
    const st = ATTACK_STORIES.find(s => s.id === "edge-vpn-cve-exploit")!;
    expect(storyHonoursLocks(st.events, "nexacorp")).toBe(false);                       // Palo Alto shop
    expect(storyHonoursLocks(st.events, "nexacorp", { firewall: "fortigate", vpn: "fortigate_sslvpn" })).toBe(true);
    expect(storyFitsStack(st.events, "nexacorp", { firewall: "checkpoint" })).toBe(false);
    expect(storiesForCompany("nexacorp", "hard").some(s => s.id === "edge-vpn-cve-exploit")).toBe(true); // still offered where it fits
  });
  it("a Google Workspace shop's endpoints don't run Outlook / Teams / OneDrive", () => {
    const outlook = corpus().map(c => c.ev).find(e => categoryOf(e) === "edr" && /\bOutlook\b/.test(e.description ?? ""));
    expect(outlook).toBeTruthy();
    expect(fitsStack(outlook!, "nexacorp", {})).toBe(true);
    expect(fitsStack(outlook!, "nexacorp", { collab: "google_workspace" })).toBe(false);
  });
  it("names a swapped-out product on no row, whatever its category", () => {
    const ev = { id: "x", ts: "2026-10-01T08:00:00Z", source: "okta", vendor: "Okta", event_type: "auth_success", severity: 1,
      user_email: "k.taylor@nexacorp.com", description: "k.taylor signed in to SharePoint Online" } as unknown as Parameters<typeof applyStack>[0];
    expect(applyStack(ev, "nexacorp", { idp: "okta", collab: "google_workspace" }).description).toBe("k.taylor signed in to Google Drive");
  });
});
