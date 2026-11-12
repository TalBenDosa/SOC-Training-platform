// The XDR console stands for Microsoft Sentinel only (Tal, 2026-11-12: "it is meant to imitate Sentinel only; fit the
// scenario and the data to it; if they work with other things, use the EDR"). An XDR session runs the Microsoft
// products a Sentinel workspace holds, offers only attacks told in those records, and its feed shows no other
// vendor's world (AWS, Okta, Google Workspace, CrowdStrike, nginx); the EDR console keeps every product.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { nativeView, applyStack } from "@/lib/logs/native";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline, teamStoryFilter, teamStoryPool } from "./buildTimeline";
import { envForConsole, isXdrStack, NOT_SENTINEL, stackForConsole, XDR_PRODUCTS } from "./investigationConsole";
import { TENANT_TEMPLATE } from "./tenant";
import { PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { teamLoad } from "./load";

const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const XDR = stackForConsole({}, "sentinel");
const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "mgr" }];

describe("XDR is Microsoft Sentinel only", () => {
  it("an XDR session runs the Microsoft products and Azure only; an EDR session keeps what was chosen", () => {
    const chosen = stackForConsole({ edr: "crowdstrike", idp: "okta", collab: "google_workspace", waf: "aws_waf", web_server: "nginx", vpn: "zscaler_zpa", firewall: "fortigate" }, "sentinel");
    expect(chosen).toMatchObject({ ...XDR_PRODUCTS, firewall: "fortigate", detection_feed: "ms_graph" });
    expect(chosen.vpn).toBeUndefined();
    expect(isXdrStack(chosen)).toBe(true);
    expect(stackForConsole({ idp: "okta" }, "edr")).toEqual({ idp: "okta" });
    const env: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
    const xdrEnv = envForConsole(env, "sentinel");
    expect(xdrEnv.platforms).toContain("azure");
    expect(xdrEnv.platforms).not.toContain("aws");
    expect(xdrEnv.platforms).not.toContain("gcp");
    expect(envForConsole(env, "edr")).toBe(env);
  });

  for (const c of COMPANIES) {
    it(`every attack offered in an XDR session is told in Sentinel's own records, and so is the whole feed (${c})`, () => {
      const fits = teamStoryFilter(c, XDR);
      const offered = DIFFS.flatMap(d => teamStoryPool(c, d, null, XDR).filter(fits).map(s => ({ d, s })));
      expect(offered.length, "an XDR session still has attacks to run").toBeGreaterThan(3);
      const foreign: string[] = [];
      for (const { d, s } of offered.slice(0, 6)) {
        const feed = buildTeamTimeline(c, d, `xdr-${s.id}`, s.id, teamLoad(d, ROSTER), XDR).filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
        for (const e of feed) {
          const id = nativeView(applyStack(e, c, XDR), c, XDR)?.log.sourceId;
          if (id && NOT_SENTINEL.has(id)) foreign.push(`${s.id}: ${String((e as { id?: string }).id)} as ${id}`);
        }
      }
      expect(foreign.slice(0, 10)).toEqual([]);
    }, 300_000);
  }

  it("a named organization's XDR session offers no AWS or Google Cloud attack", () => {
    const env = envForConsole({ platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" }, "sentinel");
    const fits = teamStoryFilter(TENANT_TEMPLATE, XDR, env);
    for (const d of DIFFS) for (const s of teamStoryPool(TENANT_TEMPLATE, d, env, XDR).filter(fits)) {
      expect(s.events.some(e => e.source === "cloudtrail" || /google cloud|gcp/i.test(e.vendor ?? "")), s.id).toBe(false);
    }
  });
});
