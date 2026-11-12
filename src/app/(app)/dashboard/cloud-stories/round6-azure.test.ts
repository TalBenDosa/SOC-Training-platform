// Cloud round, Azure (round6-azure.ts): every row renders natively and validates on every company the story lists,
// the team variants stay inside an XDR (Sentinel-only) session's products, and the single-player and Team Training
// variants of a family share no person or outside address.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { applyStack, nativeView, NATIVE_SOURCES, stackFor } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import { NOT_SENTINEL, stackForConsole } from "@/lib/team/investigationConsole";
import type { TelemetryEvent } from "@/lib/sim/types";
import { CLOUD_R6_AZURE_STORIES } from "./round6-azure";

const XDR = stackForConsole({}, "sentinel");
const FAMILIES = ["cloud-azure-device-code", "cloud-azure-vm-run-command", "cloud-azure-automation-persistence", "cloud-azure-federation-backdoor", "cloud-azure-function-publish-profile"];
const story = (id: string) => ATTACK_STORIES.find(s => s.id === id)!;
const render = (id: string, c: string) => instantiateStory(story(id), companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, c), feedCompanyProfile(c).architecture?.edr, c, () => 0.3, { seed: `r6az-${id}-${c}` });
/**
 * Entra directory-audit operations the native Entra module does not render yet (src/lib/logs/native/sources/
 * _identity-common.ts identityFacts has no action for them): the trust changes of the federation family. Until the
 * module learns them these rows keep their legacy view; remove an entry here once it renders.
 */
const PENDING_ENTRA_OPS = new Set<string>();
const pending = (e: TelemetryEvent) => PENDING_ENTRA_OPS.has(String((e.raw ?? {})["azure.auditlogs.operationName"] ?? ""));
const outside = (evs: TelemetryEvent[]) => new Set(evs.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && !/^10\.|^192\.168\.|^172\./.test(x)));

describe("Cloud round: Azure families", () => {
  it("each family has one single-player and one Team Training variant, registered in the catalog", () => {
    expect(CLOUD_R6_AZURE_STORIES).toHaveLength(10);
    for (const fam of FAMILIES) {
      const v = CLOUD_R6_AZURE_STORIES.filter(s => s.family === fam);
      expect(v.map(s => s.mode).sort(), fam).toEqual(["solo", "team"]);
      for (const s of v) {
        const cat = story(s.id);
        expect(cat.family).toBe(fam);
        expect(!!cat.teamOnly, s.id).toBe(s.mode === "team");
        expect(s.events.length, s.id).toBeGreaterThanOrEqual(9);
        expect(s.events.some(e => e.expected_verdict === "fp"), `${s.id} benign look-alike`).toBe(true);
      }
    }
  });

  for (const s of CLOUD_R6_AZURE_STORIES) for (const c of s.companies) {
    it(`${s.id} renders natively and validly on ${c}`, () => {
      const out = render(s.id, c);
      const stack = stackFor(c);
      const bad: string[] = [];
      let native = 0;
      const missing: string[] = [];
      for (const e of out.events) {
        const v = nativeView(applyStack(e, c, stack), c, stack);
        if (!v) { if (!pending(e) && e.source !== "soar") missing.push(e.id); continue; }
        native++;
        const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
        if (viol.length) bad.push(`${e.id} ${v.log.sourceId}: ${JSON.stringify(viol.slice(0, 2))}`);
      }
      expect(bad).toEqual([]);
      expect(missing, "rows with no native record").toEqual([]);
      expect(native, "most rows render natively").toBeGreaterThan(out.events.filter(e => !pending(e)).length * 0.85);
    });
  }

  it("team variants stay inside an XDR session's products", () => {
    for (const s of CLOUD_R6_AZURE_STORIES.filter(x => x.mode === "team")) for (const c of s.companies) {
      const foreign = render(s.id, c).events.map(e => nativeView(applyStack(e, c, XDR), c, XDR)?.log.sourceId).filter(id => id && NOT_SENTINEL.has(id));
      expect(foreign, `${s.id} ${c}`).toEqual([]);
    }
  });

  it("the two variants of a family share no person or outside address", () => {
    for (const fam of FAMILIES) {
      const [a, b] = CLOUD_R6_AZURE_STORIES.filter(s => s.family === fam);
      const users = (evs: TelemetryEvent[]) => new Set(evs.map(e => e.user_email).filter(Boolean));
      const both = <T,>(x: Set<T>, y: Set<T>) => [...x].filter(v => y.has(v));
      expect(both(users(a.events), users(b.events)), fam).toEqual([]);
      expect(both(outside(a.events), outside(b.events)).filter(ip => ip !== "192.0.2.150"), fam).toEqual([]);
    }
  });

  it("no em dashes, documentation addresses only, and every row is described", () => {
    for (const s of CLOUD_R6_AZURE_STORIES) {
      expect(JSON.stringify(s).includes(String.fromCharCode(0x2014)), s.id).toBe(false);
      for (const ip of outside(s.events)) expect(ip, `${s.id} ${ip}`).toMatch(/^(203\.0\.113|198\.51\.100|192\.0\.2)\./);
      for (const e of s.events) expect((e.description ?? "").length, e.id).toBeGreaterThan(20);
    }
  });
});
