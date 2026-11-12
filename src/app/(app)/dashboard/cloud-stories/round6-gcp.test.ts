// Cloud round, Google Cloud (round6-gcp.ts): every family has one single-player and one Team Training variant, every
// row renders natively and validly on the companies each story lists (Cloud Audit Logs through gcp_audit), a named
// organization that picks Google Cloud is offered the team variants, and the two variants share no person or outside
// address on their attack rows.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { applyStack, nativeView, NATIVE_SOURCES, stackFor } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import { teamStoryPool } from "@/lib/team/buildTimeline";
import { TENANT_TEMPLATE } from "@/lib/team/tenant";
import type { TeamEnv } from "@/lib/team/environment";
import type { TelemetryEvent } from "@/lib/sim/types";
import { CLOUD_R6_GCP_STORIES } from "./round6-gcp";

const FAMILIES = ["cloud-gcp-setiampolicy-owner", "cloud-gcp-bucket-public", "cloud-gcp-actas-deploy", "cloud-gcp-startup-script", "cloud-gcp-bigquery-export", "cloud-gcp-logging-tamper"];
const story = (id: string) => ATTACK_STORIES.find(s => s.id === id)!;
const render = (id: string, c: string) => instantiateStory(story(id), companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, c), feedCompanyProfile(c).architecture?.edr, c, () => 0.3, { seed: `g6-${id}-${c}` });
const attack = (evs: TelemetryEvent[]) => evs.filter(e => !e.is_baseline && e.expected_verdict !== "fp");
const outside = (evs: TelemetryEvent[]) => new Set(attack(evs).flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && !/^10\.|^192\.168\.|^172\./.test(x)));

describe("Cloud round: Google Cloud families", () => {
  it("each family has one single-player and one Team Training variant, registered in the catalog", () => {
    expect(CLOUD_R6_GCP_STORIES).toHaveLength(12);
    for (const fam of FAMILIES) {
      const v = CLOUD_R6_GCP_STORIES.filter(s => s.family === fam);
      expect(v.map(s => s.mode).sort(), fam).toEqual(["solo", "team"]);
      for (const s of v) {
        const cat = story(s.id);
        expect(cat.family).toBe(fam);
        expect(!!cat.teamOnly, s.id).toBe(s.mode === "team");
      }
    }
  });

  for (const s of CLOUD_R6_GCP_STORIES) for (const c of s.companies) {
    it(`${s.id} renders natively and validly on ${c}`, () => {
      const out = render(s.id, c);
      const stack = stackFor(c);
      const bad: string[] = [];
      let gcp = 0, native = 0;
      for (const e of out.events) {
        const v = nativeView(applyStack(e, c, stack), c, stack);
        if (e.source === "cloud_gcp") { expect(v?.log.sourceId, e.id).toBe("gcp_audit"); gcp++; }
        if (!v) continue;
        native++;
        const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
        if (viol.length) bad.push(`${e.id} ${v.log.sourceId}: ${JSON.stringify(viol.slice(0, 2))}`);
      }
      expect(bad).toEqual([]);
      expect(gcp).toBeGreaterThanOrEqual(3);
      expect(native).toBe(out.events.length);
    });
  }

  it("a named organization on Google Cloud is offered the team variants, and not without it", () => {
    const withGcp: TeamEnv = { platforms: ["gcp"], industry: "general" };
    const without: TeamEnv = { platforms: ["azure"], industry: "general" };
    const ids = (env: TeamEnv) => new Set((["easy", "medium", "hard"] as const).flatMap(d => teamStoryPool(TENANT_TEMPLATE, d, env).map(s => s.id)));
    const on = ids(withGcp), off = ids(without);
    for (const s of CLOUD_R6_GCP_STORIES.filter(x => x.mode === "team")) {
      expect(on.has(s.id), s.id).toBe(true);
      expect(off.has(s.id), s.id).toBe(false);
    }
    for (const s of CLOUD_R6_GCP_STORIES.filter(x => x.mode === "solo")) expect(on.has(s.id), s.id).toBe(false);
  });

  it("the two variants of a family share no person and no outside address on their attack rows", () => {
    for (const fam of FAMILIES) {
      const [a, b] = CLOUD_R6_GCP_STORIES.filter(s => s.family === fam);
      const users = (evs: TelemetryEvent[]) => new Set(evs.map(e => e.user_email).filter(Boolean));
      const both = <T,>(x: Set<T>, y: Set<T>) => [...x].filter(v => y.has(v));
      expect(both(users(a.events), users(b.events)), fam).toEqual([]);
      expect(both(outside(a.events), outside(b.events)), fam).toEqual([]);
    }
  });

  it("no em dashes, documentation addresses only, a benign look-alike and a description on every story", () => {
    for (const s of CLOUD_R6_GCP_STORIES) {
      expect(JSON.stringify(s).includes(String.fromCharCode(0x2014)), s.id).toBe(false);
      for (const ip of outside(s.events)) expect(ip, `${s.id} ${ip}`).toMatch(/^(203\.0\.113|198\.51\.100|192\.0\.2)\./);
      expect(s.events.some(e => e.expected_verdict === "fp" && !!e.fp_explanation), s.id).toBe(true);
      for (const e of s.events) expect((e.description ?? "").length, e.id).toBeGreaterThan(20);
    }
  });
});
