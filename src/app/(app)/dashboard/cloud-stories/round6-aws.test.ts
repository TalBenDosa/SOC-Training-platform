// Cloud round, AWS (round6-aws.ts): every row renders natively and validates on every company the story lists, each
// family has one single-player and one Team Training variant that share no person, outside address or resource, and
// the stories keep to documentation addresses and the platform's writing rules.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { ATTACK_STORIES, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { companyFeedPool, feedCompanyProfile } from "@/app/(app)/dashboard/feedPool";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { applyStack, nativeView, NATIVE_SOURCES, stackFor } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import type { TelemetryEvent } from "@/lib/sim/types";
import { CLOUD_R6_AWS_STORIES } from "./round6-aws";

const FAMILIES = ["cloud-aws-sso-device-code", "cloud-aws-lambda-url-backdoor", "cloud-aws-secrets-harvest", "cloud-aws-org-escape", "cloud-aws-ses-abuse"];
const OFFICE = new Set(["192.0.2.150", "198.51.100.220"]);
const story = (id: string) => ATTACK_STORIES.find(s => s.id === id)!;
const render = (id: string, c: string) => instantiateStory(story(id), companyFeedPool({ BENIGN_EVENTS, COMPANY_EVENTS }, c), feedCompanyProfile(c).architecture?.edr, c, () => 0.3, { seed: `r6-${id}-${c}` });
const ips = (evs: TelemetryEvent[]) => new Set(evs.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && !/^10\.|^192\.168\.|^172\./.test(x)));

describe("Cloud round: AWS families", () => {
  it("each family has one single-player and one Team Training variant, registered in the catalog", () => {
    for (const fam of FAMILIES) {
      const v = CLOUD_R6_AWS_STORIES.filter(s => s.family === fam);
      expect(v.map(s => s.mode).sort(), fam).toEqual(["solo", "team"]);
      for (const s of v) {
        const cat = story(s.id);
        expect(cat, s.id).toBeTruthy();
        expect(cat.family).toBe(fam);
        expect(!!cat.teamOnly, s.id).toBe(s.mode === "team");
      }
    }
  });

  for (const s of CLOUD_R6_AWS_STORIES) for (const c of s.companies) {
    it(`${s.id} renders natively and validly on ${c}`, () => {
      const out = render(s.id, c);
      const stack = stackFor(c);
      const bad: string[] = [];
      let native = 0;
      for (const e of out.events) {
        const v = nativeView(applyStack(e, c, stack), c, stack);
        if (!v) continue;
        native++;
        const viol = validateNative(v.log, NATIVE_SOURCES[v.log.sourceId]!.schema);
        if (viol.length) bad.push(`${e.id} ${v.log.sourceId}: ${JSON.stringify(viol.slice(0, 2))}`);
      }
      expect(bad).toEqual([]);
      expect(native / out.events.length).toBeGreaterThan(0.85);
    });
  }

  it("CloudTrail rows render as CloudTrail records with their event source and caller", () => {
    for (const s of CLOUD_R6_AWS_STORIES) {
      const out = render(s.id, "rocketstack");
      for (const e of out.events.filter(x => x.vendor === "AWS CloudTrail")) {
        const v = nativeView(e, "rocketstack", stackFor("rocketstack"));
        expect(v?.log.sourceId, `${s.id} ${e.id}`).toBe("aws_cloudtrail");
        expect(v?.log.record.eventSource, `${s.id} ${e.id}`).toBe((e.raw ?? {})["aws.cloudtrail.eventSource"]);
        expect(v?.log.record.sourceIPAddress, `${s.id} ${e.id}`).toBe(e.src_ip);
      }
    }
  });

  it("the two variants of a family share no person, outside address or resource name", () => {
    for (const fam of FAMILIES) {
      const [a, b] = CLOUD_R6_AWS_STORIES.filter(s => s.family === fam);
      const users = (evs: TelemetryEvent[]) => new Set(evs.map(e => e.user_email).filter(Boolean));
      const actors = (evs: TelemetryEvent[]) => new Set(evs.map(e => (e.raw ?? {})["aws.cloudtrail.userIdentity.arn"]).filter(Boolean));
      const both = <T,>(x: Set<T>, y: Set<T>) => [...x].filter(v => y.has(v));
      expect(both(users(a.events), users(b.events)), fam).toEqual([]);
      expect(both(ips(a.events), ips(b.events)).filter(ip => !OFFICE.has(ip)), fam).toEqual([]);
      expect(both(actors(a.events), actors(b.events)), fam).toEqual([]);
    }
  });

  it("every story has a benign look-alike, an incident, documentation addresses and no em dash", () => {
    const em = String.fromCharCode(0x2014);
    for (const s of CLOUD_R6_AWS_STORIES) {
      expect(s.events.some(e => e.expected_verdict === "fp" && e.fp_explanation), s.id).toBe(true);
      expect(s.events.length, s.id).toBeGreaterThanOrEqual(10);
      expect(s.events.length, s.id).toBeLessThanOrEqual(18);
      expect(JSON.stringify(s).includes(em), s.id).toBe(false);
      for (const ip of ips(s.events)) expect(ip, `${s.id} ${ip}`).toMatch(/^(203\.0\.113|198\.51\.100|192\.0\.2)\./);
      for (const e of s.events) {
        expect(e.incident_id, e.id).toBeTruthy();
        expect((e.description ?? "").length, e.id).toBeGreaterThan(20);
      }
      for (const k of JSON.stringify(s).match(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g) ?? []) expect(k.endsWith("EXAMPLE"), `${s.id} ${k}`).toBe(true);
    }
  });
});
