// Web application attack stories through the real Team-SOC pipeline: each story is in the Team
// Training pool of the companies whose stacks can show it, is never picked by the single-player
// dashboard, runs for a named organization, renders every step in order in native WAF and web
// server formats, keeps answer data out of public entries, and carries its benign look-alike.
import { describe, expect, it } from "vitest";
import { WEB_ENTRY_STORIES } from "@/app/(app)/dashboard/web-stories/entry";
import { WEB_ADVANCED_STORIES } from "@/app/(app)/dashboard/web-stories/advanced";
import { ATTACK_STORIES, pickStoryForCompany, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { nativeView, stackFor, storyFitsOrg, applyStack } from "@/lib/logs/native";
import { categoryOf } from "@/lib/logs/native/stack";
import { validateNative } from "@/lib/logs/native/validate";
import { NATIVE_SOURCES } from "@/lib/logs/native";
import { makeCtx } from "@/lib/logs/native/ctx";
import { techniqueById } from "@/lib/mitre/attack";
import { storyProblems, renderedStories } from "@/lib/qa/investigability";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline, teamStoryFilter, teamStoryPool, TEAM_ANSWER_FIELDS } from "./buildTimeline";
import { legacyLoad } from "./load";
import { parseTenant, type Tenant } from "./tenant";
import { DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { TENANT_TEMPLATE } from "./tenant";
import { storyCategory } from "./storyCategory";

const DEFS = [...WEB_ENTRY_STORIES, ...WEB_ADVANCED_STORIES];
const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const DASH = /[–—]/;
const authoredId = (e: { answer?: unknown }) => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "");
const needsCloudTrail = (events: TelemetryEvent[]) => events.some(e => e.source === "cloudtrail");

function emptyValues(o: unknown, path = ""): string[] {
  if (o === "") return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
}

describe("web application attack catalog", () => {
  it("has at least eight stories across all three levels, registered and team-only", () => {
    expect(DEFS.length).toBeGreaterThanOrEqual(8);
    expect(new Set(DEFS.map(d => d.complexity))).toEqual(new Set(["foundation", "core", "advanced"]));
    for (const d of DEFS) {
      const s = ATTACK_STORIES.find(x => x.id === d.id);
      expect(s, d.id).toBeTruthy();
      expect(s!.teamOnly, d.id).toBe(true);
      expect(s!.companies, `${d.id} is not locked to a company`).toBeUndefined();
      expect(storyCategory(d.id)).toBe("web");
    }
  });

  it("the single-player dashboard never picks a web story", () => {
    const ids = new Set(DEFS.map(d => d.id));
    for (const c of COMPANIES) for (const d of DIFFS) for (let i = 0; i < 60; i++) expect(ids.has(pickStoryForCompany(c, d).id)).toBe(false);
  });

  it("no legacy WAF event changed its rendering: only the neutral vendor routes to a module", () => {
    for (const s of ATTACK_STORIES) if (!s.id.startsWith("web-")) for (const e of s.events) if (e.source === "waf") expect(categoryOf(e), e.id).toBeNull();
  });
});

for (const def of DEFS) {
  describe(def.id, () => {
    const story = ATTACK_STORIES.find(s => s.id === def.id)!;
    const cloud = needsCloudTrail(def.events);
    const companies = COMPANIES.filter(c => !cloud || stackFor(c).cloud === "aws_cloudtrail");

    it("is in the Team Training pool of every company whose stack can show it", () => {
      for (const c of companies) {
        const inPool = DIFFS.some(d => storiesForCompany(c, d).some(s => s.id === def.id) && teamStoryPool(c, d, null).some(s => s.id === def.id));
        expect(inPool, c).toBe(true);
        expect(teamStoryFilter(c)(story), c).toBe(true);
      }
    });

    it("runs for a named organization with every platform, and with the default one unless it needs AWS", () => {
      const inEnv = (env: TeamEnv) => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, env);
        return DIFFS.some(d => teamStoryPool(TENANT_TEMPLATE, d, env).filter(fits).some(s => s.id === def.id));
      };
      expect(inEnv(FULL_ENV)).toBe(true);
      expect(inEnv(DEFAULT_ENV)).toBe(!cloud);
      expect(storyFitsOrg(story.events, TENANT_TEMPLATE, {})).toBe(true);
    });

    it("a named organization on AWS WAF shows it too", () => {
      const fits = teamStoryFilter(TENANT_TEMPLATE, { waf: "aws_waf" }, { platforms: ["aws", "linux"], industry: "general" });
      expect(fits(story)).toBe(true);
    });

    it("has a benign look-alike in the same shape as the attack", () => {
      const look = def.events.filter(e => e.expected_verdict === "fp" && e.fp_explanation);
      expect(look.length).toBeGreaterThan(0);
      const attacks = def.events.filter(e => !e.is_baseline && e.expected_verdict !== "fp");
      for (const l of look) expect(attacks.some(a => a.source === l.source && a.event_type === l.event_type), l.id).toBe(true);
    });

    it("is investigable: several sources in time order, a first alert, no gate problem", () => {
      expect(new Set(def.events.map(e => e.source)).size).toBeGreaterThanOrEqual(2);
      const t = def.events.map(e => Date.parse(e.ts));
      expect([...t].sort((a, b) => a - b)).toEqual(t);
      expect(def.events.some(e => e.is_detection || /waf_block/.test(e.event_type))).toBe(true);
      const r = renderedStories().find(x => x.story.id === def.id)!;
      expect(storyProblems(r)).toEqual([]);
    });

    it("every technique is in the library; text has no em or en dash", () => {
      for (const id of story.mitre) expect(techniqueById(id), id).toBeTruthy();
      for (const e of def.events) expect(DASH.test(JSON.stringify([e.description, e.fp_explanation, e.raw])), e.id).toBe(false);
      expect(DASH.test(def.title)).toBe(false);
    });

    for (const c of companies) {
      for (const d of DIFFS.filter(x => teamStoryPool(c, x, null).some(s => s.id === def.id))) {
        it(`injects complete, ordered, native logs with no answer data (${c}, ${d})`, () => {
          const tl = buildTeamTimeline(c, d, `web-${def.id}`, def.id);
          const ids = new Set(def.events.map(e => e.id));
          const rows = tl.filter(e => ids.has(authoredId(e)));
          expect(rows.length).toBe(def.events.length);
          const offs = rows.map(e => e.due_offset_ms);
          expect([...offs].sort((a, b) => a - b)).toEqual(offs);
          expect(rows.map(authoredId)).toEqual(def.events.map(e => e.id));
          for (const e of rows) {
            const body = e.body as unknown as TelemetryEvent & Record<string, unknown>;
            expect(body.raw, "every injected log carries its raw record").toBeTruthy();
            const txt = JSON.stringify(e.body);
            expect(JUNK.test(txt), `placeholder junk in ${txt.slice(0, 160)}`).toBe(false);
            expect(emptyValues(body.raw), "raw fields with empty values").toEqual([]);
            for (const f of TEAM_ANSWER_FIELDS) expect(body[f], `${f} on a public entry`).toBeUndefined();
            if (body.source === "waf" || body.source === "web_server") {
              const v = nativeView(body, c);
              expect(v, `${authoredId(e)} renders natively`).toBeTruthy();
              expect(validateNative(v!.log, NATIVE_SOURCES[v!.log.sourceId]!.schema)).toEqual([]);
              expect(JSON.stringify(v!.log.record) + (v!.log.rawLine ?? ""), "the client address is in the record").toContain(body.src_ip!);
            }
          }
        });
      }
    }
  });
}

describe("one incident agrees across products", () => {
  it("every AWS record of a story names the company's own account", () => {
    const def = DEFS.find(d => d.id === "web-ssrf-cloud-metadata")!;
    for (const c of COMPANIES.filter(x => stackFor(x).cloud === "aws_cloudtrail")) {
      const rows = buildTeamTimeline(c, "hard", `acct-${c}`, def.id).filter(e => new Set(def.events.map(x => x.id)).has(authoredId(e)));
      const text = rows.map(e => JSON.stringify(nativeView(e.body as unknown as TelemetryEvent, c)?.log.record ?? {})).join(" ");
      const accounts = new Set([...text.matchAll(/\b\d{12}\b/g)].map(m => m[0]));
      expect(accounts, c).toEqual(new Set([makeCtx(c).tenant.awsAccountId]));
    }
  });

  it("a named organization's rows carry its own name, never the template's", () => {
    const tenant = parseTenant("acme-labs") as Tenant;
    for (const def of DEFS.filter(d => !needsCloudTrail(d.events))) {
      const diff = def.complexity === "foundation" ? "easy" : def.complexity === "core" ? "medium" : "hard";
      const rows = buildTeamTimeline(TENANT_TEMPLATE, diff, `tenant-${def.id}`, def.id, legacyLoad(diff), {}, tenant, DEFAULT_ENV).filter(e => new Set(def.events.map(x => x.id)).has(authoredId(e)));
      expect(rows.length, def.id).toBe(def.events.length);
      expect(/nexacorp/i.test(JSON.stringify(rows.map(e => e.body))), def.id).toBe(false);
    }
  });

  it("a web row prints the stack's product, and a bound row stays on its server", () => {
    const shell = DEFS.find(d => d.id === "web-upload-webshell")!.events.find(e => e.source === "web_server")!;
    expect(nativeView(applyStack(shell, "nexacorp"), "nexacorp")?.log.sourceId).toBe("nginx");
    const free = DEFS.find(d => d.id === "web-path-traversal-config")!.events.find(e => e.source === "web_server")!;
    expect(nativeView(applyStack(free, "nexacorp"), "nexacorp")?.log.sourceId).toBe("iis");
    expect(nativeView(applyStack(free, "rocketstack"), "rocketstack")?.log.sourceId).toBe("nginx");
    const waf = DEFS.find(d => d.id === "web-path-traversal-config")!.events.find(e => e.source === "waf")!;
    expect(nativeView(applyStack(waf, "medcore"), "medcore")?.log.sourceId).toBe("azure_waf");
    expect(nativeView(applyStack(waf, "quantumbank"), "quantumbank")?.log.sourceId).toBe("aws_waf");
  });
});
