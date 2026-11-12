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
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
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
/** Stories whose systems exist only on some companies. */
const NOT_ON: Record<string, string[]> = { "web-xxe-store-skimmer": ["medcore", "quantumbank"] };
/** What a row shows of itself before anyone reads its fields. */
const face = (e: TelemetryEvent) => ({ detection: !!e.is_detection, severity: e.severity, technique: mitreVisible(e) ? e.mitre_technique : undefined, tactic: mitreVisible(e) ? e.mitre_tactic : undefined });
const ruleOf = (e: TelemetryEvent) => [e.raw?.["waf.rule.key"], e.raw?.["waf.rule.name"]].join("|");

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
      if (NOT_ON[d.id]) expect(s!.companies, d.id).toEqual(COMPANIES.filter(c => !NOT_ON[d.id].includes(c)));
      else expect(s!.companies, `${d.id} is not locked to a company`).toBeUndefined();
      expect(storyCategory(d.id)).toBe("web");
    }
  });

  it("the single-player dashboard never picks a web story", () => {
    const ids = new Set(DEFS.map(d => d.id));
    for (const c of COMPANIES) for (const d of DIFFS) for (let i = 0; i < 60; i++) expect(ids.has(pickStoryForCompany(c, d).id)).toBe(false);
  });

  // Stories moved onto the neutral WAF on purpose (they render as the session's WAF): webshell-rce named the
  // backend server and AWS WAF in an Azure shop (2026-11-12).
  const MIGRATED_TO_NEUTRAL_WAF = new Set(["webshell-rce"]);
  it("no legacy WAF event changed its rendering: only the neutral vendor routes to a module", () => {
    for (const s of ATTACK_STORIES) if (!s.id.startsWith("web-") && !MIGRATED_TO_NEUTRAL_WAF.has(s.id)) for (const e of s.events) if (e.source === "waf") expect(categoryOf(e), e.id).toBeNull();
  });
});

for (const def of DEFS) {
  describe(def.id, () => {
    const story = ATTACK_STORIES.find(s => s.id === def.id)!;
    const cloud = needsCloudTrail(def.events);
    const companies = COMPANIES.filter(c => (!cloud || stackFor(c).cloud === "aws_cloudtrail") && !NOT_ON[def.id]?.includes(c));

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

    it("a look-alike shows the same face as its attack twin: only its fields differ", () => {
      const look = def.events.filter(e => e.expected_verdict === "fp" && e.fp_explanation);
      const attacks = def.events.filter(e => !e.is_baseline && e.expected_verdict !== "fp");
      for (const l of look) {
        const twins = attacks.filter(a => a.source === l.source && a.event_type === l.event_type && ruleOf(a) === ruleOf(l));
        expect(twins.length, `${l.id} has an attack row on the same rule`).toBeGreaterThan(0);
        expect(twins.map(face), l.id).toContainEqual(face(l));
      }
    });

    it("a WAF row that matched no rule carries no technique", () => {
      for (const e of def.events) if (e.source === "waf" && !e.raw?.["waf.rule.key"]) expect(e.mitre_technique, e.id).toBeUndefined();
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

describe("web traffic is not only the attack", () => {
  const sessions = COMPANIES.flatMap(c => DEFS.filter(d => !NOT_ON[d.id]?.includes(c)).flatMap(def => {
    const diff = DIFFS.find(x => teamStoryPool(c, x, null).some(s => s.id === def.id));
    return diff ? [{ c, def, diff }] : [];
  }));
  const isWeb = (e: { body: unknown }) => ["waf", "web_server"].includes(String((e.body as TelemetryEvent).source));

  it("every session has ordinary web rows on the story's own sites, and rule hits that are nobody's attack", () => {
    for (const { c, def, diff } of sessions) {
      const ids = new Set(def.events.map(e => e.id));
      const tl = buildTeamTimeline(c, diff, `noise-${def.id}`, def.id);
      const noise = tl.filter(e => isWeb(e) && authoredId(e).startsWith("wn_") && !ids.has(authoredId(e)));
      expect(noise.length, `${c} ${def.id}`).toBeGreaterThanOrEqual(6);
      const storySites = new Set(tl.filter(e => isWeb(e) && ids.has(authoredId(e))).map(e => (e.body as unknown as TelemetryEvent).network?.domain));
      expect(noise.some(e => storySites.has((e.body as unknown as TelemetryEvent).network?.domain)), `${c} ${def.id}`).toBe(true);
      for (const e of noise) {
        const b = e.body as unknown as TelemetryEvent;
        const v = nativeView(b, c);
        expect(v, authoredId(e)).toBeTruthy();
        expect(validateNative(v!.log, NATIVE_SOURCES[v!.log.sourceId]!.schema)).toEqual([]);
      }
    }
  }, 120_000);   // a session per web story per company

  it("a session with no web story still has them, and a rule hit among them", () => {
    for (const c of COMPANIES) {
      const tl = [0, 1, 2].flatMap(i => buildTeamTimeline(c, "medium", `plain-${i}`));
      const noise = tl.filter(e => isWeb(e) && authoredId(e).startsWith("wn_"));
      expect(noise.length, c).toBeGreaterThan(10);
      expect(noise.some(e => (e.body as unknown as TelemetryEvent).is_detection), c).toBe(true);
    }
  });

  it("a named organization without a WAF product sees no WAF noise", () => {
    const rows = buildTeamTimeline(TENANT_TEMPLATE, "medium", "noise-org", null, legacyLoad("medium"), {}, parseTenant("acme-labs") as Tenant, { platforms: ["linux"], industry: "general" });
    expect(rows.some(e => (e.body as unknown as TelemetryEvent).source === "waf")).toBe(false);
  });
});

describe("one incident agrees across products", () => {
  it("one workstation has one address in the web rows and the firewall row, on every seed", () => {
    const id = "web-stored-xss-session";
    const ids = new Set(DEFS.find(d => d.id === id)!.events.map(e => e.id));
    for (const c of COMPANIES) for (let i = 0; i < 5; i++) {
      const rows = buildTeamTimeline(c, "medium", `ip-${i}`, id).filter(e => ids.has(authoredId(e)));
      const b = (x: string) => rows.find(e => authoredId(e) === x)?.body as unknown as TelemetryEvent;
      expect(new Set(["web_xs_001", "web_xs_004", "web_xs_005"].map(x => b(x).src_ip)).size, `${c} ${i}`).toBe(1);
    }
  }, 120_000);

  it("each run of a shell is its own process, and its parent is the shell that ran it", () => {
    for (const c of ["nexacorp", "rocketstack"]) {
      const def = DEFS.find(d => d.id === "web-upload-webshell")!;
      const rows = buildTeamTimeline(c, "medium", `proc-${c}`, def.id);
      const b = (x: string) => rows.find(e => authoredId(e) === x)!.body as unknown as TelemetryEvent;
      expect(new Set(["web_up_007", "web_up_008", "web_up_010", "web_up_014"].map(x => b(x).process?.pid)).size).toBe(4);
      expect(b("web_up_015").process?.parent_pid).toBe(b("web_up_014").process?.pid);
      expect(b("web_up_012").process?.pid).toBe(b("web_up_015").process?.pid);
      expect(b("web_up_012").process?.user).toBe("www-data");
    }
  });

  it("a row's pid is the pid its native record prints, and stays so when a client re-times the row", () => {
    const def = DEFS.find(d => d.id === "web-upload-webshell")!;
    for (const c of ["nexacorp", "rocketstack"]) {
      const row = buildTeamTimeline(c, "medium", `pid-${c}`, def.id).find(e => authoredId(e) === "web_up_007")!.body as unknown as TelemetryEvent;
      const later = { ...row, ts: "2026-11-07T20:15:00.000Z" };
      for (const b of [row, later]) expect(JSON.stringify(nativeView(b, c)?.log.record)).toContain(String(row.process?.pid));
    }
  });

  it("the staff identity of a story is an IT person on every company", () => {
    for (const c of COMPANIES) for (const [id, row] of [["web-reset-poisoning", "web_rp_006"], ["web-stored-xss-session", "web_xs_005"]]) {
      const body = buildTeamTimeline(c, "medium", `who-${c}`, id).find(e => authoredId(e) === row)!.body as unknown as TelemetryEvent;
      const seat = COMPANY_ASSETS[c].seats?.it?.find(s => s.user === body.user_email?.split("@")[0]);
      expect(seat, `${c} ${row} ${body.user_email}`).toBeTruthy();
      expect(body.hostname).toBe(seat!.host);
    }
  });

  it("the WAF's access row routes to the server the origin's log names", () => {
    const def = DEFS.find(d => d.id === "web-path-traversal-config")!;
    const rows = buildTeamTimeline("nexacorp", "easy", "route", def.id);
    const b = (x: string) => rows.find(e => authoredId(e) === x)!.body as unknown as TelemetryEvent;
    const access = nativeView(b("web_pt_006"), "nexacorp")!.log.record.properties as Record<string, unknown>;
    expect(access.serverRouted).toBe(`${b("web_pt_007").dst_ip}:443`);
  });

  it("a blocked request on Azure WAF shows the row that blocked it", () => {
    const def = DEFS.find(d => d.id === "web-path-traversal-config")!;
    const row = buildTeamTimeline("nexacorp", "easy", "blocked", def.id).find(e => authoredId(e) === "web_pt_004")!.body as unknown as TelemetryEvent;
    const v = nativeView(row, "nexacorp")!;
    const p = (r: Record<string, unknown>) => r.properties as Record<string, unknown>;
    expect(p(v.log.record).action).toBe("Matched");
    expect(p(v.related![0].record).action).toBe("Blocked");
    expect(p(v.related![0].record).transactionId).toBe(p(v.log.record).transactionId);
  });

  it("one site is in one Azure WAF policy mode", () => {
    for (const def of DEFS) {
      const actions = def.events.filter(e => e.source === "waf").map(e => nativeView(applyStack(e, "nexacorp"), "nexacorp")?.log.record.properties as { action?: string; policyScopeName?: string } | undefined);
      const byListener = new Map<string, Set<string>>();
      for (const a of actions) if (a?.policyScopeName && a.action) byListener.set(a.policyScopeName, (byListener.get(a.policyScopeName) ?? new Set()).add(a.action));
      for (const [l, set] of byListener) if (set.has("Detected")) expect([...set], `${def.id} ${l}`).toEqual(["Detected"]);
    }
  });

  it("a WAF and origin row of one request are one moment", () => {
    for (const [id, a, b] of [["web-path-traversal-config", "web_pt_006", "web_pt_007"], ["web-waf-evasion-sqli", "web_wf_011", "web_wf_012"]]) {
      const c = "nexacorp", d = id === "web-path-traversal-config" ? "easy" as const : "medium" as const;
      const rows = buildTeamTimeline(c, d, `pair-${id}`, id);
      const at = (x: string) => rows.find(e => authoredId(e) === x)!.due_offset_ms;
      expect(at(b) - at(a), id).toBeGreaterThan(0);
      expect(at(b) - at(a), id).toBeLessThanOrEqual(700);
    }
  });

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
