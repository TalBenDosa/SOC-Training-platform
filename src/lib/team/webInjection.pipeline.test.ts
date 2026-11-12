// The web injection round (Tal, 2026-11-12) through both engines. Every family is a parametric template
// of two or more variants that differ in app, entry, server platform and look-alike; the single-player
// dashboard deals it (unlike the first web catalog) family first, Team Training deals it with the same
// family memory, every web row renders natively and lands in the XDR table its product really fills.
import { describe, expect, it } from "vitest";
import { WEB_INJECTION_STORIES } from "@/app/(app)/dashboard/web-stories/injection";
import { ATTACK_STORIES, familyOf, pickInFamilies, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { nativeView, stackFor } from "@/lib/logs/native";
import { validateNative } from "@/lib/logs/native/validate";
import { NATIVE_SOURCES } from "@/lib/logs/native";
import { techniqueById } from "@/lib/mitre/attack";
import { mitreVisible } from "@/lib/sim/mitreVisible";
import { storyProblems, renderedStories } from "@/lib/qa/investigability";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline, teamStoryFilter, teamStoryPool, TEAM_ANSWER_FIELDS } from "./buildTimeline";
import { emptyHistory } from "./variety";
import { storyCategory } from "./storyCategory";

const DEFS = WEB_INJECTION_STORIES;
const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const DIFFS = ["easy", "medium", "hard"] as const;
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const DASH = /[–—]/;
const authoredId = (e: { answer?: unknown }) => String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "");
const face = (e: TelemetryEvent) => ({ detection: !!e.is_detection, severity: e.severity, technique: mitreVisible(e) ? e.mitre_technique : undefined, tactic: mitreVisible(e) ? e.mitre_tactic : undefined });
const ruleOf = (e: TelemetryEvent) => [e.raw?.["waf.rule.key"], e.raw?.["waf.rule.name"]].join("|");
const families = () => { const m = new Map<string, typeof DEFS>(); for (const d of DEFS) m.set(d.family!, [...(m.get(d.family!) ?? []), d]); return m; };
const sitesOf = (evs: TelemetryEvent[]) => new Set(evs.filter(e => e.source === "waf" || e.source === "web_server").map(e => e.network?.domain));
const pathsOf = (evs: TelemetryEvent[]) => new Set(evs.filter(e => e.source === "waf" || e.source === "web_server").map(e => e.network?.url?.replace(/^https:\/\/[^/]+/, "").split("?")[0]));
/** Companies a story can run at in either engine. */
const fitting = (id: string) => COMPANIES.filter(c => DIFFS.some(d => storiesForCompany(c, d).some(s => s.id === id)));
const WEB_TABLES = new Set(["AWSWAF", "AGWFirewallLogs", "AGWAccessLogs", "W3CIISLog", "NGINX_CL"]);

function emptyValues(o: unknown, path = ""): string[] {
  if (o === "") return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
}

describe("web injection round: catalog", () => {
  it("every story is registered for both engines, in a family of two or more different variants", () => {
    expect(DEFS.length).toBeGreaterThanOrEqual(2);
    for (const d of DEFS) {
      const s = ATTACK_STORIES.find(x => x.id === d.id);
      expect(s, d.id).toBeTruthy();
      expect(s!.teamOnly, `${d.id} is dealt in the single-player dashboard too`).toBeFalsy();
      expect(s!.family, d.id).toBe(d.family);
      expect(d.id.startsWith("web-inj-"), d.id).toBe(true);
      expect(storyCategory(d.id)).toBe("web");
    }
    for (const [fam, vs] of families()) {
      expect(vs.length, fam).toBeGreaterThanOrEqual(2);
      // Variants are different incidents: another site and another way in, never the same plot renamed.
      for (let i = 0; i < vs.length; i++) for (let j = i + 1; j < vs.length; j++) {
        const [a, b] = [vs[i], vs[j]];
        expect([...sitesOf(a.events)].filter(x => sitesOf(b.events).has(x)), `${a.id} / ${b.id} share a site`).toEqual([]);
        expect([...pathsOf(a.events)].filter(x => pathsOf(b.events).has(x)), `${a.id} / ${b.id} share an entry path`).toEqual([]);
        expect(a.title).not.toBe(b.title);
      }
    }
  });

  it("each story fits at least two companies, and its family is dealt there in the single-player dashboard", () => {
    for (const d of DEFS) expect(fitting(d.id).length, d.id).toBeGreaterThanOrEqual(2);
    for (const [fam, vs] of families()) {
      const anywhere = COMPANIES.some(c => DIFFS.some(df => storiesForCompany(c, df, true).some(s => familyOf(s) === fam)));
      expect(anywhere, fam).toBe(true);
      void vs;
    }
  });

  it("a family is drawn as often as a single story, whatever its number of variants", () => {
    const pool = [{ id: "a" }, { id: "b" }, { id: "v1", family: "f" }, { id: "v2", family: "f" }, { id: "v3", family: "f" }];
    let x = 0; const rnd = () => ((x = (x * 9301 + 49297) % 233280) / 233280);
    const n: Record<string, number> = { a: 0, b: 0, f: 0 };
    for (let i = 0; i < 6000; i++) n[familyOf(pickInFamilies(pool, rnd))]++;
    for (const k of Object.keys(n)) expect(n[k] / 6000, k).toBeGreaterThan(0.28);
    // No families: the plain draw, one random number per pick.
    let calls = 0; const counted = () => { calls++; return 0.5; };
    pickInFamilies([{ id: "a" }, { id: "b" }], counted);
    expect(calls).toBe(1);
  });

  it("a Team session that met one variant waits before dealing its sibling", () => {
    const [fam, vs] = [...families()][0];
    const c = fitting(vs[0].id)[0];
    const d = DIFFS.find(x => teamStoryPool(c, x, null).some(s => s.id === vs[0].id))!;
    const history = { ...emptyHistory(), stories: { [vs[0].id]: 1 } };
    for (const seed of ["fam-1", "fam-2", "fam-3", "fam-4", "fam-5", "fam-6"]) {
      let picked: string[] = [];
      buildTeamTimeline(c, d, seed, null, undefined, {}, null, null, { history, onVariety: r => { picked = r.stories; } });
      expect(picked.some(id => ATTACK_STORIES.find(s => s.id === id)?.family === fam), `${seed}: ${picked}`).toBe(false);
    }
  });
});

for (const def of DEFS) {
  describe(def.id, () => {
    const story = ATTACK_STORIES.find(s => s.id === def.id)!;
    const companies = fitting(def.id);

    it("is in the Team Training pool of every company it fits", () => {
      for (const c of companies) {
        expect(DIFFS.some(d => teamStoryPool(c, d, null).some(s => s.id === def.id)), c).toBe(true);
        expect(teamStoryFilter(c)(story), c).toBe(true);
      }
    });

    it("has a benign look-alike that shows the same face as an attack row", () => {
      const look = def.events.filter(e => e.expected_verdict === "fp" && e.fp_explanation);
      expect(look.length).toBeGreaterThan(0);
      const attacks = def.events.filter(e => !e.is_baseline && e.expected_verdict !== "fp");
      for (const l of look) {
        const twins = attacks.filter(a => a.source === l.source && a.event_type === l.event_type && ruleOf(a) === ruleOf(l));
        expect(twins.length, `${l.id} has an attack row of its kind`).toBeGreaterThan(0);
        expect(twins.map(face), l.id).toContainEqual(face(l));
      }
    });

    it("a WAF row that matched no rule carries no technique", () => {
      for (const e of def.events) if (e.source === "waf" && !e.raw?.["waf.rule.key"]) expect(e.mitre_technique, e.id).toBeUndefined();
    });

    it("is investigable: several sources in time order, a first alert, no gate problem", () => {
      expect(new Set(def.events.map(e => e.source)).size).toBeGreaterThanOrEqual(3);
      const t = def.events.map(e => Date.parse(e.ts));
      expect([...t].sort((a, b) => a - b)).toEqual(t);
      expect(def.events.some(e => e.is_detection)).toBe(true);
      const r = renderedStories().find(x => x.story.id === def.id)!;
      expect(storyProblems(r)).toEqual([]);
    });

    it("every technique is in the library; text has no em or en dash; ids are its own", () => {
      for (const id of story.mitre) expect(techniqueById(id), id).toBeTruthy();
      for (const e of def.events) expect(DASH.test(JSON.stringify([e.description, e.fp_explanation, e.raw])), e.id).toBe(false);
      expect(DASH.test(def.title)).toBe(false);
      const ids = def.events.map(e => e.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    for (const c of companies) {
      it(`Team: complete, ordered, native, no answer data, every web row in its own XDR table (${c})`, () => {
        const d = DIFFS.find(x => teamStoryPool(c, x, null).some(s => s.id === def.id))!;
        const tl = buildTeamTimeline(c, d, `inj-${def.id}`, def.id);
        const ids = new Set(def.events.map(e => e.id));
        const rows = tl.filter(e => ids.has(authoredId(e)));
        expect(rows.length).toBe(def.events.length);
        expect(rows.map(authoredId)).toEqual(def.events.map(e => e.id));
        const bodies = rows.map(e => e.body as unknown as TelemetryEvent & Record<string, unknown>);
        for (const body of bodies) {
          expect(body.raw).toBeTruthy();
          const txt = JSON.stringify(body);
          expect(JUNK.test(txt), txt.slice(0, 160)).toBe(false);
          expect(emptyValues(body.raw)).toEqual([]);
          for (const f of TEAM_ANSWER_FIELDS) expect(body[f], `${f} on a public entry`).toBeUndefined();
          if (body.source === "waf" || body.source === "web_server") {
            const v = nativeView(body, c);
            expect(v, `${body.id} renders natively`).toBeTruthy();
            expect(validateNative(v!.log, NATIVE_SOURCES[v!.log.sourceId]!.schema)).toEqual([]);
          }
        }
        const feed = tl.filter(t => t.channel === "feed").map(t => t.body as unknown as TelemetryEvent);
        const ws = buildWorkspace(feed, { companyId: c, stack: stackFor(c) });
        for (const body of bodies.filter(b => b.source === "waf" || b.source === "web_server")) {
          const tables = (ws.eventRows[body.id] ?? []).map(m => m.table).filter(t => t !== "SecurityAlert");
          expect(tables.length, `${body.id} reaches a table`).toBeGreaterThan(0);
          expect(tables.every(t => WEB_TABLES.has(t)), `${body.id}: ${tables}`).toBe(true);
        }
      }, 120_000);
    }
  });
}
