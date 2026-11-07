// Wave-4 AI storylines through the real Team-SOC pipeline. Each story must be pickable for every
// company it lists and for a named organization, its timeline rows must be complete, ordered and
// rendered, answer data must stay off the public rows, and its benign twin must be there. These
// stories are Team Training only: the single-player draw never returns them.
import { describe, expect, it } from "vitest";
import { pickStoryForCompany, ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { AI_WAVE4_A_STORIES } from "@/app/(app)/dashboard/ai-stories/wave4-a";
import { AI_WAVE4_B_STORIES } from "@/app/(app)/dashboard/ai-stories/wave4-b";
import { buildTeamTimeline, teamStoryPool, teamStoryFilter, TEAM_ANSWER_FIELDS } from "./buildTimeline";
import { TENANT_TEMPLATE } from "./tenant";
import { DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { storyCategory } from "./storyCategory";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";

const STORIES = [...AI_WAVE4_A_STORIES, ...AI_WAVE4_B_STORIES];
const DIFFS = ["easy", "medium", "hard"] as const;
const COMPANIES = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const DASH = /[–—]/;
const SPOILER = /\b(malicious|attacker|stolen|exfiltrat\w*|poison\w*|backdoor|hijack\w*|compromised)\b/i;
// A working injection has this voice. Logs here carry sizes, classifications and summaries only.
const INJECTION = /ignore (all |any )?(previous|prior|above)|disregard (your|all|previous)|you are now|system prompt:|do not tell the user/i;
const REAL_EMPTY = new Set(["azure.signinlogs.resultDescription", "azure.signinlogs.properties.deviceDetail.deviceId"]);

function emptyValues(o: unknown, path = ""): string[] {
  if (o === "") return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
}

describe("wave-4 AI storylines", () => {
  it("has at least the eight owner topics, on unique ids", () => {
    expect(STORIES.length).toBeGreaterThanOrEqual(8);
    expect(new Set(STORIES.map(s => s.id)).size).toBe(STORIES.length);
  });

  it("covers every level", () => {
    expect(new Set(STORIES.map(s => s.complexity))).toEqual(new Set(["foundation", "core", "advanced"]));
  });

  it("reaches every company that holds the seat its topic needs", () => {
    const topic = (id: string) => id.replace(/-(aws|azure|api)$/, "");
    const byTopic = new Map<string, Set<string>>();
    for (const s of STORIES) {
      const set = byTopic.get(topic(s.id)) ?? new Set<string>();
      s.companies.forEach(c => set.add(c));
      byTopic.set(topic(s.id), set);
    }
    // A coding agent needs a developer seat: MedCore's clinical desks have none, so it is the one company off these topics.
    const developerTopics = new Set(["ai-agent-skill-host-cloud", "ai-hub-model-load-workstation", "ai-mcp-server-update-drift", "ai-agent-rules-file-tamper", "ai-assistant-commit-key-leak", "ai-agent-prod-delete"]);
    const narrow = new Set(["ai-rag-source-poisoning", "ai-training-data-poisoning"]); // one topic in two builds, named apart
    for (const [t, set] of byTopic) {
      if (narrow.has(t)) continue;
      expect([...set].sort(), t).toEqual(COMPANIES.filter(c => !developerTopics.has(t) || c !== "medcore").sort());
    }
    const both = new Set([...byTopic.get("ai-rag-source-poisoning")!, ...byTopic.get("ai-training-data-poisoning")!]);
    expect([...both].sort()).toEqual([...COMPANIES].sort());
  });

  it("every company a story lists holds the seat it needs", () => {
    for (const s of STORIES) if (s.seat) for (const c of s.companies) expect(COMPANY_ASSETS[c].seats?.[s.seat]?.length, `${s.id} on ${c}`).toBeGreaterThan(0);
  });

  // A role mailbox, a canary, a clinical or warehouse seat, or a shared server must never be who or where a story happens.
  const NOT_A_PERSON = /sec-canary|security-admin|helpdesk|\bdba@|-desk\d*@|wh-shift/;
  const WRONG_HOST = /WH-TERM|WS-NURS|NRS-TERM|WS-HR-|WS-LOG-|PACS|-NAS|BACKUP|-FS\d|-FILE|SRV-GL-APP02|SRV-PROD-001|ADMIN01|-DC\d|-SQL/;
  for (const s of STORIES) for (const c of s.companies) {
    it(`${s.id} lands on the right people and hosts on ${c}, across seeds`, () => {
      const diff = DIFFS.find(d => teamStoryPool(c, d, null).some(x => x.id === s.id))!;
      const ids = new Set(s.events.map(e => e.id));
      for (let seed = 0; seed < 6; seed++) {
        const rows = buildTeamTimeline(c, diff, `seats-${seed}`, s.id).filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "")));
        for (const e of rows) {
          const b = e.body as { hostname?: string; user_email?: string };
          expect(NOT_A_PERSON.test(b.user_email ?? ""), `${b.user_email} on ${c}`).toBe(false);
          expect(WRONG_HOST.test(b.hostname ?? ""), `${b.hostname} on ${c}`).toBe(false);
        }
        if (s.seat === "developer" || s.seat === "finance") {
          const seats = COMPANY_ASSETS[c].seats![s.seat]!;
          const hosts = new Set(rows.map(e => (e.body as { hostname?: string }).hostname).filter(Boolean));
          expect(seats.some(x => hosts.has(x.host)), `a ${s.seat} seat on ${c}`).toBe(true);
        }
      }
    });
  }

  it("an alert about a resource or a visitor names no employee", () => {
    for (const id of ["ai-portal-assistant-injection-azure", "ai-model-extraction-azure", "ai-exposed-inference-endpoint", "ai-exposed-vector-store"]) {
      const s = STORIES.find(x => x.id === id)!;
      const row = s.events.filter(e => e.source === "siem").at(-1)!;
      expect(row.user_email, id).toBeUndefined();
      expect(JSON.stringify((row.raw as { Entities?: unknown }).Entities), id).not.toContain('"account"');
      expect(row.raw?.["target.user.name"], id).toBeUndefined();
      expect(String(row.raw?.["CompromisedEntity"] ?? ""), id).not.toContain("@");
    }
  });

  it("the benign alert twin has the attack alert's shape and no verdict word", () => {
    for (const id of ["ai-agent-skill-host-cloud-aws", "ai-agent-skill-host-cloud-azure", "ai-hub-model-load-workstation"]) {
      const s = STORIES.find(x => x.id === id)!;
      const alerts = s.events.filter(e => e.source === "edr" && e.is_detection);
      const twin = alerts.find(e => e.expected_verdict === "fp")!, attack = alerts.find(e => e.expected_verdict !== "fp")!;
      expect(Object.keys(twin.raw ?? {}).sort(), id).toEqual(Object.keys(attack.raw ?? {}).sort());
      expect(JSON.stringify(twin.raw), id).not.toContain("av.verdict");
    }
  });

  for (const c of COMPANIES) for (const d of DIFFS) {
    it(`single-player never draws one (${c}, ${d})`, () => {
      const seen: string[] = [];
      pickStoryForCompany(c, d, s => { seen.push(s.id); return true; });
      const ids = new Set(STORIES.map(s => s.id));
      expect(seen.length).toBeGreaterThan(0);
      expect(seen.filter(id => ids.has(id))).toEqual([]);
    });
  }

  for (const s of STORIES) {
    describe(s.id, () => {
      const registered = ATTACK_STORIES.find(x => x.id === s.id);
      const pools = s.companies.flatMap(c => DIFFS.filter(d => teamStoryPool(c, d, null).some(x => x.id === s.id)).map(d => ({ c, d })));

      it("is registered, team-only, in the AI category", () => {
        expect(registered?.teamOnly).toBe(true);
        expect(storyCategory(s.id)).toBe("ai");
      });

      it("is in the Team Training pool of every company it lists", () => {
        expect([...new Set(pools.map(p => p.c))].sort()).toEqual([...s.companies].sort());
      });

      it("passes the team filter on every company it lists", () => {
        for (const c of s.companies) expect(teamStoryFilter(c)(registered!), c).toBe(true);
      });

      it("is pickable for a named organization running every platform", () => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, FULL_ENV);
        expect(DIFFS.filter(d => teamStoryPool(TENANT_TEMPLATE, d, FULL_ENV).filter(fits).some(x => x.id === s.id)).length).toBeGreaterThan(0);
      });

      it("reads the default organization environment as its platforms say", () => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
        const inDefault = DIFFS.some(d => teamStoryPool(TENANT_TEMPLATE, d, DEFAULT_ENV).filter(fits).some(x => x.id === s.id));
        expect(inDefault).toBe(!s.id.endsWith("-aws"));
      });

      it("has a benign twin with an explanation", () => {
        const twins = s.events.filter(e => e.expected_verdict === "fp");
        expect(twins.length).toBeGreaterThan(0);
        for (const e of twins) expect(e.fp_explanation?.length).toBeGreaterThan(20);
      });

      it("has several sources, a first alert, and chronological steps", () => {
        expect(new Set(s.events.map(e => `${e.source}:${e.vendor}`)).size).toBeGreaterThanOrEqual(2);
        expect(s.events.some(e => e.is_detection && e.expected_verdict !== "fp") || s.events.some(e => e.source === "soar")).toBe(true);
        const ts = s.events.map(e => Date.parse(e.ts));
        expect(ts.some(Number.isNaN)).toBe(false);
        for (let i = 1; i < ts.length; i++) expect(ts[i], `${s.events[i].id} comes after ${s.events[i - 1].id}`).toBeGreaterThanOrEqual(ts[i - 1]);
      });

      it("carries no spoiler, no dash and no injection text", () => {
        expect(SPOILER.test(s.title), s.title).toBe(false);
        for (const e of s.events) {
          const shown = `${e.description} ${JSON.stringify(e.raw)} ${JSON.stringify(e.process ?? {})}`;
          expect(DASH.test(shown + s.title), e.id).toBe(false);
          expect(INJECTION.test(shown), e.id).toBe(false);
          if (e.expected_verdict !== "fp" && !e.is_detection) expect(SPOILER.test(`${e.description} ${JSON.stringify(e.raw)}`), `${e.id}: ${e.description}`).toBe(false);
        }
      });

      it("uses documentation addresses and fake keys", () => {
        const text = JSON.stringify(s.events);
        for (const k of text.match(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g) ?? []) expect(k.endsWith("EXAMPLE"), k).toBe(true);
        for (const h of text.match(/\b[0-9A-F]{64}\b/g) ?? []) expect(h).toBe(h.toLowerCase());
      });

      for (const { c, d } of pools) {
        it(`injects complete, ordered, rendered logs (${c}, ${d})`, () => {
          const tl = buildTeamTimeline(c, d, `wave4-${s.id}`, s.id);
          const ids = new Set(s.events.map(e => e.id));
          const rows = tl.filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "")));
          expect(rows.length).toBe(s.events.length);
          const offs = rows.map(e => e.due_offset_ms);
          expect([...offs].sort((a, b) => a - b)).toEqual(offs);
          for (const e of rows) {
            const body = e.body as Record<string, unknown>;
            expect(body.raw, "every injected log carries its raw record").toBeTruthy();
            expect(JUNK.test(JSON.stringify(body)), JSON.stringify(body).slice(0, 160)).toBe(false);
            expect(emptyValues(body.raw).filter(p => !REAL_EMPTY.has(p)), "raw fields with empty values").toEqual([]);
            for (const f of TEAM_ANSWER_FIELDS) expect(body[f], `${f} on a public row`).toBeUndefined();
          }
          const twin = rows.filter(e => (e.answer as { fp_explanation?: string }).fp_explanation);
          expect(twin.length, "the benign twin reaches the feed").toBeGreaterThan(0);
        });
      }
    });
  }
});
