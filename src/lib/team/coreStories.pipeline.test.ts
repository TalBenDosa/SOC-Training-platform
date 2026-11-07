// The core attack catalog through the real Team-SOC pipeline: every story pickable for its companies
// and for a named organization, every step present in order, raw records complete, no placeholder
// junk, answer data absent from public rows, a benign look-alike in each story, and Team Training only.
import { describe, expect, it, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { CORE_STORIES } from "@/app/(app)/dashboard/core-stories";
import { ATTACK_STORIES, pickStoryForCompany, storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { buildTeamTimeline, classifyStoryEvent, teamStoryFilter, teamStoryPool, TEAM_ANSWER_FIELDS } from "./buildTimeline";
import { TENANT_TEMPLATE } from "./tenant";
import { DEFAULT_ENV, PLATFORM_CHOICES, type TeamEnv } from "./environment";
import { storyCategory } from "./storyCategory";

const DIFFS = ["easy", "medium", "hard"] as const;
const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const REAL_EMPTY = new Set(["azure.signinlogs.resultDescription", "azure.signinlogs.properties.deviceDetail.deviceId"]);
const emptyValues = (o: unknown, path = ""): string[] => {
  if (o === "") return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
};
const offered = (company: string, id: string) => DIFFS.filter(d => teamStoryPool(company, d, null).filter(teamStoryFilter(company)).some(s => s.id === id));

describe("core attack catalog in the Team-SOC pipeline", () => {
  it("has at least ten stories, across every level", () => {
    expect(CORE_STORIES.length).toBeGreaterThanOrEqual(10);
    expect(new Set(CORE_STORIES.map(s => s.complexity))).toEqual(new Set(["foundation", "core", "advanced"]));
  });

  for (const s of CORE_STORIES) {
    describe(s.id, () => {
      const companies = COMPANIES.filter(c => offered(c, s.id).length > 0);

      it("has a real category and is Team Training only", () => {
        expect(storyCategory(s.id)).not.toBe("other");
        expect(ATTACK_STORIES.find(x => x.id === s.id)?.teamOnly).toBe(true);
      });

      it("is in the team pool of a built-in company", () => {
        expect(companies.length).toBeGreaterThan(0);
        for (const c of companies) expect(DIFFS.some(d => storiesForCompany(c, d).some(x => x.id === s.id))).toBe(true);
      });

      it("is pickable for a named organization running every platform", () => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, FULL_ENV);
        expect(DIFFS.some(d => teamStoryPool(TENANT_TEMPLATE, d, FULL_ENV).filter(fits).some(x => x.id === s.id))).toBe(true);
      });

      it("has a benign look-alike and attack rows", () => {
        const verdicts = s.events.map(classifyStoryEvent);
        expect(verdicts.some(v => v === "fp" || v === "benign")).toBe(true);
        expect(verdicts.filter(v => v === "tp" || v === "escalate").length).toBeGreaterThan(3);
      });

      it("uses English without long dashes", () => {
        for (const e of s.events) expect(`${e.description}${s.title}`).not.toMatch(/[–—]/);
      });

      for (const c of companies) {
        const d = offered(c, s.id)[0];
        it(`injects complete, ordered, rendered logs (${c}, ${d})`, () => {
          const tl = buildTeamTimeline(c, d, `core-${s.id}`, s.id);
          const ids = new Set(s.events.map(e => e.id));
          const story = tl.filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "")));
          expect(story.length).toBe(s.events.length);
          const offs = story.map(e => e.due_offset_ms);
          expect([...offs].sort((a, b) => a - b)).toEqual(offs);
          for (const e of story) {
            const raw = (e.body as { raw?: unknown }).raw;
            expect(raw, "every injected log carries its raw record").toBeTruthy();
            const txt = JSON.stringify(e.body);
            expect(JUNK.test(txt), `placeholder junk in ${txt.slice(0, 160)}`).toBe(false);
            expect(emptyValues(raw).filter(p => !REAL_EMPTY.has(p)), "raw fields with empty values").toEqual([]);
            for (const f of TEAM_ANSWER_FIELDS) expect(Object.keys(e.body), `answer field ${f} on a public row`).not.toContain(f);
          }
          expect(story.some(e => ["fp", "benign"].includes(String((e.answer as { expected_verdict?: string }).expected_verdict)))).toBe(true);
        });
      }
    });
  }

  it("is never returned by pickStoryForCompany", () => {
    const ids = new Set(CORE_STORIES.map(s => s.id));
    for (const c of COMPANIES) for (const d of DIFFS) {
      // The dashboard's whole candidate list, then the picker itself.
      expect(storiesForCompany(c, d, true).filter(s => ids.has(s.id)).map(s => s.id)).toEqual([]);
      for (let i = 0; i < 12; i++) expect(ids.has(pickStoryForCompany(c, d).id)).toBe(false);
    }
  }, 60_000);

  it("leaves the single-player pool as it was: no team story counts toward a pool's size", () => {
    const soloView = ATTACK_STORIES.filter(s => !s.teamOnly);
    for (const c of COMPANIES) for (const d of DIFFS) {
      const solo = storiesForCompany(c, d, true);
      expect(solo.filter(s => s.teamOnly).map(s => s.id)).toEqual([]);
      expect(solo.filter(s => s.soloCompanies && !s.soloCompanies.includes(c)).map(s => s.id)).toEqual([]);
      expect(solo.every(s => soloView.includes(s))).toBe(true);
    }
    // QuantumBank has fewer than eight advanced stories alone, so Hard broadens to core.
    expect(storiesForCompany("quantumbank", "hard", true).some(s => s.complexity === "core")).toBe(true);
  });

  it("widened stories keep their old list for single player", () => {
    const widened = ATTACK_STORIES.filter(s => s.soloCompanies && !s.id.startsWith("ai-") && !s.id.startsWith("web-"));
    expect(widened.length).toBeGreaterThanOrEqual(10);
    for (const s of widened) expect(s.companies!.length).toBeGreaterThan(s.soloCompanies!.length);
  });

  it("runs at least the identity and endpoint stories on the default named-organization environment", () => {
    const fits = teamStoryFilter(TENANT_TEMPLATE, {}, DEFAULT_ENV);
    const pool = new Set(DIFFS.flatMap(d => teamStoryPool(TENANT_TEMPLATE, d, DEFAULT_ENV).filter(fits).map(x => x.id)));
    expect(CORE_STORIES.filter(s => !/s3|ebs/.test(s.id) && !pool.has(s.id)).map(s => s.id)).toEqual([]);
  });
});
