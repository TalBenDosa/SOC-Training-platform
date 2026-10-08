// Wave-3 AI storylines through the real Team-SOC pipeline: each story must be pickable in the
// Session Builder pool for its companies (and for a named organization), and the logs the
// timeline injects must be complete: every story step present, in time order, rendered with a
// raw record and no placeholder junk ("undefined", "NaN", "[object Object]", empty values).
import { describe, expect, it } from "vitest";
import { AI_WAVE3_B_STORIES } from "@/app/(app)/dashboard/ai-stories/wave3-b";
import { AI_WAVE3_C_STORIES } from "@/app/(app)/dashboard/ai-stories/wave3-c";
import { AI_WAVE3_D_STORIES } from "@/app/(app)/dashboard/ai-stories/wave3-d";
import { buildTeamTimeline, teamStoryPool, teamStoryFilter } from "./buildTimeline";
import { TENANT_TEMPLATE } from "./tenant";
import { PLATFORM_CHOICES, type TeamEnv } from "./environment";

const STORIES = [...AI_WAVE3_B_STORIES, ...AI_WAVE3_C_STORIES, ...AI_WAVE3_D_STORIES];
const DIFFS = ["easy", "medium", "hard"] as const;
const FULL_ENV: TeamEnv = { platforms: PLATFORM_CHOICES.map(p => p.id), industry: "general" };
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
// Real Entra sign-in fields that are legitimately "" (success has no resultDescription; an
// unregistered device has no deviceId) - the shared emitter writes them that way for every story.
const REAL_EMPTY = new Set(["azure.signinlogs.resultDescription", "azure.signinlogs.properties.deviceDetail.deviceId"]);

function emptyValues(o: unknown, path = ""): string[] {
  if (o === "" ) return [path];
  if (Array.isArray(o)) return o.flatMap((v, i) => emptyValues(v, `${path}[${i}]`));
  if (o && typeof o === "object") return Object.entries(o).flatMap(([k, v]) => emptyValues(v, path ? `${path}.${k}` : k));
  return [];
}

describe("wave-3 AI storylines in the Team-SOC pipeline", () => {
  it("has the six stories", () => { expect(STORIES.map(s => s.id).sort()).toHaveLength(6); });

  for (const s of STORIES) {
    describe(s.id, () => {
      const pools = s.companies.flatMap(c => DIFFS.filter(d => teamStoryPool(c, d, null).some(x => x.id === s.id)).map(d => ({ c, d })));

      it("is in the Session Builder pool for at least one of its companies", () => { expect(pools.length).toBeGreaterThan(0); });

      it("is pickable for a named organization running every platform", () => {
        const fits = teamStoryFilter(TENANT_TEMPLATE, {}, FULL_ENV);
        const named = DIFFS.filter(d => teamStoryPool(TENANT_TEMPLATE, d, FULL_ENV).filter(fits).some(x => x.id === s.id));
        expect(named.length).toBeGreaterThan(0);
      });

      for (const { c, d } of pools) {
        it(`injects complete, ordered, rendered logs (${c}, ${d})`, () => {
          const tl = buildTeamTimeline(c, d, `wave3-${s.id}`, s.id);
          // this storyline's own rows: the session also carries a warm-up story, other attacks and
          // MSEL twists (which attach to the story's incident), so match on the authored event id
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
          }
        });
      }
    });
  }
});
