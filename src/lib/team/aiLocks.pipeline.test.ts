// Existing AI storylines whose company list was widened for Team Training. Each must run on every
// company it gained, its rows must not name another tenant, and single-player must stay as it was:
// `soloCompanies` keeps the old list and the dashboard draw never offers a gained company.
import { describe, expect, it } from "vitest";
import { ATTACK_STORIES, pickStoryForCompany, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_ASSETS } from "@/lib/sim/companyProfilesMeta";
import { buildTeamTimeline, teamStoryFilter, teamStoryPool } from "./buildTimeline";

const WIDENED: Record<string, string[]> = {
  "ai-shadow-chat-upload": ["nexacorp", "globallogis", "quantumbank"],
  "ai-chat-harvest-extension": ["nexacorp", "medcore", "globallogis", "quantumbank"],
  "ai-claude-enterprise-departure": ["nexacorp", "medcore", "globallogis"],
  "ai-copilot-oversharing-probe": ["nexacorp", "medcore", "globallogis"],
  "ai-claude-shared-secret": ["rocketstack"],
  "ai-claude-compliance-key-harvest": ["rocketstack"],
  "ai-stored-injection-copilot-kb": ["nexacorp", "quantumbank"],
  "ai-malicious-model-pickle": ["rocketstack"],
  "ai-deepfake-exec-call-payment-fraud": ["quantumbank", "globallogis"],
  "ai-browser-agent-prompt-hijack": ["nexacorp"],
};
const DIFFS = ["easy", "medium", "hard"] as const;
const JUNK = /\bundefined\b|\bNaN\b|\[object Object\]/;
const FIVE = ["nexacorp", "medcore", "rocketstack", "globallogis", "quantumbank"];
const soloDraw = (c: string, d: typeof DIFFS[number]) => {
  const seen: string[] = [];
  pickStoryForCompany(c, d, s => { seen.push(s.id); return true; });
  return seen;
};

describe("widened AI storylines", () => {
  for (const [id, old] of Object.entries(WIDENED)) {
    const s = ATTACK_STORIES.find(x => x.id === id) as AttackStory;
    const gained = (s?.companies ?? []).filter(c => !old.includes(c));

    describe(id, () => {
      it("keeps the old list for single-player and gains at least one company", () => {
        expect([...(s.soloCompanies ?? [])].sort()).toEqual([...old].sort());
        expect(gained.length).toBeGreaterThan(0);
        expect(s.teamOnly).toBeFalsy();
      });

      it("single-player offers it exactly where it did", () => {
        for (const c of FIVE) {
          const offered = DIFFS.some(d => soloDraw(c, d).includes(id));
          expect(offered, c).toBe(old.includes(c));
        }
      });

      for (const c of gained) {
        const diff = DIFFS.find(d => teamStoryPool(c, d, null).some(x => x.id === id));

        it(`is in the team pool and passes the team filter on ${c}`, () => {
          expect(diff).toBeTruthy();
          expect(teamStoryFilter(c)(s)).toBe(true);
        });

        it(`renders whole, in this tenant's identity, on ${c}`, () => {
          const tl = buildTeamTimeline(c, diff!, `locks-${id}`, id);
          const ids = new Set(s.events.map(e => e.id));
          const rows = tl.filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, "")));
          expect(rows.length).toBe(s.events.length);
          const foreign = Object.entries(COMPANY_ASSETS).filter(([k, a]) => FIVE.includes(k) && k !== c).map(([, a]) => a.domain);
          for (const e of rows) {
            const txt = JSON.stringify(e.body);
            expect((e.body as { raw?: unknown }).raw).toBeTruthy();
            expect(JUNK.test(txt), txt.slice(0, 160)).toBe(false);
            for (const d of foreign) expect(txt.includes(d), `${d} on a ${c} row`).toBe(false);
          }
        });
      }
    });
  }
});
