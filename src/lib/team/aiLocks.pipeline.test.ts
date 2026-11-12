// Existing AI storylines whose company list was once widened for Team Training. Single-player stays as it
// was (`soloCompanies` keeps the old list, the dashboard draw never offers a gained company), and since the
// two engines stopped sharing stories (Tal, 2026-11-12) Team Training deals none of them.
import { describe, expect, it } from "vitest";
import { ATTACK_STORIES, pickStoryForCompany, storiesForCompany, type AttackStory } from "@/app/(app)/dashboard/attackStories";
import { buildTeamTimeline, teamStoryPool } from "./buildTimeline";

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

      // The single-player dashboard and Team Training never share a story (Tal, 2026-11-12): a single-player
      // storyline is not dealt in Team Training on any company, whatever its widened list says.
      it("Team Training never deals it on its own, on any company or level", () => {
        for (const c of FIVE) for (const d of DIFFS) expect(teamStoryPool(c, d, null).some(x => x.id === id), `${c} ${d}`).toBe(false);
      });
      // An admin's choice always runs (Tal 2026-11-12): a plan saved before the split that names it still gets it,
      // on a company it was written for.
      it("still runs when an older plan chose it", () => {
        const c = old[0];
        const d = DIFFS.find(x => storiesForCompany(c, x, true).some(st => st.id === id))!;
        const ids = new Set(s.events.map(e => e.id));
        const tl = buildTeamTimeline(c, d, `locks-${id}`, id);
        expect(tl.filter(e => ids.has(String((e.answer as { original_id?: string } | undefined)?.original_id ?? "").replace(/__\d+$/, ""))).length).toBe(s.events.length);
      });
    });
  }
});
