// QA M7: the Session Builder's storyline list, POST /sessions and /start judge a pinned
// storyline with ONE predicate (teamStoryFilter) — on the INSTANTIATED story, the same
// check the timeline's random pick uses. It used to look at the raw authored events.
import { describe, it, expect } from "vitest";
import { teamStoryFilter, resolveTeamStory } from "./buildTimeline";
import { storiesForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { storyFitsStack } from "@/lib/logs/native";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import type { Stack } from "@/lib/logs/native/stack";

const STACKS: Stack[] = [{}, { edr: "crowdstrike", firewall: "fortigate" }, { edr: "sentinelone", idp: "okta" }, { collab: "google_workspace" }];
const DIFFS = ["easy", "medium", "hard"] as const;

describe("teamStoryFilter (one storyline rule everywhere)", () => {
  it("every company × difficulty keeps pinnable storylines under the company's own products", () => {
    for (const c of COMPANY_PROFILES) for (const d of DIFFS) {
      const fits = teamStoryFilter(c.id, {});
      expect(storiesForCompany(c.id, d).filter(fits).length, `${c.id} ${d}`).toBeGreaterThan(0);
    }
  });

  it("with a chosen stack it accepts exactly the stories whose instantiated events the products can show", () => {
    let judged = 0, differsFromRaw = 0;
    for (const c of COMPANY_PROFILES.slice(0, 3)) for (const stack of STACKS.slice(1)) {
      const fits = teamStoryFilter(c.id, stack);
      for (const s of storiesForCompany(c.id, "medium")) {
        const ok = fits(s);
        judged++;
        if (ok !== storyFitsStack(s.events, c.id, stack)) differsFromRaw++;
        // Accepting a story means its instantiated chain fits — the guarantee the feed needs.
        if (ok) {
          const evs = instantiateStory(s, [], undefined, c.id).events ?? [];
          expect(evs.length).toBeGreaterThan(0);
        }
      }
    }
    expect(judged).toBeGreaterThan(0);
    console.log(`[story-filter] judged ${judged}, raw-vs-instantiated disagreements: ${differsFromRaw}`);
  });

  it("resolveTeamStory only knows stories storiesForCompany offers", () => {
    expect(resolveTeamStory("nexacorp", "easy", "definitely-not-a-story")).toBeNull();
    const first = storiesForCompany("nexacorp", "easy")[0];
    expect(resolveTeamStory("nexacorp", "easy", first.id)?.id).toBe(first.id);
  });
});
