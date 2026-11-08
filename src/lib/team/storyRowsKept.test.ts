import { describe, it, expect } from "vitest";
import { buildFittedTimeline } from "./fitTimeline";
import { teamLoad, withShiftMinutes } from "./load";
import { loadWithPlan, planFromConfig } from "./attackPlan";
import { tenantFromConfig } from "./tenant";
import { envFromConfig } from "./environment";

/**
 * Review 2026-11-08 (Sdema exercise 129714f9, content review): with a small team the fitter cuts the
 * ordinary noise to a handful of rows, and placement used to push the last story rows PAST the end of
 * the canvas, where the emit loop never reached them. The voice-clone takeover lost its impact rows
 * (the Romania sign-in, the correlation alert, the forwarding rule, the salary mail) without a trace.
 * Every planned story row must reach the timeline at any fitted load.
 */
const CONFIG = {
  env: { industry: "general", platforms: ["azure", "linux"] },
  stack: { edr: "mde", detection_feed: "ms_graph" },
  tenant: { name: "sdemagroup" },
  attacks: { bonus: true, count: 3, slots: ["nexacorp-chain-d", "ai-rag-chatbot-document-injection", "ai-helpdesk-voice-reset"] },
};

function storyRows(roster: { role: string }[], seed: string): Map<string, number> {
  const plan = planFromConfig(CONFIG);
  const load = loadWithPlan(withShiftMinutes(teamLoad("medium", roster), 30), plan);
  const { timeline } = buildFittedTimeline({
    companyId: "nexacorp", difficulty: "medium", seed, slots: plan.slots, load,
    stack: CONFIG.stack as never, tenant: tenantFromConfig(CONFIG), env: envFromConfig(CONFIG), opts: { bonus: false }, roster,
  });
  const per = new Map<string, number>();
  for (const r of timeline) {
    const a = r.answer as { origin?: string; incident?: string } | undefined;
    if (r.channel === "feed" && a?.origin === "story") per.set(a.incident ?? "?", (per.get(a.incident ?? "?") ?? 0) + 1);
  }
  return per;
}

describe("every planned story row reaches the timeline at any fitted load", () => {
  const small = [{ role: "t1" }, { role: "t2" }, { role: "mgr" }];
  const large = [{ role: "t1" }, { role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];
  for (const seed of ["sdema-1", "sdema-a", "sdema-b", "sdema-c"]) {
    it(`seed ${seed}: a small team sees the same story rows as a large one`, () => {
      const s = storyRows(small, seed), l = storyRows(large, seed);
      expect([...s.entries()].sort()).toEqual([...l.entries()].sort());
    });
  }
});
