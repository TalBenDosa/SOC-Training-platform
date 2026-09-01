/**
 * Lazy barrel for the HEAVY simulation data.
 *
 * The dashboard is a client component, so everything it imports statically ships
 * in its first-load JS. The benign-event pool (~433KB), the per-company event
 * pools (~260KB) and the attack-story registry (which pulls in all 24
 * scenario-packs) together add up to hundreds of KB the browser downloads and
 * parses on entry — yet none of it is needed until the analyst presses "Start
 * Training" (the feed is idle until then). Loading it through `import()` here
 * moves all of it into a separate chunk fetched on demand, so it never taxes the
 * dashboard's time-to-interactive.
 *
 * `loadSimData()` is memoised: the first call kicks off the fetch, every later
 * call (and the preload on shift-start intent) shares that one promise, so the
 * data is downloaded and parsed at most once per page.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { AttackStory } from "./attackStories";
import type { EdrInvestigation } from "@/lib/edr/investigations";

/** Training difficulty. Defined here (a leaf module) rather than in page.tsx so
 *  simData and page.tsx don't form an import cycle — page.tsx re-exports it. */
export type Difficulty = "easy" | "medium" | "hard";

export interface SimData {
  BENIGN_EVENTS: TelemetryEvent[];
  COMPANY_EVENTS: Record<string, TelemetryEvent[]>;
  pickStoryForCompany: (companyId: string, difficulty?: Difficulty) => AttackStory;
  instantiateStory: (story: AttackStory, companyPool: TelemetryEvent[], companyEdr?: string) => AttackStory;
  buildInvestigationFromStory: (story: AttackStory) => EdrInvestigation | null;
}

let cached: Promise<SimData> | null = null;

export function loadSimData(): Promise<SimData> {
  if (!cached) {
    const p = (async () => {
      const [benign, pools, stories, edr] = await Promise.all([
        import("./benignEvents"),
        import("@/lib/sim/companyProfiles"),
        import("./attackStories"),
        import("@/lib/edr/fromLiveStory"),
      ]);
      return {
        BENIGN_EVENTS: benign.BENIGN_EVENTS,
        COMPANY_EVENTS: pools.COMPANY_EVENTS,
        pickStoryForCompany: stories.pickStoryForCompany,
        instantiateStory: stories.instantiateStory,
        buildInvestigationFromStory: edr.buildInvestigationFromStory,
      };
    })();
    // Don't poison the singleton on failure: a rejected import() (chunk-load
    // error on a flaky network, or after a redeploy swapped the chunk hash while
    // the tab was open) must not lock "Start Training" forever. Reset so the next
    // call re-attempts. Awaiters of `p` still see the rejection (they surface a
    // retry hint); this catch only clears the cache and is itself handled, so it
    // never becomes an unhandled rejection.
    p.catch(() => { if (cached === p) cached = null; });
    cached = p;
  }
  return cached;
}
