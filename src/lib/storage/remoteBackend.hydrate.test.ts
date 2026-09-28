/**
 * hydrate() must distinguish "the server has no rows" from "the read failed".
 * A failed read used to fill the cache with empty lists, and /progress rendered
 * "0 attempted, 0%, 0m" for a learner whose scenario_history rows were safe in
 * the DB (#1). It also must never make a partial load look like a brand-new
 * account (which would import this browser's guest data over it).
 */
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createRemoteBackend } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";

type Res = { data: unknown; error: { message: string } | null };

/** Chainable, thenable query stub: every builder method returns itself; awaiting yields the table's result. */
function makeSupabase(results: Record<string, Res>) {
  return {
    from(table: string) {
      const res: Res = results[table] ?? { data: [], error: null };
      const q: Record<string, unknown> = {};
      for (const m of ["select", "eq", "order", "limit"]) q[m] = () => q;
      q.maybeSingle = () => Promise.resolve(res);
      q.then = (ok: (v: Res) => unknown, bad?: (e: unknown) => unknown) => Promise.resolve(res).then(ok, bad);
      return q;
    },
  } as unknown as SupabaseClient;
}

const HISTORY_ROW = {
  slug: "multi-host-intrusion", title: "Multi-Host Intrusion", score: 92, xp_earned: 470,
  time_taken: 600, completed_at: "2026-09-28T10:47:00Z", report: null,
};

describe("remoteBackend.hydrate", () => {
  it("loads the server rows into the cache on a clean read", async () => {
    const sb = makeSupabase({
      profiles: { data: { xp: 2567 }, error: null },
      user_progress: { data: { cleared_companies: [], streak_freezes: [] }, error: null },
      scenario_history: { data: [HISTORY_ROW], error: null },
    });
    const { backend, hydrate } = createRemoteBackend(sb, "u1", "org-1");
    const r = await hydrate();
    expect(r).toEqual({ wasEmpty: false, rowsMissing: false, failed: [] });
    expect(backend.get(LEARNER_KEYS.totalXp)).toBe("2567");
    const hist = JSON.parse(backend.get(LEARNER_KEYS.scenarioHistory)!);
    expect(hist).toHaveLength(1);
    expect(hist[0]).toMatchObject({ slug: "multi-host-intrusion", score: 92, xpEarned: 470 });
  });

  it("reports a failed read instead of passing it off as an empty history", async () => {
    const sb = makeSupabase({
      profiles: { data: { xp: 2567 }, error: null },
      user_progress: { data: { cleared_companies: [] }, error: null },
      scenario_history: { data: null, error: { message: "timeout" } },
    });
    const { hydrate } = createRemoteBackend(sb, "u1", "org-1");
    const r = await hydrate();
    expect(r.failed).toEqual(["scenario_history"]);
    expect(r.rowsMissing).toBe(false);
  });

  it("a partial load of a zero-XP account is never 'wasEmpty' (no guest import over it)", async () => {
    const sb = makeSupabase({
      profiles: { data: { xp: 0 }, error: null },
      user_progress: { data: {}, error: null },
      room_progress: { data: null, error: { message: "network" } },
    });
    const { hydrate } = createRemoteBackend(sb, "u1", "org-1");
    const r = await hydrate();
    expect(r.failed).toEqual(["room_progress"]);
    expect(r.wasEmpty).toBe(false);
  });

  it("a failed profile read is not mistaken for a deleted account", async () => {
    const sb = makeSupabase({
      profiles: { data: null, error: { message: "network" } },
      user_progress: { data: null, error: { message: "network" } },
    });
    const { hydrate } = createRemoteBackend(sb, "u1", "org-1");
    const r = await hydrate();
    expect(r.rowsMissing).toBe(false);
    expect(r.failed).toEqual(["profiles", "user_progress"]);
  });

  it("a clean read with no provisioned rows IS a deleted account", async () => {
    const sb = makeSupabase({
      profiles: { data: null, error: null },
      user_progress: { data: null, error: null },
    });
    const { hydrate } = createRemoteBackend(sb, "u1", "org-1");
    expect((await hydrate()).rowsMissing).toBe(true);
  });
});
