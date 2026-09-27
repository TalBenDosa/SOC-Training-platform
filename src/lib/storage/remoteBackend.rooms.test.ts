/**
 * Room-write behaviour of the remote backend (audit 2026-09, "I practice but my
 * points don't go up"):
 *  · only CHANGED rooms are upserted, one row per statement — one rejected row
 *    (RLS after an org switch, the 0025 CHECK cap) must not fail every other
 *    room's save the way the old whole-map upsert did;
 *  · xp_earned is clamped to the DB cap;
 *  · a newer write for a room supersedes an older held write for that room;
 *  · after a successful write the cached total is refreshed from profiles.xp
 *    (the leaderboard's number), but not while other writes are pending.
 */
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createRemoteBackend } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";
import { XP_CHANGED_EVENT } from "./progress";

type Row = Record<string, unknown>;

function makeSupabase(opts: { serverXp?: number; failRoom?: string } = {}) {
  const upserts: Row[] = [];
  const state = { serverXp: opts.serverXp ?? 0, failRoom: opts.failRoom, failAll: false, profileReads: 0 };
  const client = {
    from(table: string) {
      return {
        upsert: (row: Row) => {
          upserts.push({ table, ...row });
          const fail = state.failAll || (state.failRoom !== undefined && row.room_id === state.failRoom);
          return Promise.resolve(fail ? { error: { message: "denied" } } : { error: null });
        },
        insert: () => Promise.resolve({ error: null }),
        select: () => ({
          eq: () => ({
            maybeSingle: () => {
              if (table === "profiles") state.profileReads++;
              return Promise.resolve({ data: table === "profiles" ? { xp: state.serverXp } : null, error: null });
            },
          }),
        }),
      };
    },
  } as unknown as SupabaseClient;
  return { client, upserts, state };
}

const tick = () => new Promise(r => setTimeout(r, 0));
const entry = (xp: number, extra: Row = {}) => ({ completedTaskIds: ["t1"], xpEarned: xp, perTaskXp: { t1: xp }, ...extra });

describe("remoteBackend room writes", () => {
  it("upserts only the room that changed, as its own statement", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: entry(10), r2: entry(20) }));
    await tick();
    expect(sb.upserts.map(u => u.room_id)).toEqual(["r1", "r2"]);

    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: entry(10), r2: entry(30) }));
    await tick();
    expect(sb.upserts.map(u => u.room_id)).toEqual(["r1", "r2", "r2"]);
    expect(sb.upserts[2]).toMatchObject({ user_id: "u1", org_id: "org-1", xp_earned: 30 });
  });

  it("one rejected room row does not block other rooms' saves", async () => {
    const sb = makeSupabase({ failRoom: "stranded" });
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ stranded: entry(10) }));
    await tick();
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ stranded: entry(10), fresh: entry(25) }));
    await tick();
    const fresh = sb.upserts.filter(u => u.room_id === "fresh");
    expect(fresh).toHaveLength(1);
    expect(fresh[0]).not.toHaveProperty("stranded");
  });

  it("clamps xp_earned to the 0..1000 DB cap", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ big: entry(2400) }));
    await tick();
    expect(sb.upserts[0].xp_earned).toBe(1000);
  });

  it("a newer write for a room supersedes its older held write", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    sb.state.failAll = true;
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: entry(10) }));
    await tick();
    sb.state.failAll = false;
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: entry(40) }));
    await tick();
    // Reconnect must NOT replay the stale 10-XP row over the 40-XP one.
    window.dispatchEvent(new Event("online"));
    await tick();
    expect(sb.upserts.map(u => u.xp_earned)).toEqual([10, 40]);
  });

  it("refreshes the cached total from profiles.xp after a successful write", async () => {
    const sb = makeSupabase({ serverXp: 345 });
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    backend.set(LEARNER_KEYS.totalXp, "999"); // optimistic value that drifted
    const seen: number[] = [];
    const onXp = (e: Event) => seen.push((e as CustomEvent).detail.total);
    window.addEventListener(XP_CHANGED_EVENT, onXp);
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: entry(10) }));
    await tick(); await tick();
    window.removeEventListener(XP_CHANGED_EVENT, onXp);
    expect(backend.get(LEARNER_KEYS.totalXp)).toBe("345");
    expect(seen).toContain(345);
  });

  it("does not refresh the total while a write is held (would look like a drop)", async () => {
    const sb = makeSupabase({ serverXp: 5, failRoom: "bad" });
    const { backend } = createRemoteBackend(sb.client, "u1", "org-1");
    backend.set(LEARNER_KEYS.totalXp, "500");
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ bad: entry(10), ok: entry(20) }));
    await tick(); await tick();
    expect(backend.get(LEARNER_KEYS.totalXp)).toBe("500");
    expect(sb.state.profileReads).toBe(0);
  });
});
