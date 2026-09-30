/**
 * Room progress is SERVER-AUTHORITATIVE since 0078: the browser never writes
 * room_progress (client writes are revoked — a user could otherwise upsert any
 * xp_earned for any room). POST /api/rooms/[id]/tasks/[taskId]/complete is the
 * only writer. The remote backend keeps the map in its cache for immediate UI.
 */
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createRemoteBackend } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";

function makeSupabase() {
  const writes: string[] = [];
  const client = {
    from(table: string) {
      return {
        upsert: () => { writes.push(table); return Promise.resolve({ error: null }); },
        insert: () => { writes.push(table); return Promise.resolve({ error: null }); },
        update: () => { writes.push(table); return Promise.resolve({ error: null }); },
        select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
      };
    },
  } as unknown as SupabaseClient;
  return { client, writes };
}

const flush = () => new Promise(r => setTimeout(r, 0));

describe("remoteBackend room progress (0078)", () => {
  it("never writes room_progress from the browser", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify({ r1: { completedTaskIds: ["t1"], xpEarned: 1000 } }));
    await flush();
    expect(sb.writes.filter(t => t === "room_progress")).toHaveLength(0);
  });

  it("still serves the optimistic map from the cache for immediate UI", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");
    const map = { r1: { completedTaskIds: ["t1"], xpEarned: 20 } };
    backend.set(LEARNER_KEYS.roomProgress, JSON.stringify(map));
    expect(JSON.parse(backend.get(LEARNER_KEYS.roomProgress)!)).toEqual(map);
  });
});
