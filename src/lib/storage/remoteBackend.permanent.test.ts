/**
 * QA phase 7, E-13: a write the DATABASE refused (trigger / constraint /
 * permission) is not held for retry — replaying it forever showed "check your
 * connection, your work is safe" while the row was lost. Network failures still are.
 */
import { describe, it, expect } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createRemoteBackend, isPermanentWriteError } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";
import { getSyncState } from "./syncState";

const flush = () => new Promise(r => setTimeout(r, 0));
function client(error: unknown): SupabaseClient {
  return {
    from: () => ({
      insert: () => Promise.resolve({ error }),
      upsert: () => Promise.resolve({ error }),
      select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
    }),
  } as unknown as SupabaseClient;
}
const session = JSON.stringify([{ type: "dashboard", date: "2026-10-01T00:00:00Z", xpEarned: 50, detectRate: 80, avgCatchMs: null }]);

describe("isPermanentWriteError", () => {
  it.each([
    [{ code: "P0001", message: "invalid_session: out of range" }, true],
    [{ code: "23505", message: "duplicate key" }, true],
    [{ code: "42501", message: "permission denied" }, true],
    [{ code: "22003", message: "integer out of range" }, true],
    [{ code: "PGRST204", message: "column not found" }, true],
    [{ code: "", message: "TypeError: Failed to fetch" }, false],
    [{ message: "network down" }, false],
    [new TypeError("Failed to fetch"), false],
  ])("%j → %s", (err, permanent) => expect(isPermanentWriteError(err)).toBe(permanent));
});

describe("remote writes", () => {
  it("a database refusal is not held for retry", async () => {
    const { backend } = createRemoteBackend(client({ code: "P0001", message: "invalid_session: out of range" }), "u1", "org1");
    backend.set(LEARNER_KEYS.dashboardSessions, session);
    await flush();
    expect(getSyncState()).toEqual({ retrying: 0, needsRetry: 0 });
  });

  it("a network failure still is", async () => {
    const { backend } = createRemoteBackend(client({ code: "", message: "TypeError: Failed to fetch" }), "u2", "org1");
    backend.set(LEARNER_KEYS.dashboardSessions, session);
    await flush();
    expect(getSyncState().needsRetry).toBe(1);
  });
});
