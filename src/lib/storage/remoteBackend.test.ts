/**
 * Tests for the failed-write retry behaviour added alongside the sync-status
 * banner. This is exactly the logic that fails silently in production if it
 * regresses — the previous behaviour was to log a dropped write and move on,
 * which is invisible until a student reports lost XP that can't be reconstructed.
 *
 * The distinction under test is the important one:
 *   · user_progress is an UPSERT → safe to replay automatically on reconnect.
 *   · dashboard_sessions is an append-only INSERT → replaying a write that
 *     actually committed duplicates the row. It must NOT auto-replay.
 *   · scenario_history and room_progress are never written by the browser any
 *     more — server routes are their only writers (#30 / 0078, client XP
 *     self-granting).
 */
import { describe, it, expect, beforeEach } from "vitest";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createRemoteBackend } from "./remoteBackend";
import { LEARNER_KEYS } from "./keys";
import { getSyncState } from "./syncState";

/** Minimal Supabase stub: records calls and returns whatever we queue up. */
function makeSupabase() {
  const calls: { table: string; op: "upsert" | "insert"; rows: unknown }[] = [];
  let failNext = false;

  const api = {
    setFailing(v: boolean) { failNext = v; },
    calls,
    countFor(table: string) { return calls.filter(c => c.table === table).length; },
    client: {
      from(table: string) {
        const result = () =>
          Promise.resolve(failNext ? { error: { message: "network down" } } : { error: null });
        return {
          upsert: (rows: unknown) => { calls.push({ table, op: "upsert", rows }); return result(); },
          insert: (rows: unknown) => { calls.push({ table, op: "insert", rows }); return result(); },
          select: () => ({ eq: () => ({ maybeSingle: () => Promise.resolve({ data: null, error: null }) }) }),
        };
      },
    } as unknown as SupabaseClient,
  };
  return api;
}

const flushMicrotasks = () => new Promise(r => setTimeout(r, 0));

describe("remoteBackend failed-write handling", () => {
  beforeEach(() => {
    // Reset the module-level sync state between tests.
    window.dispatchEvent(new CustomEvent("noop"));
  });

  it("reports nothing while writes succeed", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    backend.set(LEARNER_KEYS.clearedCompanies, JSON.stringify(["nexacorp"]));
    await flushMicrotasks();

    expect(sb.countFor("user_progress")).toBe(1);
    expect(getSyncState()).toEqual({ retrying: 0, needsRetry: 0 });
  });

  it("holds a failed idempotent upsert and replays it on reconnect", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    sb.setFailing(true);
    backend.set(LEARNER_KEYS.clearedCompanies, JSON.stringify(["nexacorp"]));
    await flushMicrotasks();

    // Surfaced, not swallowed.
    expect(getSyncState().retrying).toBe(1);
    expect(sb.countFor("user_progress")).toBe(1);

    // Reconnect → automatic replay, and the queue drains.
    sb.setFailing(false);
    window.dispatchEvent(new Event("online"));
    await flushMicrotasks();

    expect(sb.countFor("user_progress")).toBe(2);
    expect(getSyncState()).toEqual({ retrying: 0, needsRetry: 0 });
  });

  it("does NOT auto-replay an append-only insert on reconnect", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    sb.setFailing(true);
    backend.set(LEARNER_KEYS.dashboardSessions, JSON.stringify([
      { type: "dashboard", date: "2026-08-07T00:00:00Z", xpEarned: 50, detectRate: 80, avgCatchMs: null },
    ]));
    await flushMicrotasks();

    expect(getSyncState().needsRetry).toBe(1);
    expect(sb.countFor("dashboard_sessions")).toBe(1);

    // Reconnect alone must not resend it — a duplicate would double-count XP.
    sb.setFailing(false);
    window.dispatchEvent(new Event("online"));
    await flushMicrotasks();

    expect(sb.countFor("dashboard_sessions")).toBe(1);
    expect(getSyncState().needsRetry).toBe(1);
  });

  it("replays an append-only insert only when the user explicitly retries", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    sb.setFailing(true);
    backend.set(LEARNER_KEYS.dashboardSessions, JSON.stringify([
      { type: "dashboard", date: "2026-08-07T00:00:00Z", xpEarned: 50, detectRate: 80, avgCatchMs: null },
    ]));
    await flushMicrotasks();
    expect(getSyncState().needsRetry).toBe(1);

    sb.setFailing(false);
    window.dispatchEvent(new CustomEvent("soc:sync-retry"));
    await flushMicrotasks();

    expect(sb.countFor("dashboard_sessions")).toBe(2);
    expect(getSyncState()).toEqual({ retrying: 0, needsRetry: 0 });
  });

  it("never writes scenario_history from the client — cache only, total re-read from the server", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    const list = [{ slug: "s1", title: "S1", score: 90, xpEarned: 2000, timeTaken: 60, date: "2026-08-07T00:00:00Z" }];
    backend.set(LEARNER_KEYS.scenarioHistory, JSON.stringify(list));
    await flushMicrotasks();

    expect(sb.calls.filter(c => c.table === "scenario_history")).toHaveLength(0);
    expect(getSyncState()).toEqual({ retrying: 0, needsRetry: 0 });
    // The history is still visible to the UI immediately.
    expect(JSON.parse(backend.get(LEARNER_KEYS.scenarioHistory)!)).toEqual(list);
  });

  it("never writes profiles.xp from the client (server-authoritative since 0008)", async () => {
    const sb = makeSupabase();
    const { backend } = createRemoteBackend(sb.client, "user-1", "org-1");

    backend.set(LEARNER_KEYS.totalXp, "9999");
    await flushMicrotasks();

    expect(sb.countFor("profiles")).toBe(0);
  });
});
