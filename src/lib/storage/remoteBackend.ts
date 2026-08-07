/**
 * Remote (Supabase-backed) implementation of `StorageBackend` — the concrete
 * Phase-1 backend `backend.ts` was designed for. Follows the documented
 * "hydrate-then-read-cache" pattern: `hydrate()` loads every learner-data row
 * for the signed-in user into an in-memory `Map` ONCE (async), and after that
 * `get()` is a synchronous cache read (matching the UI's expectation that
 * storage reads never block). `set()` updates the cache immediately
 * (optimistic) and persists to Supabase in the background.
 *
 * Failed writes are NO LONGER silent (they used to be logged and dropped, so a
 * flaky connection could lose a finished room with no warning). Every write now
 * goes through `run()`, which holds the failed thunk and reports it via
 * syncState.ts. Idempotent upserts replay automatically on reconnect; append-only
 * inserts wait for an explicit user retry, because replaying one that actually
 * committed would duplicate a row — and a duplicate scenario_history row
 * double-counts XP through the recompute trigger.
 *
 * KNOWN SIMPLIFICATIONS (fine for an MVP, worth hardening later):
 *  - Pending writes live in memory only: a hard reload while offline still loses
 *    them. Persisting the queue to localStorage would close that.
 *  - No cross-tab sync — two open tabs each hold their own cache; last write
 *    wins. A `postgres_changes` subscription would fix this later.
 *  - `room_progress`/`dashboard_sessions`/`scenario_history` upsert the ENTIRE
 *    decoded value on every `set()` rather than diffing — correct, but does
 *    more writes than strictly necessary. Fine at this data volume.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { StorageBackend } from "./backend";
import { LEARNER_KEYS } from "./keys";
import type { RoomProgressMap, ScenarioRecord } from "./progress";
import type { DashboardSessionRecord } from "@/app/(app)/dashboard/useLiveEvents";
import { setSyncState, SYNC_RETRY_EVENT } from "./syncState";

function safeParse<T>(raw: string | undefined | null, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(raw) as T; } catch { return fallback; }
}

export interface RemoteBackendHandle {
  backend: StorageBackend;
  /**
   * Loads all rows for `userId` into the cache.
   * `wasEmpty` — the account has no progress yet (fresh signup — a good moment to import local progress).
   * `rowsMissing` — the account's provisioned rows (profiles + user_progress, created by the signup
   * trigger) don't exist at all. A valid session pointing at a DELETED user looks exactly like this;
   * the caller should sign out rather than treat it as a fresh account.
   */
  hydrate: () => Promise<{ wasEmpty: boolean; rowsMissing: boolean }>;
}

export function createRemoteBackend(
  supabase: SupabaseClient,
  userId: string,
  /**
   * The learner's org, read from the JWT claim by the caller. When set, it is
   * stamped on every write so the row satisfies the NOT NULL org_id column and
   * the per-org RLS `WITH CHECK (org_id = current_org())` (migrations 0010/0011).
   * Null before the multi-tenancy hook is live — writes then omit org_id and the
   * column's DEFAULT (bootstrap org) applies, so this is safe pre-migration.
   */
  orgId: string | null = null,
): RemoteBackendHandle {
  const cache = new Map<string, string>();

  // Spread into a row to add org_id only when we actually have one.
  const org = orgId ? { org_id: orgId } : {};

  function log(action: string, err: unknown) {
    // Non-fatal by design (see file doc) — surfaced to the console so it's not silent.
    console.error(`[remoteBackend] ${action} failed:`, err);
  }

  // ── Failed-write tracking + retry ───────────────────────────────────────────
  // Each pending entry holds the EXACT thunk that failed, so a retry re-sends
  // the same rows rather than recomputing them from a cache that has since moved
  // on (the append-only cases diff against the cache, so recomputing would send
  // nothing). See syncState.ts for why only idempotent writes auto-retry.
  type Pending = { action: string; idempotent: boolean; run: () => PromiseLike<{ error: unknown }> };
  const pending = new Map<number, Pending>();
  let seq = 0;

  function publish() {
    const all = [...pending.values()];
    setSyncState({
      retrying:   all.filter(p => p.idempotent).length,
      needsRetry: all.filter(p => !p.idempotent).length,
    });
  }

  /**
   * Execute a write, tracking failure. `idempotent` marks writes that are safe
   * to replay blindly (upserts keyed on the primary key); append-only inserts
   * are not, and are held for an explicit retry instead.
   */
  function run(action: string, idempotent: boolean, thunk: () => PromiseLike<{ error: unknown }>) {
    const id = ++seq;
    thunk().then(({ error }) => {
      if (error) {
        log(action, error);
        pending.set(id, { action, idempotent, run: thunk });
        publish();
      }
    }, err => {
      // Network-level rejection (offline, DNS, CORS) — same handling.
      log(action, err);
      pending.set(id, { action, idempotent, run: thunk });
      publish();
    });
  }

  /** Re-send held writes. `includeNonIdempotent` only when the user asked. */
  function flush(includeNonIdempotent: boolean) {
    for (const [id, p] of [...pending.entries()]) {
      if (!p.idempotent && !includeNonIdempotent) continue;
      pending.delete(id);
      run(p.action, p.idempotent, p.run);
    }
    publish();
  }

  if (typeof window !== "undefined") {
    // A real reconnect is strong evidence the earlier attempt never reached the
    // server, so replaying the idempotent writes then is safe.
    window.addEventListener("online", () => flush(false));
    window.addEventListener(SYNC_RETRY_EVENT, () => flush(true));
  }

  // ── Per-key persistence ─────────────────────────────────────────────────────
  function persist(key: string, value: string) {
    switch (key) {
      case LEARNER_KEYS.totalXp: {
        // profiles.xp is SERVER-AUTHORITATIVE since migration 0008: a DB trigger
        // keeps it at xp_offset + sum(xp_earned) across the completion tables, and
        // the xp column is REVOKEd from client roles. We therefore do NOT write it
        // here — the caller's value stays in the in-memory cache (set by
        // backend.set) for immediate optimistic UI, and the true total is re-read
        // from profiles on the next hydrate(). The completion-record writes below
        // (roomProgress / dashboardSessions / scenarioHistory) are what actually
        // move the server total. Writing xp here would only earn a denied 403.
        return;
      }
      case LEARNER_KEYS.roomProgress: {
        const map = safeParse<RoomProgressMap>(value, {});
        const rows = Object.entries(map).map(([roomId, entry]) => ({
          user_id: userId,
          ...org,
          room_id: roomId,
          completed_task_ids: entry.completedTaskIds,
          xp_earned: entry.xpEarned,
          per_task_xp: entry.perTaskXp ?? {},
          telemetry: entry.telemetry ?? [],
          completed_at: entry.completedAt ?? null,
        }));
        if (rows.length === 0) return;
        // Upsert keyed on (user_id, room_id) — safe to replay.
        run("roomProgress", true, () => supabase.from("room_progress").upsert(rows, { onConflict: "user_id,room_id" }));
        return;
      }
      case LEARNER_KEYS.dashboardSessions: {
        const list = safeParse<DashboardSessionRecord[]>(value, []);
        const prev = safeParse<DashboardSessionRecord[]>(cache.get(key), []);
        // Append-only in practice (progress.ts only ever appends+caps) — insert
        // just the newly-appended tail rather than re-inserting everything.
        const fresh = list.slice(Math.max(0, prev.length));
        if (fresh.length === 0) return;
        const sessionRows = fresh.map(s => ({
          user_id: userId,
          ...org,
          played_at: s.date,
          xp_earned: s.xpEarned,
          detect_rate: s.detectRate,
          fn_count: s.fnCount ?? 0,
          avg_catch_ms: s.avgCatchMs,
          attacks_caught_count: s.attacksCaughtCount,
          attacks_presented_count: s.attacksPresentedCount,
          events_opened_count: s.eventsOpenedCount ?? 0,
          duration_ms: s.durationMs ?? 0,
        }));
        // Append-only insert — replaying one that actually committed would
        // duplicate the session, so this waits for an explicit retry.
        run("dashboardSessions", false, () => supabase.from("dashboard_sessions").insert(sessionRows));
        return;
      }
      case LEARNER_KEYS.scenarioHistory: {
        const list = safeParse<ScenarioRecord[]>(value, []);
        const prev = safeParse<ScenarioRecord[]>(cache.get(key), []);
        const fresh = list.slice(Math.max(0, prev.length));
        if (fresh.length === 0) return;
        const historyRows = fresh.map(s => ({
          user_id: userId,
          ...org,
          slug: s.slug,
          title: s.title,
          score: s.score,
          xp_earned: s.xpEarned,
          time_taken: s.timeTaken,
          completed_at: s.date,
          report: s.report ?? null, // requires migration 0017 (jsonb column)
        }));
        // Append-only, and a duplicate row here double-counts XP through the
        // recompute trigger — so never replayed without the user asking.
        run("scenarioHistory", false, () => supabase.from("scenario_history").insert(historyRows));
        return;
      }
      case LEARNER_KEYS.clearedCompanies: {
        const list = safeParse<string[]>(value, []);
        run("clearedCompanies", true, () => supabase.from("user_progress").upsert(
          { user_id: userId, ...org, cleared_companies: list },
          { onConflict: "user_id" },
        ));
        return;
      }
      case LEARNER_KEYS.streakFreezes: {
        const list = safeParse<string[]>(value, []);
        run("streakFreezes", true, () => supabase.from("user_progress").upsert(
          { user_id: userId, ...org, streak_freezes: list },
          { onConflict: "user_id" },
        ));
        return;
      }
      case LEARNER_KEYS.lastSession: {
        run("lastSession", true, () => supabase.from("user_progress").upsert(
          { user_id: userId, ...org, last_session: value },
          { onConflict: "user_id" },
        ));
        return;
      }
      default:
        // Unknown key (e.g. a future addition) — cache-only until the mapping is added here.
        return;
    }
  }

  const backend: StorageBackend = {
    get(key) {
      return cache.get(key) ?? null;
    },
    set(key, value) {
      persist(key, value); // reads cache.get(key) as "prev" for diffing before we overwrite it
      cache.set(key, value);
    },
    remove(key) {
      cache.delete(key);
    },
  };

  async function hydrate(): Promise<{ wasEmpty: boolean; rowsMissing: boolean }> {
    const [profileRes, userProgressRes, roomRes, sessionsRes, scenariosRes] = await Promise.all([
      supabase.from("profiles").select("xp").eq("id", userId).maybeSingle(),
      supabase.from("user_progress").select("*").eq("user_id", userId).maybeSingle(),
      supabase.from("room_progress").select("*").eq("user_id", userId),
      supabase.from("dashboard_sessions").select("*").eq("user_id", userId).order("played_at", { ascending: true }),
      supabase.from("scenario_history").select("*").eq("user_id", userId).order("completed_at", { ascending: true }),
    ]);

    const xp = profileRes.data?.xp ?? 0;
    cache.set(LEARNER_KEYS.totalXp, String(xp));

    const up = userProgressRes.data;
    cache.set(LEARNER_KEYS.clearedCompanies, JSON.stringify(up?.cleared_companies ?? []));
    cache.set(LEARNER_KEYS.streakFreezes, JSON.stringify(up?.streak_freezes ?? []));
    if (up?.last_session) cache.set(LEARNER_KEYS.lastSession, String(up.last_session));

    const roomMap: RoomProgressMap = {};
    for (const row of roomRes.data ?? []) {
      roomMap[row.room_id] = {
        completedTaskIds: row.completed_task_ids ?? [],
        xpEarned: row.xp_earned ?? 0,
        perTaskXp: row.per_task_xp ?? {},
        telemetry: row.telemetry ?? [],
        completedAt: row.completed_at ?? undefined,
      };
    }
    cache.set(LEARNER_KEYS.roomProgress, JSON.stringify(roomMap));

    const sessions: DashboardSessionRecord[] = (sessionsRes.data ?? []).map(row => ({
      type: "dashboard" as const,
      date: row.played_at,
      xpEarned: row.xp_earned,
      detectRate: row.detect_rate,
      fnCount: row.fn_count,
      avgCatchMs: row.avg_catch_ms,
      attacksCaughtCount: row.attacks_caught_count,
      attacksPresentedCount: row.attacks_presented_count,
      eventsOpenedCount: row.events_opened_count,
      durationMs: row.duration_ms,
    }));
    cache.set(LEARNER_KEYS.dashboardSessions, JSON.stringify(sessions));

    const scenarios: ScenarioRecord[] = (scenariosRes.data ?? []).map(row => ({
      slug: row.slug,
      title: row.title,
      score: row.score,
      xpEarned: row.xp_earned,
      timeTaken: row.time_taken,
      date: row.completed_at,
      report: row.report ?? undefined, // null / absent (pre-migration) → undefined
    }));
    cache.set(LEARNER_KEYS.scenarioHistory, JSON.stringify(scenarios));

    const wasEmpty = xp === 0 && roomMap && Object.keys(roomMap).length === 0
      && sessions.length === 0 && scenarios.length === 0;
    // The signup trigger always creates both rows, so both missing means the
    // account itself is gone (deleted user with a still-valid session).
    const rowsMissing = !profileRes.data && !userProgressRes.data;
    return { wasEmpty, rowsMissing };
  }

  return { backend, hydrate };
}
