/**
 * Remote (Supabase-backed) implementation of `StorageBackend` — the concrete
 * Phase-1 backend `backend.ts` was designed for. Follows the documented
 * "hydrate-then-read-cache" pattern: `hydrate()` loads every learner-data row
 * for the signed-in user into an in-memory `Map` ONCE (async), and after that
 * `get()` is a synchronous cache read (matching the UI's expectation that
 * storage reads never block). `set()` updates the cache immediately
 * (optimistic) and persists to Supabase in the background.
 *
 * KNOWN SIMPLIFICATIONS (fine for an MVP, worth hardening later):
 *  - Background writes are fire-and-forget — a failed write is logged, not
 *    retried or queued. A flaky connection can silently drop a write.
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

export function createRemoteBackend(supabase: SupabaseClient, userId: string): RemoteBackendHandle {
  const cache = new Map<string, string>();

  function log(action: string, err: unknown) {
    // Non-fatal by design (see file doc) — surfaced to the console so it's not silent.
    console.error(`[remoteBackend] ${action} failed:`, err);
  }

  // ── Per-key persistence ─────────────────────────────────────────────────────
  function persist(key: string, value: string) {
    switch (key) {
      case LEARNER_KEYS.totalXp: {
        const xp = parseInt(value, 10) || 0;
        supabase.from("profiles").update({ xp }).eq("id", userId).then(({ error }) => {
          if (error) log("totalXp", error);
        });
        return;
      }
      case LEARNER_KEYS.roomProgress: {
        const map = safeParse<RoomProgressMap>(value, {});
        const rows = Object.entries(map).map(([roomId, entry]) => ({
          user_id: userId,
          room_id: roomId,
          completed_task_ids: entry.completedTaskIds,
          xp_earned: entry.xpEarned,
          per_task_xp: entry.perTaskXp ?? {},
          telemetry: entry.telemetry ?? [],
          completed_at: entry.completedAt ?? null,
        }));
        if (rows.length === 0) return;
        supabase.from("room_progress").upsert(rows, { onConflict: "user_id,room_id" }).then(({ error }) => {
          if (error) log("roomProgress", error);
        });
        return;
      }
      case LEARNER_KEYS.dashboardSessions: {
        const list = safeParse<DashboardSessionRecord[]>(value, []);
        const prev = safeParse<DashboardSessionRecord[]>(cache.get(key), []);
        // Append-only in practice (progress.ts only ever appends+caps) — insert
        // just the newly-appended tail rather than re-inserting everything.
        const fresh = list.slice(Math.max(0, prev.length));
        if (fresh.length === 0) return;
        supabase.from("dashboard_sessions").insert(fresh.map(s => ({
          user_id: userId,
          played_at: s.date,
          xp_earned: s.xpEarned,
          detect_rate: s.detectRate,
          fn_count: s.fnCount ?? 0,
          avg_catch_ms: s.avgCatchMs,
          attacks_caught_count: s.attacksCaughtCount,
          attacks_presented_count: s.attacksPresentedCount,
          events_opened_count: s.eventsOpenedCount ?? 0,
          duration_ms: s.durationMs ?? 0,
        }))).then(({ error }) => { if (error) log("dashboardSessions", error); });
        return;
      }
      case LEARNER_KEYS.scenarioHistory: {
        const list = safeParse<ScenarioRecord[]>(value, []);
        const prev = safeParse<ScenarioRecord[]>(cache.get(key), []);
        const fresh = list.slice(Math.max(0, prev.length));
        if (fresh.length === 0) return;
        supabase.from("scenario_history").insert(fresh.map(s => ({
          user_id: userId,
          slug: s.slug,
          title: s.title,
          score: s.score,
          xp_earned: s.xpEarned,
          time_taken: s.timeTaken,
          completed_at: s.date,
        }))).then(({ error }) => { if (error) log("scenarioHistory", error); });
        return;
      }
      case LEARNER_KEYS.clearedCompanies: {
        const list = safeParse<string[]>(value, []);
        supabase.from("user_progress").upsert(
          { user_id: userId, cleared_companies: list },
          { onConflict: "user_id" },
        ).then(({ error }) => { if (error) log("clearedCompanies", error); });
        return;
      }
      case LEARNER_KEYS.streakFreezes: {
        const list = safeParse<string[]>(value, []);
        supabase.from("user_progress").upsert(
          { user_id: userId, streak_freezes: list },
          { onConflict: "user_id" },
        ).then(({ error }) => { if (error) log("streakFreezes", error); });
        return;
      }
      case LEARNER_KEYS.lastSession: {
        supabase.from("user_progress").upsert(
          { user_id: userId, last_session: value },
          { onConflict: "user_id" },
        ).then(({ error }) => { if (error) log("lastSession", error); });
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
