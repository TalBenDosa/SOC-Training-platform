"use client";
/**
 * Sync-failure signalling for the remote storage backend.
 *
 * Background writes in remoteBackend are fire-and-forget: a failed write was
 * logged to the console and nothing else. A student on a flaky connection could
 * finish a room, see the XP land optimistically, and lose it — with no warning
 * that anything went wrong. The support shape of that is "my XP disappeared",
 * which is unfalsifiable after the fact.
 *
 * This makes failure observable, and distinguishes the two cases that matter:
 *
 *  · RETRYABLE   — idempotent upserts (room progress, user_progress). Re-running
 *                  them is free of side effects, so they auto-retry on reconnect.
 *  · NEEDS_RETRY — append-only inserts (dashboard sessions). Re-running one
 *                  that actually committed would duplicate a row, so those are
 *                  surfaced for an explicit, user-initiated retry rather than
 *                  retried silently. (scenario_history used to be one of these;
 *                  it is now written only by the server-side grade route.)
 */
export const SYNC_STATE_EVENT = "soc:sync-state";

export interface SyncState {
  /** Idempotent writes waiting on a reconnect. */
  retrying: number;
  /** Non-idempotent writes that failed and need an explicit retry. */
  needsRetry: number;
}

let state: SyncState = { retrying: 0, needsRetry: 0 };

export function getSyncState(): SyncState {
  return state;
}

export function setSyncState(next: SyncState): void {
  state = next;
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(SYNC_STATE_EVENT, { detail: next }));
}

/** Ask the active backend to retry everything it's holding. */
export const SYNC_RETRY_EVENT = "soc:sync-retry";
export function requestSyncRetry(): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent(SYNC_RETRY_EVENT));
}
