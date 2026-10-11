/**
 * ONE client-side notifications store shared by everything that shows them —
 * the Topbar bell and the plan-announcement popup — so the app makes a single
 * GET /api/notifications per poll no matter how many consumers are mounted.
 *
 *  - `attach(userId)` registers a consumer (ref-counted). The first consumer
 *    for a user starts the poll (startNotificationPolling: every 60 s while
 *    visible + one debounced refresh on wake); the last one to detach stops it.
 *    A fresh-enough snapshot (< REUSE_MS) is reused instead of refetched, so the
 *    bell remounting with every page's Topbar doesn't refetch on each click.
 *  - Once the server answers `enabled: false` (no organisation) for a user, the
 *    poll stops for good for that user (shouldPoll).
 *  - Responses for a user who is no longer the current one are dropped.
 *  - markRead / markAllRead are optimistic; the next refresh reconciles.
 *
 * Framework-free (useSyncExternalStore subscribes to it via useNotifications).
 */
import type { NotificationItem, NotificationsResponse } from "./types";
import { shouldPoll, startNotificationPolling } from "./polling";

export interface NotificationsState {
  /** The user this snapshot belongs to (null = signed out). */
  userId: string | null;
  enabled: boolean;
  items: NotificationItem[];
  unread: number;
  loaded: boolean;
  error: boolean;
  /** The user id for which the server answered `enabled: false` — no more polling. */
  offFor: string | null;
  /** When the last successful response landed (ms epoch, 0 = never). */
  at: number;
}

export const REUSE_MS = 15_000;

const blank = (userId: string | null): NotificationsState => ({
  userId, enabled: false, items: [], unread: 0, loaded: false, error: false, offFor: null, at: 0,
});

export const EMPTY_NOTIFICATIONS: NotificationsState = blank(null);

let state: NotificationsState = EMPTY_NOTIFICATIONS;
const listeners = new Set<() => void>();
let consumers = 0;
let stopPoll: (() => void) | null = null;
let inflight: Promise<void> | null = null;

function set(next: NotificationsState) {
  state = next;
  listeners.forEach(l => l());
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

export const getSnapshot = (): NotificationsState => state;
export const getServerSnapshot = (): NotificationsState => EMPTY_NOTIFICATIONS;

function stopPolling() {
  stopPoll?.();
  stopPoll = null;
}

/**
 * Bumped by every local mutation (mark read). A fetch that STARTED before a
 * mutation carries the old server state, so its result is dropped instead of
 * restoring the unread badge the user just cleared (P5-21).
 */
let mutationVersion = 0;
let inflightVersion = -1;

/** Fetch the current user's inbox. Concurrent calls share one request. */
export function refresh(): Promise<void> {
  const userId = state.userId;
  if (!userId) return Promise.resolve();
  if (inflight && inflightVersion === mutationVersion) return inflight;
  const startedAt = mutationVersion;
  const run = (async () => {
    try {
      const res = await fetch("/api/notifications", { cache: "no-store" });
      if (state.userId !== userId || mutationVersion !== startedAt) return;
      if (!res.ok) { set({ ...state, error: true, loaded: true }); return; }
      const d: NotificationsResponse = await res.json();
      if (state.userId !== userId || mutationVersion !== startedAt) return;
      const enabled = Boolean(d.enabled);
      set({
        ...state,
        enabled,
        items: Array.isArray(d.notifications) ? d.notifications : [],
        unread: typeof d.unread === "number" ? d.unread : 0,
        loaded: true,
        error: false,
        offFor: enabled ? state.offFor : userId,
        at: Date.now(),
      });
      if (!enabled) stopPolling();
    } catch {
      if (state.userId === userId) set({ ...state, error: true, loaded: true });
    }
  })();
  inflight = run;
  inflightVersion = startedAt;
  // Only clear our own request (a user switch may already have replaced it).
  void run.finally(() => { if (inflight === run) inflight = null; });
  return run;
}

/**
 * Register a consumer for `userId` (null = signed out: resets the store).
 * Returns the matching detach function.
 */
export function attach(userId: string | null): () => void {
  if (state.userId !== userId) {
    stopPolling();
    inflight = null;
    set(blank(userId));
  }
  if (!userId) return () => {};
  consumers += 1;
  if (shouldPoll(userId, state.offFor)) {
    if (!(state.at && Date.now() - state.at < REUSE_MS)) void refresh();
    if (!stopPoll) stopPoll = startNotificationPolling(() => { void refresh(); });
  }
  return () => {
    consumers = Math.max(0, consumers - 1);
    if (consumers === 0) stopPolling();
  };
}

async function postRead(body: { ids: string[] } | { all: true }): Promise<void> {
  try {
    await fetch("/api/notifications/read", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    });
  } catch { /* the next poll reconciles */ }
}

/** Mark these notifications read (optimistic: the badge drops at once). */
export function markRead(ids: readonly string[]): Promise<void> {
  const want = new Set(ids);
  const now = new Date().toISOString();
  let dropped = 0;
  const items = state.items.map(x => {
    if (!want.has(x.id) || x.read_at) return x;
    dropped += 1;
    return { ...x, read_at: now };
  });
  if (dropped === 0) return Promise.resolve();
  mutationVersion += 1;
  set({ ...state, items, unread: Math.max(0, state.unread - dropped), at: 0 });
  return postRead({ ids: [...want].slice(0, 100) });
}

/** Mark the whole inbox read, then refetch. */
export async function markAllRead(): Promise<void> {
  if (state.unread === 0) return;
  mutationVersion += 1;
  const now = new Date().toISOString();
  set({ ...state, items: state.items.map(x => (x.read_at ? x : { ...x, read_at: now })), unread: 0, at: 0 });
  await postRead({ all: true });
  await refresh();
}

/** Test hook: reset module state. */
export function __resetNotificationsStore() {
  stopPolling();
  inflight = null;
  inflightVersion = -1;
  mutationVersion = 0;
  consumers = 0;
  listeners.clear();
  state = EMPTY_NOTIFICATIONS;
}
