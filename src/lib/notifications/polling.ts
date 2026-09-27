/**
 * The bell's refresh schedule (client-side; unit-tested in polling.test.ts):
 *  - every `pollMs` while the tab is visible;
 *  - once when the window wakes up — `focus` and `visibilitychange` usually
 *    fire together, so they are debounced into ONE refresh.
 * Returns a stop function. The bell doesn't start it at all once the server has
 * said the feature is off for this user (shouldPoll).
 */
export const POLL_MS = 60_000;
export const WAKE_DEBOUNCE_MS = 400;

export function startNotificationPolling(
  refresh: () => void,
  opts: { pollMs?: number; debounceMs?: number } = {},
): () => void {
  const pollMs = opts.pollMs ?? POLL_MS;
  const debounceMs = opts.debounceMs ?? WAKE_DEBOUNCE_MS;
  const visible = () => document.visibilityState === "visible";
  let wake: ReturnType<typeof setTimeout> | undefined;
  const onWake = () => {
    clearTimeout(wake);
    wake = setTimeout(() => { if (visible()) refresh(); }, debounceMs);
  };
  const id = setInterval(() => { if (visible()) refresh(); }, pollMs);
  window.addEventListener("focus", onWake);
  document.addEventListener("visibilitychange", onWake);
  return () => {
    clearInterval(id);
    clearTimeout(wake);
    window.removeEventListener("focus", onWake);
    document.removeEventListener("visibilitychange", onWake);
  };
}

/** Poll only for a signed-in user the server hasn't switched off (`enabled: false`). */
export function shouldPoll(userId: string | null, offFor: string | null): boolean {
  return userId !== null && offFor !== userId;
}
