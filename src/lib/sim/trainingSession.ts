/**
 * Shared "is a live shift running?" flag, so the EDR console (opened in its own
 * tab from the SOC Dashboard) can tell whether the student has actually pressed
 * Start Training. The EDR is only reachable from an active shift — nothing
 * streams, and no telemetry reaches the endpoint view, until training begins.
 *
 * localStorage (NOT sessionStorage) because the EDR opens in a SEPARATE tab and
 * must read the flag the Dashboard set: sessionStorage is per-tab, localStorage
 * is shared across same-origin tabs and its `storage` event lets one tab react
 * to the other. The Dashboard owns the lifecycle — it clears the flag on mount
 * (clean slate) and on End Session, so a stale flag can never leave the EDR
 * reachable without a live shift.
 */
const KEY = "soc_training_active";
export const TRAINING_EVENT = "soc:training-changed";

export function isTrainingActive(): boolean {
  if (typeof window === "undefined") return false;
  try { return localStorage.getItem(KEY) === "1"; } catch { return false; }
}

export function setTrainingActive(active: boolean): void {
  if (typeof window === "undefined") return;
  try {
    if (active) localStorage.setItem(KEY, "1");
    else localStorage.removeItem(KEY);
  } catch { /* storage unavailable — ignore */ }
  window.dispatchEvent(new CustomEvent(TRAINING_EVENT));
}
