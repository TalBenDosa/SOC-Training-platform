/**
 * The Dashboard's per-learner browser storage (F15, Stage A 2026-11-18). On a shared lab PC the next
 * student used to see the previous one's last training report, report drafts, saved searches and
 * organisation. These keys now belong to one learner: they are cleared on sign-out and whenever a
 * different learner (or a guest after a learner) uses the browser. Same pattern as rooms/reviewStore.
 */
import type { SessionReport } from "./sessionReport";

/** Exact keys and key prefixes the Dashboard writes for the learner. */
const KEYS = ["soc_last_training_report_v1", "soc:saved-searches", "soc_selected_company_v1"];
const PREFIXES = ["soc_report_draft_"];
const OWNER_KEY = "soc:dashboard-owner";

/** True for a key that holds this learner's Dashboard data. */
export function isDashboardLearnerKey(k: string): boolean {
  return KEYS.includes(k) || PREFIXES.some(p => k.startsWith(p));
}

/** Remove every Dashboard learner key on this device. */
export function clearDashboardLearnerStore(): void {
  try {
    const ls = window.localStorage;
    for (let i = ls.length - 1; i >= 0; i--) {
      const k = ls.key(i);
      if (k && isDashboardLearnerKey(k)) ls.removeItem(k);
    }
  } catch { /* blocked storage: nothing was saved */ }
}

/** The learner using this browser now (null = guest). A change of learner clears the previous one's data. */
export function setDashboardOwner(userId: string | null): void {
  const owner = userId ?? "guest";
  try {
    const ls = window.localStorage;
    const prev = ls.getItem(OWNER_KEY);
    if (prev !== null && prev !== owner) clearDashboardLearnerStore();
    ls.setItem(OWNER_KEY, owner);
  } catch { /* blocked storage */ }
}

/** A stored training report, or null when the value is missing, corrupt or of an older shape. */
export function parseStoredReport(raw: string | null): SessionReport | null {
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as Partial<SessionReport> | null;
    if (!r || typeof r !== "object" || !r.facts || typeof r.facts !== "object") return null;
    if (typeof r.band !== "string" || !Array.isArray(r.metrics) || !Array.isArray(r.improvements) || !Array.isArray(r.strengths)) return null;
    return r as SessionReport;
  } catch {
    return null;
  }
}
