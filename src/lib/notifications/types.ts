/**
 * In-app notifications (migration 0076) — CLIENT-SAFE types and tiny helpers
 * shared by the API routes, the plan notifier and the Topbar bell.
 */

export type NotificationKind = "plan_assigned" | "plan_updated" | "personal_plan";
export const NOTIFICATION_KINDS: readonly NotificationKind[] = ["plan_assigned", "plan_updated", "personal_plan"];

/** What GET /api/notifications returns per row. */
export interface NotificationItem {
  id: string;
  kind: NotificationKind;
  title: string;
  body: string | null;
  link: string | null;
  created_at: string;
  read_at: string | null;
}

export interface NotificationsResponse {
  /** false when the caller has no organisation (the bell hides itself). */
  enabled: boolean;
  notifications: NotificationItem[];
  unread: number;
}

export const NOTIFICATION_LIMITS = { title: 200, body: 500, link: 300, page: 30, markIds: 100 } as const;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

/**
 * An in-app path is the only thing a notification may link to: it must start
 * with exactly one "/" (no "//host" or "/\host", which browsers treat as a new
 * origin) and contain no control characters (a tab/newline inside "/\t/host"
 * is stripped by URL parsers, turning it back into "//host"). Mirrors
 * notifications_link_chk in 0076.
 */
export function isSafeLink(link: unknown): link is string {
  return typeof link === "string"
    && link.length > 0
    && link.length <= NOTIFICATION_LIMITS.link
    && link[0] === "/"
    && link[1] !== "/"
    && link[1] !== "\\"
    && !CONTROL_CHARS.test(link);
}

// ── Email outcome (plan saves) ───────────────────────────────────────────────
/**
 * What happened to the optional "Also email recipients" part of a plan save.
 * Returned by the plan routes (`email`), recorded in the audit, and shown to the
 * manager by describeNotifyOutcome().
 */
export interface EmailReport {
  /** Recipients considered for email (= notifications actually written). */
  considered: number;
  /** Emails accepted by the provider. */
  emailed: number;
  /** Provider rejected / network error. */
  failed: number;
  skipped: {
    /** The org's daily plan-email budget was exhausted. */
    budget: number;
    /** Already emailed about this plan in the last 24 h. */
    dedupe: number;
    /** Email isn't configured on this deployment (no provider key). */
    unconfigured: number;
    /** No usable address on file. */
    no_address: number;
    /** Over the per-save cap. */
    cap: number;
  };
  /** Still sending after the response (the final counts go to the audit log). */
  pending?: boolean;
}

export const emptyEmailReport = (considered = 0): EmailReport => ({
  considered, emailed: 0, failed: 0, skipped: { budget: 0, dedupe: 0, unconfigured: 0, no_address: 0, cap: 0 },
});

/**
 * The manager-facing summary of a save's notifications, e.g.
 * "3 learners notified · 3 emailed" or
 * "3 learners notified · emails skipped: daily email limit reached (3)".
 * Empty string when nobody was notified and no email was asked for.
 */
export function describeNotifyOutcome(out: { notified?: unknown; email?: EmailReport | null } | null | undefined): string {
  const notified = typeof out?.notified === "number" ? out.notified : 0;
  const e = out?.email ?? null;
  const parts: string[] = [];
  if (notified > 0) parts.push(`${notified} learner${notified === 1 ? "" : "s"} notified`);
  if (e) {
    if (e.pending) parts.push("emails sending");
    else {
      if (e.emailed > 0) parts.push(`${e.emailed} emailed`);
      const why: string[] = [];
      if (e.skipped.unconfigured) why.push("email not configured");
      if (e.skipped.budget) why.push(`daily email limit reached (${e.skipped.budget})`);
      if (e.skipped.dedupe) why.push(`already emailed in the last 24 h (${e.skipped.dedupe})`);
      if (e.skipped.no_address) why.push(`no email address (${e.skipped.no_address})`);
      if (e.skipped.cap) why.push(`over the per-save cap (${e.skipped.cap})`);
      if (why.length) parts.push(`emails skipped: ${why.join(", ")}`);
      if (e.failed) parts.push(`${e.failed} email${e.failed === 1 ? "" : "s"} failed`);
    }
  }
  return parts.join(" · ");
}

/** "just now", "5m ago", "3h ago", "2d ago", then a short date. */
export function timeAgo(iso: string, now: number = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.round((now - t) / 1000));
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 7) return `${d}d ago`;
  return new Date(t).toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}
