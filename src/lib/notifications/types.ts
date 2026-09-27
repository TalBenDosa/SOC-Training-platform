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

/**
 * An in-app path is the only thing a notification may link to: it must start
 * with exactly one "/" (no "//host" or "/\host", which browsers treat as a new
 * origin). Mirrors notifications_link_chk in 0076.
 */
export function isSafeLink(link: unknown): link is string {
  return typeof link === "string"
    && link.length > 0
    && link.length <= NOTIFICATION_LIMITS.link
    && link[0] === "/"
    && link[1] !== "/"
    && link[1] !== "\\";
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
