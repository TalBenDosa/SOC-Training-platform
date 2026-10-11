/**
 * The plan-announcement popup's PURE logic (no React, no fetch) — unit-tested
 * in planAnnouncement.test.ts. Learners are never emailed about plans; this
 * popup (plus the bell) is how they hear about them.
 *
 *  - which notification to announce: the NEWEST unread plan notice that hasn't
 *    already been shown in this browser session;
 *  - the group: every other such notice ("and N more");
 *  - what to render: the live plan from GET /api/org/assignments?view=mine
 *    matched by assignment_id, or — when the plan is gone / archived / not
 *    loadable — the notification's own title and body;
 *  - the session "already shown" set (sessionStorage, fail-safe).
 */
import { NOTIFICATION_KINDS, isSafeLink, type NotificationItem, type NotificationKind } from "./types";
import { PRIORITY_LABEL, type LearnerPlan, type Priority, type ResolvedPlanItem } from "@/lib/plans/types";

export const PLAN_NOTICE_KINDS: ReadonlySet<NotificationKind> = new Set(NOTIFICATION_KINDS);

/** Items listed in the popup before "+N more in this plan". */
export const MAX_POPUP_ITEMS = 5;

export const ANNOUNCEMENT_HEADING: Record<NotificationKind, string> = {
  plan_assigned: "New learning plan from your manager",
  plan_updated: "Your plan was updated",
  personal_plan: "Your personal priorities were updated",
};

const time = (iso: string) => {
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
};

/** Newest first; ties broken by id (descending) so the order is stable. */
export function byNewest(a: NotificationItem, b: NotificationItem): number {
  return time(b.created_at) - time(a.created_at) || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0);
}

/** Unread plan notices not yet shown this session, newest first. */
export function pendingPlanNotices(items: readonly NotificationItem[], shown: ReadonlySet<string>): NotificationItem[] {
  return items
    .filter(n => !n.read_at && PLAN_NOTICE_KINDS.has(n.kind) && !shown.has(n.id))
    .sort(byNewest);
}

/** Every unread plan notice (shown or not) — what "Open my plan" marks read. */
export function unreadPlanNoticeIds(items: readonly NotificationItem[]): string[] {
  return items.filter(n => !n.read_at && PLAN_NOTICE_KINDS.has(n.kind)).map(n => n.id);
}

export interface AnnouncementGroup {
  /** The notice the popup is about (the newest pending one). */
  notice: NotificationItem;
  /** All pending notice ids, the headline one first. */
  ids: string[];
  /** How many OTHER pending plan notices there are ("and N more"). */
  more: number;
}

export function selectAnnouncement(items: readonly NotificationItem[], shown: ReadonlySet<string>): AnnouncementGroup | null {
  const pending = pendingPlanNotices(items, shown);
  if (pending.length === 0) return null;
  return { notice: pending[0], ids: pending.map(n => n.id), more: pending.length - 1 };
}

export interface AnnouncementItem {
  key: string;
  title: string;
  href: string;
  kind: ResolvedPlanItem["kind"];
  status: NonNullable<ResolvedPlanItem["status"]>;
}

export interface AnnouncementView {
  heading: string;
  title: string;
  /** "Personal", or the groups / "Everyone" the plan reaches the learner through. */
  via: string | null;
  priority: Priority | null;
  priorityLabel: string | null;
  dueAt: string | null;
  instructions: string | null;
  items: AnnouncementItem[];
  /** Plan items beyond the listed ones. */
  moreItems: number;
  /** The notification's own body — shown only when the plan couldn't be matched. */
  fallbackBody: string | null;
  /** True when rendered from the notification alone (plan gone / archived / not loaded). */
  fallback: boolean;
  /** Where "Open my plan" goes. */
  link: string;
}

/** Where "Open my plan" navigates: the notice's own (safe) link, else /learn. */
export function announcementLink(notice: NotificationItem): string {
  return isSafeLink(notice.link) ? notice.link : "/learn";
}

/** The live plan this notice is about, if the learner can still see it. */
export function findPlan(notice: NotificationItem, plans: readonly LearnerPlan[] | null | undefined): LearnerPlan | null {
  if (!notice.assignment_id || !plans) return null;
  const id = notice.assignment_id.toLowerCase();
  const p = plans.find(x => typeof x?.id === "string" && x.id.toLowerCase() === id);
  if (!p || (p as LearnerPlan & { archived_at?: string | null }).archived_at) return null;
  return p;
}

export function buildAnnouncementView(notice: NotificationItem, plans: readonly LearnerPlan[] | null | undefined): AnnouncementView {
  const heading = ANNOUNCEMENT_HEADING[notice.kind] ?? "Learning plan update";
  const link = announcementLink(notice);
  const plan = findPlan(notice, plans);
  if (!plan) {
    return {
      heading, title: notice.title, via: null, priority: null, priorityLabel: null, dueAt: null,
      instructions: null, items: [], moreItems: 0, fallbackBody: notice.body, fallback: true, link,
    };
  }
  const all = Array.isArray(plan.items) ? plan.items : [];
  // Open work first (stable within each group), so the popup leads with what's left to do.
  const ordered = [...all.filter(i => i.status !== "done"), ...all.filter(i => i.status === "done")];
  const items = ordered.slice(0, MAX_POPUP_ITEMS).map((i, n) => ({
    key: `${i.kind}:${i.id}:${n}`,
    title: i.title,
    href: isSafeLink(i.href) ? i.href : "/learn",
    kind: i.kind,
    status: i.status ?? "not_started",
  }));
  const priority = plan.priority === 1 || plan.priority === 2 || plan.priority === 3 ? plan.priority : null;
  const via = plan.personal ? "Personal" : (Array.isArray(plan.via) && plan.via.length ? plan.via.join(", ") : null);
  return {
    heading,
    title: plan.title || notice.title,
    via,
    priority,
    priorityLabel: priority ? PRIORITY_LABEL[priority] : null,
    dueAt: plan.due_at ?? null,
    instructions: plan.instructions?.trim() ? plan.instructions : null,
    items,
    moreItems: Math.max(0, all.length - items.length),
    fallbackBody: null,
    fallback: false,
    link,
  };
}

// ── Session "already shown" set ──────────────────────────────────────────────
export const SHOWN_KEY = "soc_plan_popup_shown_v1";
/** Bounded so a long session can't grow the entry without limit. */
export const SHOWN_CAP = 200;

type StorageLike = Pick<Storage, "getItem" | "setItem">;

/** The ids already announced in this browser session. Never throws. */
export function readShown(storage: StorageLike | null | undefined): Set<string> {
  try {
    const raw = storage?.getItem(SHOWN_KEY);
    if (!raw) return new Set();
    const arr: unknown = JSON.parse(raw);
    return new Set(Array.isArray(arr) ? arr.filter((x): x is string => typeof x === "string") : []);
  } catch {
    return new Set();
  }
}

/** Add ids to the session set; returns the new set (also when storage fails). */
export function rememberShown(storage: StorageLike | null | undefined, ids: readonly string[], current?: ReadonlySet<string>): Set<string> {
  const next = new Set(current ?? readShown(storage));
  for (const id of ids) {
    next.delete(id); // re-insert so the newest ids survive the cap
    next.add(id);
  }
  const list = [...next].slice(-SHOWN_CAP);
  try { storage?.setItem(SHOWN_KEY, JSON.stringify(list)); } catch { /* private mode / quota: in-memory only */ }
  return new Set(list);
}
