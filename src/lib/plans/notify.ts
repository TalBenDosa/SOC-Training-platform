import "server-only";
/**
 * Learning-plan notifications (migration 0076) — who gets told what when a
 * manager saves a plan, and the (optional) email that goes with it.
 *
 *   POST  /api/org/assignments         → plan_assigned  to every recipient
 *   PATCH /api/org/assignments         → plan_assigned  to NEW recipients,
 *                                        plan_updated   to existing ones, only if
 *                                        NEW items were added
 *   PUT   /api/org/students/[id]/plan  → personal_plan  to that learner, only if
 *                                        the set of items changed
 *   archive / unarchive / delete       → nothing
 *
 * Recipients are resolved with the SAME rule as the staff progress matrix
 * (targeting.resolveRecipients): org-wide → the org's active students; targeted
 * → direct users ∪ members of the targeted groups; personal → its owner — always
 * intersected with the org's ACTIVE, non-platform-admin members. The acting
 * manager is never notified about their own save.
 *
 * FAILURE POLICY: nothing here may fail or slow down the plan save. Inserts are
 * bounded and chunked, every error is logged and swallowed, and email is
 * returned as a job the route runs with next/server `after()` — i.e. after the
 * response has gone out. Email goes ONLY to the resolved recipients (the address
 * list is filtered by the notification rows, never by anything the client sent).
 *
 * The pure helpers (recipient resolution, dedupe, the before/after diff, the
 * notification text) are exported for unit tests (notify.test.ts).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { sendEmail } from "@/lib/email/sendEmail";
import { planNotificationEmail } from "@/lib/email/templates";
import { NOTIFICATION_LIMITS, isSafeLink, type NotificationKind } from "@/lib/notifications/types";
import { chunk, fetchAll, loadOrgMembers, type OrgMemberLite } from "./server";
import { resolveRecipients, type PlanTargeting, type TargetRow } from "./targeting";
import { formatDueDate, itemKey, type PlanItem } from "./types";

export const NOTIFY_LIMITS = {
  /** Most notifications one save may create (an org-wide plan in a very large org). */
  recipients: 5_000,
  /** Rows per INSERT statement. */
  insertChunk: 500,
  /** Most emails one save may send; the rest still get the in-app notification. */
  emails: 100,
  /** Emails in flight at once, and the pause between waves (Resend's default is 2 req/s). */
  emailConcurrency: 2,
  emailIntervalMs: 1_100,
} as const;

// ── Audience ─────────────────────────────────────────────────────────────────
export interface OrgAudience {
  /** Active, non-platform-admin members — the only people who can be notified. */
  eligible: Set<string>;
  /** Who an org-wide plan reaches: active students. */
  orgWide: string[];
  /** group id → member ids (only the groups asked for). */
  groupMembers: Map<string, string[]>;
}

/** Pure: build the audience from the member list and group-membership rows. */
export function buildAudience(
  members: readonly Pick<OrgMemberLite, "user_id" | "role" | "status">[],
  groupRows: readonly { group_id: string; user_id: string }[],
): OrgAudience {
  const active = members.filter(m => m.status === "active");
  const groupMembers = new Map<string, string[]>();
  for (const r of groupRows) {
    const arr = groupMembers.get(r.group_id);
    if (arr) { if (!arr.includes(r.user_id)) arr.push(r.user_id); } else groupMembers.set(r.group_id, [r.user_id]);
  }
  return {
    eligible: new Set(active.map(m => m.user_id)),
    orgWide: active.filter(m => m.role === "student").map(m => m.user_id),
    groupMembers,
  };
}

/** Members of the org + memberships of just the groups `groupIds` (org-pinned service-role reads). */
export async function loadOrgAudience(admin: SupabaseClient, orgId: string, groupIds: readonly string[]): Promise<OrgAudience> {
  const members = await loadOrgMembers(admin, orgId);
  const rows: { group_id: string; user_id: string }[] = [];
  for (const ids of chunk([...new Set(groupIds)], 100)) {
    rows.push(...await fetchAll<{ group_id: string; user_id: string }>((f, t) =>
      admin.from("org_group_members").select("group_id, user_id")
        .eq("org_id", orgId).in("group_id", ids)
        .order("group_id", { ascending: true }).order("user_id", { ascending: true })
        .range(f, t), "org_group_members"));
  }
  return buildAudience(members, rows);
}

/** Who a plan reaches right now (never an archived plan). */
export function planRecipientIds(plan: PlanTargeting, targets: readonly TargetRow[], aud: OrgAudience): string[] {
  if (plan.archived_at) return [];
  return resolveRecipients(plan, targets, aud.groupMembers, aud.eligible, aud.orgWide);
}

/** The plan's current target rows (org-pinned). */
export async function loadTargets(admin: SupabaseClient, orgId: string, assignmentId: string): Promise<TargetRow[]> {
  return fetchAll<TargetRow>((f, t) =>
    admin.from("assignment_targets").select("group_id, user_id")
      .eq("org_id", orgId).eq("assignment_id", assignmentId)
      .order("id", { ascending: true }).range(f, t), "assignment_targets");
}

/** {group_ids, user_ids} (what the API accepts) → target rows. */
export function toTargetRows(t: { group_ids: readonly string[]; user_ids: readonly string[] } | null): TargetRow[] {
  if (!t) return [];
  return [
    ...t.group_ids.map(group_id => ({ group_id, user_id: null })),
    ...t.user_ids.map(user_id => ({ group_id: null, user_id })),
  ];
}

// ── Diff ─────────────────────────────────────────────────────────────────────
/** Items in `after` whose kind:id was not in `before` (order of `after`). */
export function addedItems<T extends Pick<PlanItem, "kind" | "id">>(before: readonly Pick<PlanItem, "kind" | "id">[], after: readonly T[]): T[] {
  const had = new Set(before.map(itemKey));
  return after.filter(i => !had.has(itemKey(i)));
}

/** True when the SET of items differs (added or removed) — reorder / note / priority edits don't count. */
export function itemSetChanged(before: readonly Pick<PlanItem, "kind" | "id">[], after: readonly Pick<PlanItem, "kind" | "id">[]): boolean {
  const a = new Set(before.map(itemKey));
  const b = new Set(after.map(itemKey));
  if (a.size !== b.size) return true;
  for (const k of b) if (!a.has(k)) return true;
  return false;
}

/**
 * An edited plan: people who didn't have it before get "assigned"; people who
 * already had it get "updated" — but only when new items were added (a title,
 * due-date or reorder edit isn't worth a ping). Removed recipients get nothing.
 */
export function planEditNotices(before: readonly string[], after: readonly string[], newItemCount: number): { assigned: string[]; updated: string[] } {
  const had = new Set(before);
  const seen = new Set<string>();
  const assigned: string[] = [];
  const updated: string[] = [];
  for (const u of after) {
    if (seen.has(u)) continue;
    seen.add(u);
    if (!had.has(u)) assigned.push(u);
    else if (newItemCount > 0) updated.push(u);
  }
  return { assigned, updated };
}

// ── Text ─────────────────────────────────────────────────────────────────────
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;
const clip = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

function titlesLine(titles: readonly string[]): string {
  if (titles.length === 0) return "";
  const shown = titles.slice(0, 3).join(", ");
  return titles.length > 3 ? `${shown} +${titles.length - 3} more` : shown;
}

export interface NoticeText { title: string; body: string; link: string }

/**
 * The text of one notification. `items` are the items the notice is ABOUT (all
 * of them for "assigned"/personal, the new ones for "updated"), with titles and
 * deep links from the catalogue. A single item links straight to it; anything
 * else opens /learn, where "My learning plan" lists the whole plan.
 */
export function noticeText(
  kind: NotificationKind,
  plan: { title: string; due_at: string | null },
  items: readonly { title: string; href?: string }[],
): NoticeText {
  const due = plan.due_at ? ` · due ${formatDueDate(plan.due_at)}` : "";
  const list = titlesLine(items.map(i => i.title));
  const one = items.length === 1 && isSafeLink(items[0].href) ? items[0].href! : "/learn";
  let title: string;
  let body: string;
  if (kind === "plan_assigned") {
    title = `New learning plan: ${plan.title}`;
    body = `${plural(items.length, "item")} to complete${due}${list ? ` — ${list}` : ""}`;
  } else if (kind === "plan_updated") {
    title = `Learning plan updated: ${plan.title}`;
    body = `${plural(items.length, "new item")} added${due}${list ? ` — ${list}` : ""}`;
  } else {
    title = "Your personal priorities were updated";
    body = `${plural(items.length, "item")} to do first${due}${list ? ` — ${list}` : ""}`;
  }
  return { title: clip(title, NOTIFICATION_LIMITS.title), body: clip(body, NOTIFICATION_LIMITS.body), link: one };
}

// ── Rows ─────────────────────────────────────────────────────────────────────
export interface NoticeBatch extends NoticeText { kind: NotificationKind; userIds: readonly string[] }

export interface NotificationInsert {
  org_id: string;
  user_id: string;
  kind: NotificationKind;
  title: string;
  body: string | null;
  link: string | null;
  assignment_id: string | null;
}

/**
 * One row per recipient across all batches: the FIRST batch naming a user wins
 * (callers pass "assigned" before "updated"), the actor is skipped, anyone not
 * in `eligible` (inactive / removed / platform admin) is skipped, and the total
 * is capped (`dropped` counts what the cap cut).
 */
export function buildNotificationRows(
  batches: readonly NoticeBatch[],
  ctx: { orgId: string; actorId: string | null; assignmentId: string | null; eligible: ReadonlySet<string>; cap?: number },
): { rows: NotificationInsert[]; dropped: number } {
  const cap = ctx.cap ?? NOTIFY_LIMITS.recipients;
  const seen = new Set<string>();
  const rows: NotificationInsert[] = [];
  let dropped = 0;
  for (const b of batches) {
    for (const user_id of b.userIds) {
      if (seen.has(user_id) || user_id === ctx.actorId || !ctx.eligible.has(user_id)) continue;
      seen.add(user_id);
      if (rows.length >= cap) { dropped++; continue; }
      rows.push({
        org_id: ctx.orgId,
        user_id,
        kind: b.kind,
        title: clip(b.title, NOTIFICATION_LIMITS.title),
        body: b.body ? clip(b.body, NOTIFICATION_LIMITS.body) : null,
        link: isSafeLink(b.link) ? b.link : "/learn",
        assignment_id: ctx.assignmentId,
      });
    }
  }
  return { rows, dropped };
}

// ── Delivery ─────────────────────────────────────────────────────────────────
export interface EmailReport { attempted: number; sent: number; failed: number; skipped: number; capped: number }

export interface DeliveryResult {
  /** Notifications actually written. */
  notified: number;
  /** Run AFTER the response (next/server `after`) when email was requested; null otherwise. */
  emailJob: (() => Promise<EmailReport>) | null;
}

/**
 * Insert the notification rows (chunked) and, if `email` is set, prepare the
 * email job for the same recipients. Never throws.
 */
export async function deliverNotifications(
  admin: SupabaseClient,
  args: {
    orgId: string;
    actorId: string | null;
    assignmentId: string | null;
    batches: readonly NoticeBatch[];
    eligible: ReadonlySet<string>;
    email: boolean;
    /** Absolute origin for the email's link, e.g. "https://www.hackthesoc.app". */
    origin: string;
  },
): Promise<DeliveryResult> {
  let notified = 0;
  let rows: NotificationInsert[] = [];
  try {
    const built = buildNotificationRows(args.batches, args);
    rows = built.rows;
    if (built.dropped) console.error(`[notify] recipient cap reached: ${built.dropped} not notified (org ${args.orgId})`);
    for (const part of chunk(rows, NOTIFY_LIMITS.insertChunk)) {
      const { error } = await admin.from("notifications").insert(part);
      if (error) {
        // 42P01 = the 0076 table isn't there yet (code ahead of the migration).
        console.error(`[notify] insert failed${error.code === "42P01" || error.code === "PGRST205" ? " (migration 0076 not applied?)" : ""}: ${error.message}`);
        break;
      }
      notified += part.length;
    }
  } catch (e) {
    console.error("[notify] failed:", e instanceof Error ? e.message : e);
  }
  const emailJob = args.email && rows.length
    ? () => emailRecipients(admin, args.orgId, rows, args.origin).catch(e => {
        console.error("[notify] email job failed:", e instanceof Error ? e.message : e);
        return { attempted: 0, sent: 0, failed: 0, skipped: 0, capped: 0 };
      })
    : null;
  return { notified, emailJob };
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const wait = (ms: number) => new Promise<void>(r => setTimeout(r, ms));

/**
 * One email per notification row, to that row's user only. Addresses come from
 * org_member_emails(org) (service-role RPC) and are FILTERED to the rows'
 * user ids — someone who isn't a recipient can't be emailed even though the RPC
 * returns every member. Paced in small waves; stops early when email isn't
 * configured (sendEmail reports `skipped`), so a keyless deployment doesn't sit
 * through the pacing for nothing. Errors are logged, never thrown.
 */
export async function emailRecipients(
  admin: SupabaseClient,
  orgId: string,
  rows: readonly NotificationInsert[],
  origin: string,
  sleep: (ms: number) => Promise<void> = wait,
): Promise<EmailReport> {
  const report: EmailReport = { attempted: 0, sent: 0, failed: 0, skipped: 0, capped: 0 };
  const byUser = new Map<string, NotificationInsert>();
  for (const r of rows) if (r.org_id === orgId && !byUser.has(r.user_id)) byUser.set(r.user_id, r);
  if (byUser.size === 0) return report;
  if (!/^https?:\/\/[^/\s]+$/.test(origin)) {
    console.error("[notify] email skipped: invalid origin");
    return report;
  }

  const [{ data, error }, org] = await Promise.all([
    admin.rpc("org_member_emails", { p_org: orgId }),
    admin.from("organizations").select("name").eq("id", orgId).maybeSingle(),
  ]);
  if (error) { console.error("[notify] email lookup failed:", error.message); return report; }
  const emailOf = new Map<string, string>();
  for (const r of (data ?? []) as { user_id: string; email: string | null }[]) {
    if (byUser.has(r.user_id) && r.email && EMAIL_RE.test(r.email)) emailOf.set(r.user_id, r.email);
  }
  const orgName = (org?.data as { name?: string } | null)?.name ?? null;

  const queue = [...byUser.values()].filter(r => emailOf.has(r.user_id));
  report.capped = Math.max(0, queue.length - NOTIFY_LIMITS.emails);
  const list = queue.slice(0, NOTIFY_LIMITS.emails);
  if (report.capped) console.error(`[notify] email cap reached: ${report.capped} recipients not emailed (in-app notification still created)`);

  for (let i = 0; i < list.length; i += NOTIFY_LIMITS.emailConcurrency) {
    if (i > 0) await sleep(NOTIFY_LIMITS.emailIntervalMs);
    const wave = list.slice(i, i + NOTIFY_LIMITS.emailConcurrency);
    const results = await Promise.allSettled(wave.map(r => {
      const mail = planNotificationEmail({ heading: r.title, body: r.body, link: `${origin}${r.link ?? "/learn"}`, orgName });
      return sendEmail({ to: emailOf.get(r.user_id)!, subject: mail.subject, html: mail.html, text: mail.text });
    }));
    let unconfigured = false;
    for (const res of results) {
      report.attempted++;
      if (res.status === "rejected") { report.failed++; continue; }
      if (res.value.ok) report.sent++;
      else if (res.value.skipped) { report.skipped++; unconfigured = true; }
      else report.failed++;
    }
    if (unconfigured) {
      report.skipped += list.length - (i + wave.length);
      break;
    }
  }
  if (report.failed) console.error(`[notify] ${report.failed} plan email(s) failed (org ${orgId})`);
  return report;
}

/** The origin email links should use: the configured site URL, else the request's own. */
export function emailOrigin(req: Request): string {
  const env = process.env.NEXT_PUBLIC_SITE_URL?.trim().replace(/\/+$/, "");
  if (env && /^https?:\/\/[^/\s]+$/.test(env)) return env;
  return new URL(req.url).origin;
}
