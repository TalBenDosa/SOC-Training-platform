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
 * FAILURE POLICY: nothing here may fail the plan save. Inserts are bounded
 * and chunked (a failed chunk is logged and the next one still tried), every
 * error is logged and swallowed.
 *
 * EMAIL (only when the manager ticks "Also email recipients") shares the
 * platform's single Resend account with password resets, invites and the cron
 * nudges, which may be on the free tier (100/day, ~2 req/s). So it is fenced:
 *  - only recipients whose notification row was ACTUALLY inserted are emailed
 *    (no table → no emails);
 *  - cross-save dedupe: nobody is emailed twice about the same plan within
 *    24 h (notifications.emailed_at, set only for rows actually emailed);
 *  - a per-org DAILY budget (PLAN_EMAIL_DAILY_BUDGET, default 50) on the shared
 *    rate-limit store; when it's spent the email is skipped, in-app still sent;
 *  - one Resend BATCH call per ≤ 100 messages (sendEmailBatch), so a save costs
 *    1–2 API calls, not one per learner;
 *  - addresses come from plan_recipient_emails(org, user ids) — only the
 *    recipients, only active members of the org, never anything client-sent.
 * The route awaits the job briefly (settleEmailJob) so the manager sees the real
 * outcome; if the provider is slow it finishes in next/server after() and the
 * final counts are written to the audit log.
 *
 * The pure helpers (recipient resolution, dedupe, the before/after diff, the
 * notification text) are exported for unit tests (notify.test.ts).
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { isEmailConfigured, sendEmailBatch } from "@/lib/email/sendEmail";
import { planNotificationEmail } from "@/lib/email/templates";
import { checkRateLimit } from "@/lib/security/rateLimit";
import {
  NOTIFICATION_LIMITS, emptyEmailReport, isSafeLink, type EmailReport, type NotificationKind,
} from "@/lib/notifications/types";
import { chunk, fetchAll, loadOrgMembers, type OrgMemberLite } from "./server";
import { resolveRecipients, type PlanTargeting, type TargetRow } from "./targeting";
import { formatDueDate, itemKey, type PlanItem } from "./types";

export type { EmailReport } from "@/lib/notifications/types";

/**
 * Plan emails one org may send per UTC day (shared Resend account). OFF by
 * default: the platform shares ONE free-tier Resend account with password
 * resets and invites (100 emails/day), so plan emails stay disabled until the
 * account is upgraded and PLAN_EMAIL_DAILY_BUDGET is set (e.g. 50) in the env.
 * In-app notifications are always created.
 */
export const PLAN_EMAIL_DAILY_BUDGET = (() => {
  const n = Number(process.env.PLAN_EMAIL_DAILY_BUDGET);
  return Number.isInteger(n) && n >= 0 ? n : 0;
})();

/** Whether plan emails can be sent at all (the editors hide "Also email" otherwise). */
export function planEmailsEnabled(): boolean {
  return isEmailConfigured() && PLAN_EMAIL_DAILY_BUDGET > 0;
}

export const NOTIFY_LIMITS = {
  /** Most notifications one save may create (an org-wide plan in a very large org). */
  recipients: 5_000,
  /** Rows per INSERT statement. */
  insertChunk: 500,
  /** Most emails one save may send; the rest still get the in-app notification. */
  emails: 100,
  /** No second email about the same plan to the same person within this window. */
  emailDedupeMs: 24 * 60 * 60 * 1000,
  /** How long the route waits for the email job before handing it to after(). */
  inlineEmailWaitMs: 8_000,
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
/** A notification row that was actually written (has its id). */
export interface InsertedNotification extends NotificationInsert { id: string }

export interface DeliveryResult {
  /** Notifications actually written. */
  notified: number;
  /** The rows actually written (the only ones that may be emailed). */
  inserted: InsertedNotification[];
  /** The 0076 table isn't there (code deployed ahead of the migration). */
  tableMissing: boolean;
  /** Present when email was requested AND at least one row was written. */
  emailJob: (() => Promise<EmailReport>) | null;
}

const MISSING_TABLE = new Set(["42P01", "PGRST205"]);

/**
 * Insert the notification rows (chunked) and, if `email` is set, prepare the
 * email job for exactly the rows that were written. Never throws.
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
    /** The plan's title, for the email body (clipped + escaped there). */
    planTitle: string;
  },
): Promise<DeliveryResult> {
  const inserted: InsertedNotification[] = [];
  let tableMissing = false;
  try {
    const built = buildNotificationRows(args.batches, args);
    if (built.dropped) console.error(`[notify] recipient cap reached: ${built.dropped} not notified (org ${args.orgId})`);
    for (const part of chunk(built.rows, NOTIFY_LIMITS.insertChunk)) {
      const { data, error } = await admin.from("notifications").insert(part).select("id, user_id");
      if (error) {
        if (MISSING_TABLE.has(error.code ?? "")) {
          console.error(`[notify] notifications table missing (migration 0076 not applied?): ${error.message}`);
          tableMissing = true;
          break;
        }
        // e.g. one recipient left the org mid-save (FK) — the other chunks still go.
        console.error(`[notify] insert of ${part.length} notification(s) failed: ${error.message}`);
        continue;
      }
      const idOf = new Map(((data ?? []) as { id: string; user_id: string }[]).map(r => [r.user_id, r.id]));
      for (const row of part) {
        const id = idOf.get(row.user_id);
        if (id) inserted.push({ ...row, id });
      }
    }
  } catch (e) {
    console.error("[notify] failed:", e instanceof Error ? e.message : e);
  }
  const emailJob = args.email && inserted.length && !tableMissing
    ? () => emailRecipients(admin, args.orgId, inserted, { origin: args.origin, planTitle: args.planTitle }).catch(e => {
        console.error("[notify] email job failed:", e instanceof Error ? e.message : e);
        const r = emptyEmailReport(inserted.length);
        r.failed = inserted.length;
        return r;
      })
    : null;
  return { notified: inserted.length, inserted, tableMissing, emailJob };
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/** The rate-limit key for an org's plan-email budget on a given UTC day. */
export function emailBudgetKey(orgId: string, now: number = Date.now()): string {
  return `plan-email:${orgId}:${new Date(now).toISOString().slice(0, 10)}`;
}

/** Recipients already emailed about `assignmentId` since `sinceIso` (org-pinned). */
async function recentlyEmailed(admin: SupabaseClient, orgId: string, assignmentId: string, userIds: readonly string[], sinceIso: string): Promise<Set<string>> {
  const out = new Set<string>();
  for (const ids of chunk([...userIds], 100)) {
    const { data, error } = await admin.from("notifications").select("user_id")
      .eq("org_id", orgId).eq("assignment_id", assignmentId).in("user_id", ids)
      .gte("emailed_at", sinceIso).limit(1000);
    if (error) throw new Error(`dedupe lookup: ${error.message}`);
    for (const r of (data ?? []) as { user_id: string }[]) out.add(r.user_id);
  }
  return out;
}

/**
 * Email the recipients of the notification rows that were WRITTEN. In order:
 * one per user → drop anyone emailed about this plan in the last 24 h → per-save
 * cap → (not configured? stop, nothing spent) → addresses for exactly these
 * users → the org's daily budget → one batch call per ≤ 100 → stamp
 * emailed_at on the rows actually emailed. Errors are logged, never thrown.
 */
export async function emailRecipients(
  admin: SupabaseClient,
  orgId: string,
  rows: readonly InsertedNotification[],
  ctx: { origin: string; planTitle: string; now?: number },
): Promise<EmailReport> {
  const byUser = new Map<string, InsertedNotification>();
  for (const r of rows) if (r.org_id === orgId && r.id && !byUser.has(r.user_id)) byUser.set(r.user_id, r);
  const report = emptyEmailReport(byUser.size);
  if (byUser.size === 0) return report;
  if (!/^https?:\/\/[^/\s]+$/.test(ctx.origin)) {
    console.error("[notify] email skipped: invalid origin");
    report.failed = byUser.size;
    return report;
  }
  const now = ctx.now ?? Date.now();

  // 1. Cross-save dedupe (per plan, 24 h).
  let queue = [...byUser.values()];
  const byPlan = new Map<string, string[]>();
  for (const r of queue) if (r.assignment_id) byPlan.set(r.assignment_id, [...(byPlan.get(r.assignment_id) ?? []), r.user_id]);
  const since = new Date(now - NOTIFY_LIMITS.emailDedupeMs).toISOString();
  const already = new Set<string>();
  for (const [planId, users] of byPlan) {
    for (const u of await recentlyEmailed(admin, orgId, planId, users, since)) already.add(`${planId}:${u}`);
  }
  queue = queue.filter(r => {
    const dup = r.assignment_id !== null && already.has(`${r.assignment_id}:${r.user_id}`);
    if (dup) report.skipped.dedupe++;
    return !dup;
  });

  // 2. Per-save cap.
  if (queue.length > NOTIFY_LIMITS.emails) {
    report.skipped.cap = queue.length - NOTIFY_LIMITS.emails;
    queue = queue.slice(0, NOTIFY_LIMITS.emails);
  }
  if (queue.length === 0) return report;

  // 3. Not configured → nothing to do, and no budget spent.
  if (!isEmailConfigured() || PLAN_EMAIL_DAILY_BUDGET === 0) {
    report.skipped.unconfigured = queue.length;
    console.info(`[notify] ${queue.length} plan email(s) skipped: ${PLAN_EMAIL_DAILY_BUDGET === 0 ? "plan emails disabled" : "email not configured"}`);
    return report;
  }

  // 4. Addresses — only these users, only active members of this org.
  const emailOf = new Map<string, string>();
  for (const ids of chunk(queue.map(r => r.user_id), 500)) {
    const { data, error } = await admin.rpc("plan_recipient_emails", { p_org: orgId, p_users: ids });
    if (error) throw new Error(`address lookup: ${error.message}`);
    for (const r of (data ?? []) as { user_id: string; email: string | null }[]) {
      if (byUser.has(r.user_id) && r.email && EMAIL_RE.test(r.email)) emailOf.set(r.user_id, r.email);
    }
  }
  queue = queue.filter(r => {
    const has = emailOf.has(r.user_id);
    if (!has) report.skipped.no_address++;
    return has;
  });
  if (queue.length === 0) return report;

  // 5. The org's daily budget (shared rate-limit store, one unit per email).
  const key = emailBudgetKey(orgId, now);
  const allowed: InsertedNotification[] = [];
  for (const wave of chunk(queue, 20)) {
    const res = await Promise.all(wave.map(() => checkRateLimit(key, PLAN_EMAIL_DAILY_BUDGET, 24 * 60 * 60 * 1000)));
    wave.forEach((r, i) => { if (res[i].ok) allowed.push(r); else report.skipped.budget++; });
  }
  if (report.skipped.budget) console.error(`[notify] org ${orgId} daily plan-email budget (${PLAN_EMAIL_DAILY_BUDGET}) reached: ${report.skipped.budget} email(s) skipped`);
  if (allowed.length === 0) return report;

  // 6. One batch call per ≤ 100.
  const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
  const orgName = (org as { name?: string } | null)?.name ?? null;
  const messages = allowed.map(r => {
    const mail = planNotificationEmail({ kind: r.kind, planTitle: ctx.planTitle, orgName, link: `${ctx.origin}${isSafeLink(r.link) ? r.link : "/learn"}` });
    return { to: emailOf.get(r.user_id)!, subject: mail.subject, html: mail.html, text: mail.text };
  });
  const result = await sendEmailBatch(messages);
  if (result.skipped) { report.skipped.unconfigured += allowed.length; return report; }
  const sentIds: string[] = [];
  allowed.forEach((r, i) => { if (result.sent[i]) { report.emailed++; sentIds.push(r.id); } else report.failed++; });

  // 7. Remember who was emailed (drives the 24 h dedupe).
  const stamp = new Date(now).toISOString();
  for (const ids of chunk(sentIds, 200)) {
    const { error } = await admin.from("notifications").update({ emailed_at: stamp }).eq("org_id", orgId).in("id", ids);
    if (error) console.error(`[notify] could not record emailed_at: ${error.message}`);
  }
  if (report.failed) console.error(`[notify] ${report.failed} plan email(s) failed (org ${orgId})`);
  return report;
}

/**
 * Wait up to `waitMs` for the email job so the response can carry the real
 * outcome. If it's still running, hand the SAME promise to `schedule` (the
 * route passes next/server `after`) so it runs to completion after the
 * response, and call `onLate` with its final report (the route audits it).
 * Returns the report, or a `pending` marker. Never throws.
 */
export async function settleEmailJob(
  job: () => Promise<EmailReport>,
  schedule: (task: () => Promise<unknown>) => void,
  onLate: (r: EmailReport) => unknown,
  consideredHint: number,
  waitMs: number = NOTIFY_LIMITS.inlineEmailWaitMs,
): Promise<EmailReport> {
  const running = job();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<null>(r => { timer = setTimeout(() => r(null), waitMs); });
  const first = await Promise.race([running, timeout]);
  if (timer) clearTimeout(timer);
  if (first) return first;
  try {
    schedule(() => running.then(r => onLate(r)).catch(e => console.error("[notify] late email job failed:", e instanceof Error ? e.message : e)));
  } catch (e) {
    // Outside a request scope after() throws — keep the promise alive regardless.
    console.error("[notify] could not schedule the email job:", e instanceof Error ? e.message : e);
    void running.then(r => onLate(r)).catch(() => {});
  }
  return { ...emptyEmailReport(consideredHint), pending: true };
}

/** The origin email links should use: the configured site URL, else the request's own. */
export function emailOrigin(req: Request): string {
  const env = process.env.NEXT_PUBLIC_SITE_URL?.trim().replace(/\/+$/, "");
  if (env && /^https?:\/\/[^/\s]+$/.test(env)) return env;
  return new URL(req.url).origin;
}
