import { NextResponse, after } from "next/server";
import { getAuthedUser, requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getPlanCatalog, needsOrgCatalog } from "@/lib/plans/catalog";
import { planMatrix } from "@/lib/plans/completion";
import {
  cleanLine, cleanText, isUuid, parseAudience, parseDueDate, parsePriority, sanitizePlanItems, sanitizeTargets,
} from "@/lib/plans/sanitize";
import {
  ASSIGNMENT_COLUMNS, PlanDataError, activeMemberIds, fetchAll, loadLearnerPlans, loadOrgMembers, loadProgress,
  resolveItems, toPlanDataError, type AssignmentDbRow,
} from "@/lib/plans/server";
import { resolveRecipients, type TargetRow } from "@/lib/plans/targeting";
import { PLAN_LIMITS, type Audience, type PlanItem, type Priority, type StaffPlan } from "@/lib/plans/types";
import { deriveAssignedKeys } from "@/lib/plans/assigned";
import {
  addedItems, deliverNotifications, emailOrigin, loadOrgAudience, loadTargets, noticeText, planEditNotices,
  planEmailsEnabled, planRecipientIds, settleEmailJob, toTargetRows, type EmailReport, type NoticeBatch, type OrgAudience,
} from "@/lib/plans/notify";
import type { PlanCatalog } from "@/lib/plans/catalog";

/**
 * Learning plans (v1: migration 0021 · v2: migration 0075, docs/SPEC-assignments-v2.md).
 *
 * GET — any signed-in org member.
 *   Students (and anyone with ?view=mine) get ONLY the plans they are a
 *   recipient of — org-wide, targeted at them or one of their groups, or their
 *   personal plan — with their own status per item. The service-role read
 *   re-applies the same rule as the 0075 RLS policy (isRecipient).
 *   Staff get every group/org plan (personal plans live on the student page)
 *   with a users × items progress matrix, plus the org's group names.
 *
 * POST / PATCH / DELETE — org_admin (requireOrgAdmin), pinned to the caller's
 *   org from the JWT, audited. Items must exist in the catalogue or the org's
 *   published content; targets must be this org's groups / members.
 *
 * Progress is DERIVED from room_progress / scenario_history / quiz_progress /
 * lesson_progress, never stored — an item finished before it was assigned is
 * done the moment it's assigned.
 *
 * GET ?view=assigned-keys — any signed-in user: a compact { items: { "kind:id":
 *   { priority, due_at, done, personal } } } map of everything the CALLER
 *   receives (same recipient rules as the learner view), for the "Assigned"
 *   chips on the content lists. Empty for users without an org.
 *
 * Notifications (migration 0076, src/lib/plans/notify.ts): a create notifies
 * every recipient (plan_assigned); an edit notifies NEW recipients
 * (plan_assigned) and — only if new items were added — existing ones
 * (plan_updated). Archive / unarchive / delete notify nobody. `notify_email:
 * true` also emails those recipients (budgeted, deduped, batched — see notify.ts);
 * the response carries { notified, email } and the audit records both. A
 * notification or email failure never fails the save.
 */

export const runtime = "nodejs";
// The email job normally settles inside the request; if the provider is slow it
// continues in after(), which runs within this function's time budget.
export const maxDuration = 300;

const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

/**
 * Map a data-layer failure to a generic response, logging the detail. A schema
 * error means the code is ahead of migration 0075 (deploy order: migration
 * first) — reported as 503 "not available yet" rather than a crash.
 */
function dataFail(e: unknown, context: string, message: string) {
  const err = e instanceof PlanDataError ? e : null;
  console.error(`[assignments] ${context}:`, e instanceof Error ? e.message : e);
  if (err?.kind === "schema") return fail(503, "Learning plans aren't available yet. Please try again shortly.");
  if (err?.kind === "cap") return fail(500, `${message} (too much data to load at once).`);
  return fail(500, message);
}
/** Same, for a raw PostgREST error on a write. */
const writeFail = (error: { message: string; code?: string }, context: string, message: string) =>
  dataFail(toPlanDataError(error, context), context, message);

async function readBody(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const b = await req.json();
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  } catch { return null; }
}

type Admin = NonNullable<ReturnType<typeof getSupabaseAdminClient>>;
type Ctx = { orgId: string; userId: string; admin: Admin };

async function staffGate(action: string): Promise<Ctx | { error: NextResponse }> {
  const g = await requireOrgAdmin(action);
  if ("error" in g) return { error: g.error };
  const orgId = g.user.orgId;
  if (!orgId) return { error: fail(400, "No organisation in session.") };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: fail(503, "Server not configured.") };
  return { orgId, userId: g.user.id, admin };
}

/** The ids a targeted plan may point at: this org's groups and its ACTIVE members. */
async function targetUniverse(c: Ctx) {
  const [groups, members] = await Promise.all([
    fetchAll<{ id: string }>((f, t) =>
      c.admin.from("org_groups").select("id").eq("org_id", c.orgId).order("id", { ascending: true }).range(f, t), "org_groups"),
    loadOrgMembers(c.admin, c.orgId),
  ]);
  return { groupIds: new Set(groups.map(g => g.id)), memberIds: activeMemberIds(members) };
}

type Targets = { group_ids: string[]; user_ids: string[] };

/**
 * Make the plan's targets exactly `wanted` (null = none, i.e. org-wide).
 * Split in two phases so a plan is never left targeting nobody mid-edit:
 * `add` runs before the row update, `prune` after it.
 */
async function targetSync(c: Ctx, assignmentId: string, wanted: Targets | null, activeIds: ReadonlySet<string>) {
  const current = await fetchAll<{ id: string; group_id: string | null; user_id: string | null }>((f, t) =>
    c.admin.from("assignment_targets").select("id, group_id, user_id")
      .eq("org_id", c.orgId).eq("assignment_id", assignmentId).order("id", { ascending: true }).range(f, t), "assignment_targets");
  const wantG = new Set(wanted?.group_ids ?? []);
  const wantU = new Set(wanted?.user_ids ?? []);
  const haveG = new Set(current.map(t => t.group_id).filter(Boolean) as string[]);
  const haveU = new Set(current.map(t => t.user_id).filter(Boolean) as string[]);
  // A direct target whose user is currently inactive can't be offered in the
  // picker, so it is kept as-is unless the plan becomes org-wide (wanted=null).
  const stale = current.filter(t =>
    (t.group_id && !wantG.has(t.group_id))
    || (t.user_id && !wantU.has(t.user_id) && (wanted === null || activeIds.has(t.user_id)))).map(t => t.id);

  return {
    add: async () => {
      const rows = [
        ...[...wantG].filter(g => !haveG.has(g)).map(group_id => ({ assignment_id: assignmentId, org_id: c.orgId, group_id })),
        ...[...wantU].filter(u => !haveU.has(u)).map(user_id => ({ assignment_id: assignmentId, org_id: c.orgId, user_id })),
      ];
      if (rows.length === 0) return true;
      const { error } = await c.admin.from("assignment_targets").insert(rows);
      return !error;
    },
    prune: async () => {
      for (let i = 0; i < stale.length; i += 100) {
        const { error } = await c.admin.from("assignment_targets")
          .delete().eq("org_id", c.orgId).in("id", stale.slice(i, i + 100));
        if (error) return false;
      }
      return true;
    },
  };
}

// ── Notifications ────────────────────────────────────────────────────────────
/** Titles + deep links of items, from the catalogue (unknown ids are skipped). */
function describe(items: readonly PlanItem[], catalog: PlanCatalog) {
  return items.flatMap(i => {
    const e = catalog.index.get(`${i.kind}:${i.id}`);
    return e ? [{ title: e.title, href: e.href }] : [];
  });
}

export interface NotifyOutcome { notified: number; email: EmailReport | null }

/**
 * Write the notifications and, when asked, email their recipients. The email
 * job is awaited briefly so the manager sees the real outcome; if it runs long
 * it finishes in after() and its final counts are audited then. Never throws.
 */
async function notify(
  c: Ctx, req: Request, assignmentId: string, planTitle: string, batches: NoticeBatch[], aud: OrgAudience, email: boolean,
): Promise<NotifyOutcome> {
  const res = await deliverNotifications(c.admin, {
    orgId: c.orgId, actorId: c.userId, assignmentId, batches, eligible: aud.eligible, email, origin: emailOrigin(req), planTitle,
  });
  if (!res.emailJob) return { notified: res.notified, email: null };
  const report = await settleEmailJob(res.emailJob, task => after(task), r => logAudit({
    actorId: c.userId, action: "org.assignments.notify_email", targetTable: "assignments", targetId: assignmentId,
    metadata: { orgId: c.orgId, email: r },
  }), res.notified);
  return { notified: res.notified, email: report };
}

// ── GET ──────────────────────────────────────────────────────────────────────
export async function GET(req: Request) {
  const user = await getAuthedUser();
  if (!user) return fail(401, "Authentication required.");
  const isStaff = user.isPlatformAdmin || user.orgRole === "org_admin" || user.orgRole === "instructor";
  const view = new URL(req.url).searchParams.get("view");
  if (!user.orgId) return NextResponse.json(view === "assigned-keys" ? { items: {} } : { plans: [], is_staff: false });
  const orgId = user.orgId;

  const admin = getSupabaseAdminClient();
  if (!admin) return fail(503, "Server not configured.");

  // ── "Assigned" chips: what the caller receives, as a key → info map ──────
  // Everyone (staff included) gets their OWN assignments here — a manager can be
  // a direct target too.
  if (view === "assigned-keys") {
    try {
      const plans = await loadLearnerPlans(admin, orgId, user.id, "self");
      return NextResponse.json({ items: deriveAssignedKeys(plans) }, { headers: { "Cache-Control": "private, no-store" } });
    } catch (e) {
      if (e instanceof PlanDataError && e.kind === "schema") return NextResponse.json({ items: {} });
      return dataFail(e, "assigned keys failed", "Could not load your assignments.");
    }
  }

  // ── Learner view: only what the caller is a recipient of ─────────────────
  if (!isStaff || view === "mine") {
    try {
      // "self": the learner's own progress counts wherever it was earned (as v1).
      const plans = await loadLearnerPlans(admin, orgId, user.id, "self");
      return NextResponse.json({ plans, is_staff: isStaff });
    } catch (e) {
      // Code ahead of the migration: learners simply see no plan card.
      if (e instanceof PlanDataError && e.kind === "schema") {
        console.error("[assignments] learner view: schema not ready:", e.message);
        return NextResponse.json({ plans: [], is_staff: isStaff });
      }
      return dataFail(e, "learner view failed", "Could not load your learning plan.");
    }
  }

  // ── Staff view: every group/org plan + progress matrix ───────────────────
  try {
    const [rows, targetRows, groupRows, groupMemberRows, members] = await Promise.all([
      fetchAll<AssignmentDbRow>((f, t) =>
        admin.from("assignments").select(ASSIGNMENT_COLUMNS)
          .eq("org_id", orgId).is("personal_user_id", null)
          .order("created_at", { ascending: false }).order("id", { ascending: true }).range(f, t), "assignments", 2_000),
      fetchAll<TargetRow & { assignment_id: string }>((f, t) =>
        admin.from("assignment_targets").select("assignment_id, group_id, user_id")
          .eq("org_id", orgId).order("id", { ascending: true }).range(f, t), "assignment_targets"),
      fetchAll<{ id: string; name: string }>((f, t) =>
        admin.from("org_groups").select("id, name").eq("org_id", orgId)
          .order("name", { ascending: true }).order("id", { ascending: true }).range(f, t), "org_groups"),
      fetchAll<{ group_id: string; user_id: string }>((f, t) =>
        admin.from("org_group_members").select("group_id, user_id").eq("org_id", orgId)
          .order("group_id", { ascending: true }).order("user_id", { ascending: true }).range(f, t), "org_group_members"),
      loadOrgMembers(admin, orgId),
    ]);

    const targetsByPlan = new Map<string, TargetRow[]>();
    for (const t of targetRows) targetsByPlan.set(t.assignment_id, [...(targetsByPlan.get(t.assignment_id) ?? []), { group_id: t.group_id, user_id: t.user_id }]);
    const groupMembers = new Map<string, string[]>();
    for (const m of groupMemberRows) groupMembers.set(m.group_id, [...(groupMembers.get(m.group_id) ?? []), m.user_id]);

    const active = members.filter(m => m.status === "active");
    const eligible = new Set(active.map(m => m.user_id));
    const orgWide = active.filter(m => m.role === "student").map(m => m.user_id);
    const nameOf = new Map(members.map(m => [m.user_id, m.name]));
    const byName = [...active].sort((a, b) => a.name.localeCompare(b.name));
    const rank = new Map(byName.map((m, i) => [m.user_id, i]));

    const catalog = await getPlanCatalog(admin, orgId, needsOrgCatalog(rows.map(r => r.items)));
    const resolved = rows.map(r => {
      const audience: Audience = r.audience === "targeted" ? "targeted" : "org";
      const targets = targetsByPlan.get(r.id) ?? [];
      const recipients = resolveRecipients(
        { audience, personal_user_id: null }, targets, groupMembers, eligible, orgWide, id => rank.get(id) ?? 1e9,
      );
      return { r, audience, targets, recipients, items: resolveItems(r.items, catalog) };
    });

    // Progress for exactly the items these plans use and the learners they
    // reach — org-pinned (a manager sees progress earned inside their org).
    const allUsers = [...new Set(resolved.flatMap(x => x.recipients))];
    const allItems = resolved.flatMap(x => x.items);
    const idx = allUsers.length && allItems.length
      ? await loadProgress(admin, { orgId, userIds: allUsers, items: allItems })
      : new Map();

    const plans: StaffPlan[] = resolved.map(({ r, audience, targets, recipients, items }) => {
      const matrix = planMatrix(items, recipients, idx);
      return {
        id: r.id,
        title: r.title,
        instructions: r.instructions,
        due_at: r.due_at,
        priority: parsePriority(r.priority) as Priority,
        audience,
        targets: {
          group_ids: targets.map(t => t.group_id).filter((g): g is string => !!g),
          user_ids: targets.map(t => t.user_id).filter((u): u is string => !!u),
        },
        archived_at: r.archived_at,
        created_at: r.created_at,
        updated_at: r.updated_at,
        items,
        progress: matrix.rows.map(row => ({ ...row, name: nameOf.get(row.user_id) ?? row.user_id.slice(0, 8) })),
        completed: matrix.completed,
      };
    });

    const groups = groupRows.map(g => ({ id: g.id, name: g.name, member_count: (groupMembers.get(g.id) ?? []).length }));
    return NextResponse.json({ plans, groups, is_staff: true, email_enabled: planEmailsEnabled() });
  } catch (e) {
    return dataFail(e, "staff view failed", "Could not load learning plans.");
  }
}

// ── POST — create a plan ─────────────────────────────────────────────────────
export async function POST(req: Request) {
  const c = await staffGate("org.assignments.write");
  if ("error" in c) return c.error;
  const body = await readBody(req);
  if (!body) return fail(400, "Invalid JSON.");

  const title = cleanLine(body.title, PLAN_LIMITS.title);
  if (!title) return fail(400, "Give the plan a title.");
  const due = parseDueDate(body.due_at);
  if (!due.ok) return fail(400, "Invalid due date.");

  const catalog = await getPlanCatalog(c.admin, c.orgId);
  const items = sanitizePlanItems(body.items, catalog.isKnown);
  if (items.length === 0) return fail(400, "Pick at least one module.");

  const audience = parseAudience(body.audience);
  let targets: Targets | null = null;
  let activeIds: ReadonlySet<string> = new Set();
  if (audience === "targeted") {
    try {
      const u = await targetUniverse(c);
      activeIds = u.memberIds;
      targets = sanitizeTargets(body.targets, u.groupIds, u.memberIds);
    } catch (e) {
      return dataFail(e, "create: recipients", "Could not create the plan.");
    }
    if (targets.group_ids.length + targets.user_ids.length === 0) return fail(400, "Choose at least one group or person, or assign it to the whole organisation.");
  }

  const { data, error } = await c.admin.from("assignments").insert({
    org_id: c.orgId,
    title,
    instructions: cleanText(body.instructions, PLAN_LIMITS.instructions) || null,
    items,
    due_at: due.value,
    priority: parsePriority(body.priority),
    audience,
    created_by: c.userId,
  }).select("id").single();
  if (error) return writeFail(error, "create", "Could not create the plan.");

  if (targets) {
    const ok = await targetSync(c, data.id, targets, activeIds).then(sync => sync.add()).catch(() => false);
    if (!ok) {
      // Don't leave a targeted plan with no recipients behind.
      await c.admin.from("assignments").delete().eq("id", data.id).eq("org_id", c.orgId);
      return fail(500, "Could not save the plan's recipients.");
    }
  }

  // Everyone the new plan reaches gets "plan_assigned" (best effort).
  const emailRecipients = body.notify_email === true;
  let outcome: NotifyOutcome = { notified: 0, email: null };
  try {
    const aud = await loadOrgAudience(c.admin, c.orgId, targets?.group_ids ?? []);
    const recipients = planRecipientIds({ audience, personal_user_id: null }, toTargetRows(targets), aud);
    const text = noticeText("plan_assigned", { title, due_at: due.value }, describe(items, catalog));
    outcome = await notify(c, req, data.id, title, [{ kind: "plan_assigned", userIds: recipients, ...text }], aud, emailRecipients);
  } catch (e) {
    console.error("[assignments] create: notify failed:", e instanceof Error ? e.message : e);
  }

  await logAudit({
    actorId: c.userId, action: "org.assignments.create", targetTable: "assignments", targetId: data.id,
    metadata: {
      orgId: c.orgId, items: items.length, audience, groups: targets?.group_ids.length ?? 0, users: targets?.user_ids.length ?? 0,
      notified: outcome.notified, email_requested: emailRecipients, email: outcome.email,
    },
  });
  return NextResponse.json({ id: data.id, notified: outcome.notified, email: outcome.email });
}

// ── PATCH — edit / reorder / retarget / archive ─────────────────────────────
export async function PATCH(req: Request) {
  const c = await staffGate("org.assignments.write");
  if ("error" in c) return c.error;
  const body = await readBody(req);
  if (!body) return fail(400, "Invalid JSON.");
  if (!isUuid(body.id)) return fail(400, "id is required.");
  const id = body.id;

  const { data: existing, error: readErr } = await c.admin.from("assignments")
    .select("id, title, items, due_at, audience, personal_user_id, archived_at").eq("id", id).eq("org_id", c.orgId).maybeSingle();
  if (readErr) return writeFail(readErr, "update: read", "Could not update the plan.");
  if (!existing) return fail(404, "No such plan in your organisation.");
  if (existing.personal_user_id) return fail(400, "Personal plans are edited from the student's page.");

  // Validate everything before writing anything.
  const patch: Record<string, unknown> = {};
  if ("title" in body) {
    const title = cleanLine(body.title, PLAN_LIMITS.title);
    if (!title) return fail(400, "Give the plan a title.");
    patch.title = title;
  }
  if ("instructions" in body) patch.instructions = cleanText(body.instructions, PLAN_LIMITS.instructions) || null;
  if ("due_at" in body) {
    const due = parseDueDate(body.due_at);
    if (!due.ok) return fail(400, "Invalid due date.");
    patch.due_at = due.value;
  }
  if ("priority" in body) patch.priority = parsePriority(body.priority);
  let catalog: PlanCatalog | null = null;
  if ("items" in body) {
    catalog = await getPlanCatalog(c.admin, c.orgId);
    const items = sanitizePlanItems(body.items, catalog.isKnown);
    if (items.length === 0) return fail(400, "Pick at least one module.");
    patch.items = items;
  }
  if ("archived" in body) patch.archived_at = body.archived === true ? new Date().toISOString() : null;

  let sync: Awaited<ReturnType<typeof targetSync>> | null = null;
  let targets: Targets | null = null;
  if ("audience" in body || "targets" in body) {
    const audience = "audience" in body ? parseAudience(body.audience) : (existing.audience === "targeted" ? "targeted" : "org");
    patch.audience = audience;
    try {
      const u = await targetUniverse(c);
      if (audience === "targeted") {
        targets = sanitizeTargets(body.targets, u.groupIds, u.memberIds);
        if (targets.group_ids.length + targets.user_ids.length === 0) return fail(400, "Choose at least one group or person, or assign it to the whole organisation.");
      }
      sync = await targetSync(c, id, targets, u.memberIds);
    } catch (e) {
      return dataFail(e, "update: recipients", "Could not update the plan.");
    }
  }
  if (!sync && Object.keys(patch).length === 0) return fail(400, "Nothing to update.");

  // Who has the plan BEFORE this save — read now, while the old targets are
  // still in place. Only for edits that can change who has it or what's in it,
  // on a live plan; archive / unarchive never notify.
  const existingAudience: Audience = existing.audience === "targeted" ? "targeted" : "org";
  let before: { recipients: string[]; aud: OrgAudience; afterTargets: TargetRow[]; afterAudience: Audience } | null = null;
  if (!("archived" in body) && !existing.archived_at && ("items" in body || "audience" in body || "targets" in body)) {
    try {
      const currentTargets = await loadTargets(c.admin, c.orgId, id);
      const afterAudience = (patch.audience as Audience | undefined) ?? existingAudience;
      const afterTargets = sync ? toTargetRows(targets) : currentTargets;
      const groupIds = [...currentTargets, ...afterTargets].map(t => t.group_id).filter((g): g is string => !!g);
      const aud = await loadOrgAudience(c.admin, c.orgId, groupIds);
      before = {
        recipients: planRecipientIds({ audience: existingAudience, personal_user_id: null }, currentTargets, aud),
        aud, afterTargets, afterAudience,
      };
    } catch (e) {
      console.error("[assignments] update: could not resolve recipients for notifications:", e instanceof Error ? e.message : e);
    }
  }

  if (sync && !(await sync.add())) return fail(500, "Could not save the plan's recipients.");
  if (Object.keys(patch).length) {
    const { error } = await c.admin.from("assignments").update(patch).eq("id", id).eq("org_id", c.orgId);
    if (error) return writeFail(error, "update", "Could not update the plan.");
  }
  if (sync && !(await sync.prune())) return fail(500, "The plan was saved, but old recipients could not be removed.");

  // New recipients → "plan_assigned"; existing recipients → "plan_updated", but
  // only when new items were added. Best effort — the save already succeeded.
  const emailRecipients = body.notify_email === true;
  let outcome: NotifyOutcome = { notified: 0, email: null };
  if (before) {
    try {
      const afterRecipients = planRecipientIds({ audience: before.afterAudience, personal_user_id: null }, before.afterTargets, before.aud);
      const beforeItems = sanitizePlanItems(existing.items, () => true);
      const afterItems = (patch.items as PlanItem[] | undefined) ?? beforeItems;
      const newItems = "items" in patch ? addedItems(beforeItems, afterItems) : [];
      const { assigned, updated } = planEditNotices(before.recipients, afterRecipients, newItems.length);
      if (assigned.length || updated.length) {
        const cat = catalog ?? await getPlanCatalog(c.admin, c.orgId, needsOrgCatalog([afterItems]));
        const info = {
          title: (patch.title as string | undefined) ?? existing.title,
          due_at: "due_at" in patch ? (patch.due_at as string | null) : existing.due_at,
        };
        outcome = await notify(c, req, id, info.title, [
          { kind: "plan_assigned", userIds: assigned, ...noticeText("plan_assigned", info, describe(afterItems, cat)) },
          { kind: "plan_updated", userIds: updated, ...noticeText("plan_updated", info, describe(newItems, cat)) },
        ], before.aud, emailRecipients);
      }
    } catch (e) {
      console.error("[assignments] update: notify failed:", e instanceof Error ? e.message : e);
    }
  }

  await logAudit({
    actorId: c.userId, action: "archived" in body ? (body.archived === true ? "org.assignments.archive" : "org.assignments.unarchive") : "org.assignments.update",
    targetTable: "assignments", targetId: id,
    metadata: { orgId: c.orgId, fields: Object.keys(patch), notified: outcome.notified, email_requested: emailRecipients, email: outcome.email },
  });
  return NextResponse.json({ ok: true, notified: outcome.notified, email: outcome.email });
}

// ── DELETE — remove a plan (its targets cascade) ────────────────────────────
export async function DELETE(req: Request) {
  const c = await staffGate("org.assignments.write");
  if ("error" in c) return c.error;
  const id = new URL(req.url).searchParams.get("id");
  if (!isUuid(id)) return fail(400, "id is required.");

  // .eq("org_id") as well as id — the service-role client bypasses RLS, so the
  // tenant boundary has to be re-asserted explicitly here.
  const { data, error } = await c.admin.from("assignments").delete().eq("id", id).eq("org_id", c.orgId).select("id");
  if (error) return writeFail(error, "delete", "Could not delete the plan.");
  if (!data || data.length === 0) return fail(404, "No such plan in your organisation.");

  await logAudit({ actorId: c.userId, action: "org.assignments.delete", targetTable: "assignments", targetId: id, metadata: { orgId: c.orgId } });
  return NextResponse.json({ ok: true });
}
