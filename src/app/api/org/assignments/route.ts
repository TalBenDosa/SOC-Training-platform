import { NextResponse } from "next/server";
import { getAuthedUser, requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getPlanCatalog, needsOrgCatalog } from "@/lib/plans/catalog";
import { planMatrix } from "@/lib/plans/completion";
import {
  cleanLine, cleanText, isUuid, parseAudience, parseDueDate, parsePriority, sanitizePlanItems, sanitizeTargets,
} from "@/lib/plans/sanitize";
import {
  ASSIGNMENT_COLUMNS, fetchAll, loadLearnerPlans, loadOrgMembers, loadProgress, resolveItems, type AssignmentDbRow,
} from "@/lib/plans/server";
import { resolveRecipients, type TargetRow } from "@/lib/plans/targeting";
import { PLAN_LIMITS, type Audience, type Priority, type StaffPlan } from "@/lib/plans/types";

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
 */

export const runtime = "nodejs";

const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

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

/** The ids a targeted plan may point at: this org's groups and members. */
async function targetUniverse(c: Ctx) {
  const [groups, members] = await Promise.all([
    c.admin.from("org_groups").select("id").eq("org_id", c.orgId),
    loadOrgMembers(c.admin, c.orgId),
  ]);
  return {
    groupIds: new Set((groups.data ?? []).map(g => g.id as string)),
    memberIds: new Set(members.map(m => m.user_id)),
  };
}

type Targets = { group_ids: string[]; user_ids: string[] };

/**
 * Make the plan's targets exactly `wanted` (null = none, i.e. org-wide).
 * Split in two phases so a plan is never left targeting nobody mid-edit:
 * `add` runs before the row update, `prune` after it.
 */
async function targetSync(c: Ctx, assignmentId: string, wanted: Targets | null) {
  const { data: cur } = await c.admin.from("assignment_targets")
    .select("id, group_id, user_id").eq("org_id", c.orgId).eq("assignment_id", assignmentId);
  const current = (cur ?? []) as { id: string; group_id: string | null; user_id: string | null }[];
  const wantG = new Set(wanted?.group_ids ?? []);
  const wantU = new Set(wanted?.user_ids ?? []);
  const haveG = new Set(current.map(t => t.group_id).filter(Boolean) as string[]);
  const haveU = new Set(current.map(t => t.user_id).filter(Boolean) as string[]);
  const stale = current.filter(t => (t.group_id && !wantG.has(t.group_id)) || (t.user_id && !wantU.has(t.user_id))).map(t => t.id);

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

// ── GET ──────────────────────────────────────────────────────────────────────
export async function GET(req: Request) {
  const user = await getAuthedUser();
  if (!user) return fail(401, "Authentication required.");
  const isStaff = user.isPlatformAdmin || user.orgRole === "org_admin" || user.orgRole === "instructor";
  if (!user.orgId) return NextResponse.json({ plans: [], is_staff: false });
  const orgId = user.orgId;

  const admin = getSupabaseAdminClient();
  if (!admin) return fail(503, "Server not configured.");

  // ── Learner view: only what the caller is a recipient of ─────────────────
  if (!isStaff || new URL(req.url).searchParams.get("view") === "mine") {
    try {
      const plans = await loadLearnerPlans(admin, orgId, user.id);
      return NextResponse.json({ plans, is_staff: isStaff });
    } catch (e) {
      console.error("[assignments] learner view failed:", e instanceof Error ? e.message : e);
      return fail(500, "Could not load your learning plan.");
    }
  }

  // ── Staff view: every group/org plan + progress matrix ───────────────────
  try {
    const [plansRes, targetRows, groupsRes, groupMemberRows, members] = await Promise.all([
      admin.from("assignments").select(ASSIGNMENT_COLUMNS)
        .eq("org_id", orgId).is("personal_user_id", null)
        .order("created_at", { ascending: false }).limit(500),
      fetchAll<TargetRow & { assignment_id: string }>((f, t) =>
        admin.from("assignment_targets").select("assignment_id, group_id, user_id").eq("org_id", orgId).range(f, t)),
      admin.from("org_groups").select("id, name").eq("org_id", orgId).order("name", { ascending: true }),
      fetchAll<{ group_id: string; user_id: string }>((f, t) =>
        admin.from("org_group_members").select("group_id, user_id").eq("org_id", orgId).range(f, t)),
      loadOrgMembers(admin, orgId),
    ]);
    if (plansRes.error) throw new Error(plansRes.error.message);
    const rows = (plansRes.data ?? []) as AssignmentDbRow[];

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

    const [catalog, idx] = await Promise.all([
      getPlanCatalog(admin, orgId, needsOrgCatalog(rows.map(r => r.items))),
      rows.length ? loadProgress(admin, orgId) : Promise.resolve(new Map()),
    ]);

    const plans: StaffPlan[] = rows.map(r => {
      const audience: Audience = r.audience === "targeted" ? "targeted" : "org";
      const targets = targetsByPlan.get(r.id) ?? [];
      const items = resolveItems(r.items, catalog);
      const recipients = resolveRecipients(
        { audience, personal_user_id: null }, targets, groupMembers, eligible, orgWide, id => rank.get(id) ?? 1e9,
      );
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

    const groups = (groupsRes.data ?? []).map(g => ({ id: g.id as string, name: g.name as string, member_count: (groupMembers.get(g.id) ?? []).length }));
    return NextResponse.json({ plans, groups, is_staff: true });
  } catch (e) {
    console.error("[assignments] staff view failed:", e instanceof Error ? e.message : e);
    return fail(500, "Could not load learning plans.");
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
  if (audience === "targeted") {
    const u = await targetUniverse(c);
    targets = sanitizeTargets(body.targets, u.groupIds, u.memberIds);
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
  if (error) return fail(500, "Could not create the plan.");

  if (targets) {
    const sync = await targetSync(c, data.id, targets);
    if (!(await sync.add())) {
      // Don't leave a targeted plan with no recipients behind.
      await c.admin.from("assignments").delete().eq("id", data.id).eq("org_id", c.orgId);
      return fail(500, "Could not save the plan's recipients.");
    }
  }

  await logAudit({
    actorId: c.userId, action: "org.assignments.create", targetTable: "assignments", targetId: data.id,
    metadata: { orgId: c.orgId, items: items.length, audience, groups: targets?.group_ids.length ?? 0, users: targets?.user_ids.length ?? 0 },
  });
  return NextResponse.json({ id: data.id });
}

// ── PATCH — edit / reorder / retarget / archive ─────────────────────────────
export async function PATCH(req: Request) {
  const c = await staffGate("org.assignments.write");
  if ("error" in c) return c.error;
  const body = await readBody(req);
  if (!body) return fail(400, "Invalid JSON.");
  if (!isUuid(body.id)) return fail(400, "id is required.");
  const id = body.id;

  const { data: existing } = await c.admin.from("assignments")
    .select("id, audience, personal_user_id").eq("id", id).eq("org_id", c.orgId).maybeSingle();
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
  if ("items" in body) {
    const catalog = await getPlanCatalog(c.admin, c.orgId);
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
    if (audience === "targeted") {
      const u = await targetUniverse(c);
      targets = sanitizeTargets(body.targets, u.groupIds, u.memberIds);
      if (targets.group_ids.length + targets.user_ids.length === 0) return fail(400, "Choose at least one group or person, or assign it to the whole organisation.");
    }
    sync = await targetSync(c, id, targets);
  }
  if (!sync && Object.keys(patch).length === 0) return fail(400, "Nothing to update.");

  if (sync && !(await sync.add())) return fail(500, "Could not save the plan's recipients.");
  if (Object.keys(patch).length) {
    const { error } = await c.admin.from("assignments").update(patch).eq("id", id).eq("org_id", c.orgId);
    if (error) return fail(500, "Could not update the plan.");
  }
  if (sync && !(await sync.prune())) return fail(500, "The plan was saved, but old recipients could not be removed.");

  await logAudit({
    actorId: c.userId, action: "archived" in body ? (body.archived === true ? "org.assignments.archive" : "org.assignments.unarchive") : "org.assignments.update",
    targetTable: "assignments", targetId: id, metadata: { orgId: c.orgId, fields: Object.keys(patch) },
  });
  return NextResponse.json({ ok: true });
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
  if (error) return fail(500, "Could not delete the plan.");
  if (!data || data.length === 0) return fail(404, "No such plan in your organisation.");

  await logAudit({ actorId: c.userId, action: "org.assignments.delete", targetTable: "assignments", targetId: id, metadata: { orgId: c.orgId } });
  return NextResponse.json({ ok: true });
}
