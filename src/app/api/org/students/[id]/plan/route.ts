import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getPlanCatalog, needsOrgCatalog } from "@/lib/plans/catalog";
import { cleanLine, cleanText, isUuid, parseDueDate, parsePriority, sanitizePlanItems } from "@/lib/plans/sanitize";
import {
  ASSIGNMENT_COLUMNS, PlanDataError, loadLearnerPlans, loadProgress, resolveItems, toPlanDataError, type AssignmentDbRow,
} from "@/lib/plans/server";
import { PLAN_LIMITS, type LearnerPlan, type Priority, type ResolvedPlanItem } from "@/lib/plans/types";

/**
 * One learner's PERSONAL plan (migration 0075: assignments.personal_user_id —
 * unique per org) — "David gets lessons X, Y and practice Z".
 *
 * GET returns the personal plan (ordered items, priority, note, the learner's
 * status on each) plus every OTHER plan that reaches this learner (org-wide,
 * direct, via a group), so the manager sees the learner's whole workload.
 * PUT replaces the personal plan (an upsert on the (org_id, personal_user_id)
 * unique key, so two concurrent first saves can't collide); an empty item list
 * removes it. Only an ACTIVE member (not invited/removed, never the platform
 * super-admin) can be given a personal plan.
 *
 * org_admin only, pinned to the caller's org, and the learner is verified to be
 * a member of THAT org before anything is read or written.
 */

export const runtime = "nodejs";
type Ctx = { params: Promise<{ id: string }> };

const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

export interface PersonalPlanResponse {
  personal: {
    id: string;
    title: string;
    instructions: string | null;
    due_at: string | null;
    priority: Priority;
    items: ResolvedPlanItem[];
    updated_at: string;
  } | null;
  /** Other plans this learner receives (not editable here). */
  assigned: LearnerPlan[];
}

/** Generic failure; a schema error (code ahead of migration 0075) is a 503. */
function dataFail(e: unknown, context: string, message: string) {
  console.error(`[student plan] ${context}:`, e instanceof Error ? e.message : e);
  if (e instanceof PlanDataError && e.kind === "schema") return fail(503, "Learning plans aren't available yet. Please try again shortly.");
  return fail(500, message);
}

async function context(action: string, params: Ctx["params"]) {
  const gate = await requireOrgAdmin(action);
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: fail(400, "No organisation in session.") };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: fail(503, "Server not configured.") };
  const { id } = await params;
  if (!isUuid(id)) return { error: fail(404, "No such student in your organisation.") };

  // The learner MUST belong to the caller's org — verified before any read/write.
  const { data: member } = await admin.from("org_members")
    .select("user_id, status, profiles(is_platform_admin)").eq("org_id", orgId).eq("user_id", id).maybeSingle();
  if (!member) return { error: fail(404, "No such student in your organisation.") };
  const isPlatformAdmin = Boolean((member.profiles as { is_platform_admin?: boolean } | null)?.is_platform_admin);
  return { orgId, admin, userId: gate.user.id, studentId: id, active: member.status === "active" && !isPlatformAdmin };
}

// ── GET ──────────────────────────────────────────────────────────────────────
export async function GET(_req: Request, { params }: Ctx) {
  const c = await context("org.student_plan.read", params);
  if ("error" in c) return c.error;
  const { orgId, admin, studentId } = c;

  try {
    const { data: row, error } = await admin.from("assignments").select(ASSIGNMENT_COLUMNS)
      .eq("org_id", orgId).eq("personal_user_id", studentId).maybeSingle();
    if (error) throw toPlanDataError(error, "personal plan");
    const r = row as AssignmentDbRow | null;

    const [all, catalog] = await Promise.all([
      // "org": a manager sees only progress earned inside their own org.
      loadLearnerPlans(admin, orgId, studentId, "org"),
      getPlanCatalog(admin, orgId, needsOrgCatalog([r?.items])),
    ]);
    const idx = await loadProgress(admin, {
      orgId, userIds: [studentId], items: sanitizePlanItems(r?.items, catalog.isKnown),
    });

    const body: PersonalPlanResponse = {
      personal: r ? {
        id: r.id,
        title: r.title,
        instructions: r.instructions,
        due_at: r.due_at,
        priority: parsePriority(r.priority) as Priority,
        items: resolveItems(r.items, catalog, { idx, userId: studentId }),
        updated_at: r.updated_at,
      } : null,
      assigned: all.filter(p => !p.personal),
    };
    return NextResponse.json(body);
  } catch (e) {
    return dataFail(e, "read failed", "Could not load this learner's plan.");
  }
}

// ── PUT — replace the personal plan (empty items = remove it) ───────────────
export async function PUT(req: Request, { params }: Ctx) {
  const c = await context("org.student_plan.write", params);
  if ("error" in c) return c.error;
  const { orgId, admin, userId, studentId } = c;

  let body: Record<string, unknown>;
  try {
    const b = await req.json();
    if (!b || typeof b !== "object" || Array.isArray(b)) return fail(400, "Invalid JSON.");
    body = b as Record<string, unknown>;
  } catch { return fail(400, "Invalid JSON."); }

  const catalog = await getPlanCatalog(admin, orgId);
  const items = sanitizePlanItems(body.items, catalog.isKnown);
  const due = parseDueDate(body.due_at);
  if (!due.ok) return fail(400, "Invalid due date.");

  if (items.length === 0) {
    // Clearing is allowed whatever the learner's status.
    const { data: removed, error } = await admin.from("assignments").delete()
      .eq("org_id", orgId).eq("personal_user_id", studentId).select("id");
    if (error) return dataFail(toPlanDataError(error, "clear"), "clear", "Could not clear the plan.");
    if (removed && removed.length) {
      await logAudit({ actorId: userId, action: "org.student_plan.clear", targetTable: "assignments", targetId: removed[0].id, metadata: { orgId, studentId } });
    }
    return NextResponse.json({ ok: true, id: null });
  }

  if (!c.active) return fail(400, "Personal priorities can only be set for active learners.");

  // One statement, keyed on the (org_id, personal_user_id) unique constraint:
  // two managers saving the same learner's first plan at once both succeed
  // (last write wins) instead of one hitting a duplicate-key error.
  const { data, error } = await admin.from("assignments").upsert({
    org_id: orgId,
    personal_user_id: studentId,
    audience: "targeted",
    title: cleanLine(body.title, PLAN_LIMITS.title) || "Personal priorities",
    instructions: cleanText(body.instructions, PLAN_LIMITS.instructions) || null,
    items,
    due_at: due.value,
    priority: parsePriority(body.priority, 1),
    archived_at: null,
  }, { onConflict: "org_id,personal_user_id" }).select("id, created_by").single();
  if (error) return dataFail(toPlanDataError(error, "save"), "save", "Could not save the plan.");

  // Record the author on first creation only (the upsert payload omits it so an
  // edit never rewrites who created the plan).
  if (!data.created_by) {
    await admin.from("assignments").update({ created_by: userId }).eq("id", data.id).eq("org_id", orgId).is("created_by", null);
  }

  await logAudit({ actorId: userId, action: "org.student_plan.save", targetTable: "assignments", targetId: data.id, metadata: { orgId, studentId, items: items.length } });
  return NextResponse.json({ ok: true, id: data.id });
}
