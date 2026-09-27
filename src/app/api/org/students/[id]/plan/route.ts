import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getPlanCatalog, needsOrgCatalog } from "@/lib/plans/catalog";
import { cleanLine, cleanText, isUuid, parseDueDate, parsePriority, sanitizePlanItems } from "@/lib/plans/sanitize";
import { ASSIGNMENT_COLUMNS, loadLearnerPlans, loadProgress, resolveItems, type AssignmentDbRow } from "@/lib/plans/server";
import { PLAN_LIMITS, type LearnerPlan, type Priority, type ResolvedPlanItem } from "@/lib/plans/types";

/**
 * One learner's PERSONAL plan (migration 0075: assignments.personal_user_id —
 * unique per org) — "David gets lessons X, Y and practice Z".
 *
 * GET returns the personal plan (ordered items, priority, note, the learner's
 * status on each) plus every OTHER plan that reaches this learner (org-wide,
 * direct, via a group), so the manager sees the learner's whole workload.
 * PUT replaces the personal plan; an empty item list removes it.
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
  const { data: member } = await admin.from("org_members").select("user_id").eq("org_id", orgId).eq("user_id", id).maybeSingle();
  if (!member) return { error: fail(404, "No such student in your organisation.") };
  return { orgId, admin, userId: gate.user.id, studentId: id };
}

// ── GET ──────────────────────────────────────────────────────────────────────
export async function GET(_req: Request, { params }: Ctx) {
  const c = await context("org.student_plan.read", params);
  if ("error" in c) return c.error;
  const { orgId, admin, studentId } = c;

  try {
    const { data: row, error } = await admin.from("assignments").select(ASSIGNMENT_COLUMNS)
      .eq("org_id", orgId).eq("personal_user_id", studentId).maybeSingle();
    if (error) throw new Error(error.message);
    const r = row as AssignmentDbRow | null;

    const [all, catalog, idx] = await Promise.all([
      loadLearnerPlans(admin, orgId, studentId),
      getPlanCatalog(admin, orgId, needsOrgCatalog([r?.items])),
      loadProgress(admin, orgId, studentId),
    ]);

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
    console.error("[student plan] read failed:", e instanceof Error ? e.message : e);
    return fail(500, "Could not load this learner's plan.");
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

  const { data: existing } = await admin.from("assignments").select("id")
    .eq("org_id", orgId).eq("personal_user_id", studentId).maybeSingle();

  if (items.length === 0) {
    if (existing) {
      const { error } = await admin.from("assignments").delete().eq("id", existing.id).eq("org_id", orgId);
      if (error) return fail(500, "Could not clear the plan.");
      await logAudit({ actorId: userId, action: "org.student_plan.clear", targetTable: "assignments", targetId: existing.id, metadata: { orgId, studentId } });
    }
    return NextResponse.json({ ok: true, id: null });
  }

  const fields = {
    title: cleanLine(body.title, PLAN_LIMITS.title) || "Personal priorities",
    instructions: cleanText(body.instructions, PLAN_LIMITS.instructions) || null,
    items,
    due_at: due.value,
    priority: parsePriority(body.priority, 1),
    archived_at: null,
  };

  let id: string;
  if (existing) {
    const { error } = await admin.from("assignments").update(fields).eq("id", existing.id).eq("org_id", orgId);
    if (error) return fail(500, "Could not save the plan.");
    id = existing.id;
  } else {
    const { data, error } = await admin.from("assignments").insert({
      ...fields, org_id: orgId, audience: "targeted", personal_user_id: studentId, created_by: userId,
    }).select("id").single();
    if (error) return fail(500, "Could not save the plan.");
    id = data.id;
  }

  await logAudit({ actorId: userId, action: "org.student_plan.save", targetTable: "assignments", targetId: id, metadata: { orgId, studentId, items: items.length } });
  return NextResponse.json({ ok: true, id });
}
