import { NextResponse, after } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getPlanCatalog, needsOrgCatalog } from "@/lib/plans/catalog";
import { cleanLine, cleanText, isUuid, parseDueDate, parsePriority, sanitizePlanItems } from "@/lib/plans/sanitize";
import {
  ASSIGNMENT_COLUMNS, PlanDataError, loadLearnerPlans, loadProgress, resolveItems, toPlanDataError, type AssignmentDbRow,
} from "@/lib/plans/server";
import { PLAN_LIMITS, type LearnerPlan, type Priority, type ResolvedPlanItem } from "@/lib/plans/types";
import { deliverNotifications, emailOrigin, itemSetChanged, noticeText, planEmailsEnabled, settleEmailJob, type EmailReport } from "@/lib/plans/notify";

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
 *
 * A save that changes the SET of items (added or removed — not a reorder / note
 * edit) notifies the learner in-app ("personal_plan", migration 0076), and —
 * with `notify_email: true` — emails them too (budgeted + deduped, see
 * src/lib/plans/notify.ts). Clearing the plan notifies nobody. A notification
 * or email failure never fails the save.
 */

export const runtime = "nodejs";
// A slow email provider finishes in after(), inside this time budget.
export const maxDuration = 300;
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
  /** Plan emails available (else the "Also email" box is hidden). */
  email_enabled?: boolean;
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
      email_enabled: planEmailsEnabled(),
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

  // The current item set, to decide afterwards whether the learner is told.
  const { data: prev, error: prevErr } = await admin.from("assignments").select("items")
    .eq("org_id", orgId).eq("personal_user_id", studentId).maybeSingle();
  if (prevErr) return dataFail(toPlanDataError(prevErr, "read"), "read", "Could not save the plan.");
  const prevItems = sanitizePlanItems(prev?.items, () => true);

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

  // Tell the learner when what they have to do changed (best effort).
  const emailLearner = body.notify_email === true;
  let notified = 0;
  let email: EmailReport | null = null;
  if (studentId !== userId && itemSetChanged(prevItems, items)) {
    try {
      const text = noticeText("personal_plan", { title: "Personal priorities", due_at: due.value }, items.flatMap(i => {
        const e = catalog.index.get(`${i.kind}:${i.id}`);
        return e ? [{ title: e.title, href: e.href }] : [];
      }));
      const res = await deliverNotifications(admin, {
        orgId, actorId: userId, assignmentId: data.id,
        batches: [{ kind: "personal_plan", userIds: [studentId], ...text }],
        // Verified above: an active member of this org, not a platform admin.
        eligible: new Set([studentId]),
        email: emailLearner, origin: emailOrigin(req), planTitle: "Personal priorities",
      });
      notified = res.notified;
      if (res.emailJob) {
        email = await settleEmailJob(res.emailJob, task => after(task), r => logAudit({
          actorId: userId, action: "org.student_plan.notify_email", targetTable: "assignments", targetId: data.id,
          metadata: { orgId, studentId, email: r },
        }), res.notified);
      }
    } catch (e) {
      console.error("[student plan] notify failed:", e instanceof Error ? e.message : e);
    }
  }

  await logAudit({
    actorId: userId, action: "org.student_plan.save", targetTable: "assignments", targetId: data.id,
    metadata: { orgId, studentId, items: items.length, notified, email_requested: emailLearner, email },
  });
  return NextResponse.json({ ok: true, id: data.id, notified, email });
}
