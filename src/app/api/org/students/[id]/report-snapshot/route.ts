import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isUuid } from "@/lib/plans/sanitize";
import { sanitizeReportMetrics, type ReportMetrics } from "@/lib/org/reportMetrics";

export const runtime = "nodejs";

type Ctx = { params: Promise<{ id: string }> };
const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

export interface ReportSnapshotResponse {
  /** The figures of the previous report on this learner in this org, if any. */
  previous: { created_at: string; metrics: ReportMetrics } | null;
  /** False when the snapshot could not be kept (e.g. migration 0110 not applied yet). */
  stored: boolean;
}

/**
 * Keeps the figures of the progress report an org admin is generating (migration 0110) and
 * returns the previous report's figures, so the PDF can say what changed since then.
 *
 * org_admin only, pinned to the caller's org, and the learner must be a member of it. The
 * figures come from the student page's data (GET /api/org/students/[id]); they are bounded
 * and re-shaped here, never stored as sent.
 */
export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireOrgAdmin("org.student_report");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return fail(400, "No organisation in session.");
  const admin = getSupabaseAdminClient();
  if (!admin) return fail(503, "Server not configured.");
  const { id } = await params;
  if (!isUuid(id)) return fail(404, "No such student in your organisation.");
  const { data: member } = await admin.from("org_members").select("user_id").eq("org_id", orgId).eq("user_id", id).maybeSingle();
  if (!member) return fail(404, "No such student in your organisation.");

  let raw: unknown;
  try {
    const text = await req.text();
    if (text.length > 32_000) return fail(413, "Too large.");
    raw = JSON.parse(text);
  } catch {
    return fail(400, "Invalid JSON.");
  }
  const metrics = sanitizeReportMetrics((raw as { metrics?: unknown } | null)?.metrics);
  if (!metrics) return fail(400, "metrics are required.");

  // The two latest snapshots: a report downloaded again within the hour compares with the one
  // before it (and is not stored twice), so re-downloading never turns into "no change".
  const { data: rows, error: readErr } = await admin.from("student_report_snapshots")
    .select("created_at, metrics").eq("org_id", orgId).eq("user_id", id)
    .order("created_at", { ascending: false }).limit(2);
  if (readErr) {
    // Before migration 0110: the report is still built, without the comparison.
    if (!/42P01|does not exist/i.test(`${readErr.code ?? ""} ${readErr.message}`)) console.error("[report snapshot] read failed:", readErr.message);
    return NextResponse.json({ previous: null, stored: false } satisfies ReportSnapshotResponse);
  }
  const recent = rows?.[0] && Date.now() - Date.parse(rows[0].created_at as string) < 3_600_000;
  const prev = recent ? rows?.[1] : rows?.[0];
  let insErr: { message: string } | null = null;
  if (!recent) ({ error: insErr } = await admin.from("student_report_snapshots").insert({ org_id: orgId, user_id: id, created_by: gate.user.id, metrics }));
  if (insErr) console.error("[report snapshot] insert failed:", insErr.message);
  const previous = prev ? { created_at: prev.created_at as string, metrics: sanitizeReportMetrics(prev.metrics) } : null;
  return NextResponse.json({
    previous: previous && previous.metrics ? { created_at: previous.created_at, metrics: previous.metrics } : null,
    stored: !recent && !insErr,
  } satisfies ReportSnapshotResponse, { headers: { "Cache-Control": "private, no-store" } });
}
