import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Org-admin queue for right-to-deletion requests filed by that college's own
 * students (see supabase/migrations/0027_account_deletion.sql).
 *
 * Scoping follows the same rule as the rest of /api/org/*: the org id comes
 * from the caller's session, never from a request parameter, and every query is
 * pinned to it. Approving a request performs an irreversible auth-user delete,
 * so it lives behind requireOrgAdmin and the service-role client rather than
 * behind an RLS UPDATE policy a session token could reach.
 */

async function callerOrg() {
  const gate = await requireOrgAdmin("org.deletion_requests");
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, admin, adminId: gate.user.id };
}

/** GET — open requests for this org, oldest first (the 30-day clock runs from `requested_at`). */
export async function GET() {
  const c = await callerOrg();
  if ("error" in c) return c.error;
  const { orgId, admin } = c;

  const { data, error } = await admin
    .from("account_deletion_requests")
    .select("id, user_id, status, reason, requested_at, profiles(handle, display_name)")
    .eq("org_id", orgId)
    .eq("status", "pending")
    .order("requested_at", { ascending: true });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const requests = (data ?? []).map(r => {
    const p = r.profiles as unknown as { handle?: string; display_name?: string } | null;
    return {
      id: r.id,
      user_id: r.user_id,
      handle: p?.handle ?? null,
      display_name: p?.display_name ?? null,
      reason: r.reason,
      requested_at: r.requested_at,
      // Surfaced so an admin can see the statutory clock rather than infer it.
      days_open: Math.floor((Date.now() - new Date(r.requested_at).getTime()) / 86_400_000),
    };
  });

  return NextResponse.json({ requests });
}

/** POST — decide a request: { id, decision: "approve" | "reject", note? }. */
export async function POST(req: Request) {
  const c = await callerOrg();
  if ("error" in c) return c.error;
  const { orgId, admin, adminId } = c;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const id = String(body.id ?? "").trim();
  const decision = String(body.decision ?? "").trim();
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 1000) : null;
  if (!id) return NextResponse.json({ error: "id is required." }, { status: 400 });
  if (decision !== "approve" && decision !== "reject") {
    return NextResponse.json({ error: "decision must be \"approve\" or \"reject\"." }, { status: 400 });
  }

  // Both .eq()s scope the read to (this org, this request). A request id from
  // another college matches nothing and stops here — the same cross-tenant IDOR
  // guard the members route needed.
  const { data: reqRow, error: findErr } = await admin
    .from("account_deletion_requests")
    .select("id, user_id, status")
    .eq("id", id).eq("org_id", orgId)
    .maybeSingle();
  if (findErr) return NextResponse.json({ error: findErr.message }, { status: 500 });
  if (!reqRow) return NextResponse.json({ error: "No such request in your organisation." }, { status: 404 });
  if (reqRow.status !== "pending") {
    return NextResponse.json({ error: "That request has already been decided." }, { status: 409 });
  }

  if (decision === "reject") {
    const { error } = await admin
      .from("account_deletion_requests")
      .update({ status: "rejected", decided_by: adminId, decided_at: new Date().toISOString(), decision_note: note })
      .eq("id", id).eq("org_id", orgId);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    await logAudit({
      actorId: adminId, action: "account.deletion_rejected",
      targetTable: "account_deletion_requests", targetId: id,
      metadata: { org_id: orgId, subject: reqRow.user_id },
    });
    return NextResponse.json({ ok: true, status: "rejected" });
  }

  // ── Approve ───────────────────────────────────────────────────────────────
  // Mark completed BEFORE deleting. The request row cascades away with the
  // user (user_id → profiles → auth.users), so an update afterwards would have
  // nothing to write to. Recording the decision first also means a failure
  // between the two steps leaves evidence that the decision was taken.
  const { error: markErr } = await admin
    .from("account_deletion_requests")
    .update({ status: "completed", decided_by: adminId, decided_at: new Date().toISOString(), decision_note: note })
    .eq("id", id).eq("org_id", orgId);
  if (markErr) return NextResponse.json({ error: markErr.message }, { status: 500 });

  await logAudit({
    actorId: adminId, action: "account.deletion_approved",
    targetTable: "profiles", targetId: reqRow.user_id,
    metadata: { org_id: orgId, request_id: id },
  });

  const { error: delErr } = await admin.auth.admin.deleteUser(reqRow.user_id);
  if (delErr) {
    // Reopen so the request doesn't silently vanish from the queue with the
    // account still live — that would look "handled" while the obligation is
    // still outstanding.
    await admin.from("account_deletion_requests")
      .update({ status: "pending", decided_by: null, decided_at: null })
      .eq("id", id).eq("org_id", orgId);
    return NextResponse.json({ error: `Could not delete the account: ${delErr.message}` }, { status: 500 });
  }

  return NextResponse.json({ ok: true, status: "completed" });
}
