import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * Right to deletion — the data subject's own endpoint.
 * See supabase/migrations/0027_account_deletion.sql for why there are two paths
 * (solo learner deletes now; enrolled student files a request their college
 * actions) and docs/PPA-COMPLIANCE-ASSESSMENT.md §5.1 for the obligation.
 *
 * The delete itself is a single auth.admin.deleteUser() call. Every per-user
 * table cascades from auth.users / public.profiles, so the database removes the
 * whole graph atomically; audit_log.actor_id is `on delete set null`, so the
 * security record survives without the identifier. There is deliberately no
 * hand-written table list here — see the migration header.
 */

const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

/** GET — what this account is, and whether a deletion request is already open. */
export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: profile } = await admin
    .from("profiles")
    .select("id, handle, display_name, org_id, xp")
    .eq("id", user.id)
    .maybeSingle();

  const orgId = profile?.org_id ?? INTERNAL_ORG;
  const enrolled = orgId !== INTERNAL_ORG;

  let orgName: string | null = null;
  if (enrolled) {
    const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
    orgName = org?.name ?? null;
  }

  const { data: openRequest } = await admin
    .from("account_deletion_requests")
    .select("id, status, requested_at, decided_at, decision_note")
    .eq("user_id", user.id)
    .eq("status", "pending")
    .maybeSingle();

  return NextResponse.json({
    handle: profile?.handle ?? null,
    display_name: profile?.display_name ?? null,
    xp: profile?.xp ?? 0,
    enrolled,
    org_name: orgName,
    deletion_request: openRequest ?? null,
  });
}

/**
 * DELETE — erase this account, or file the request that leads to it.
 *
 * Returns 200 when the account is gone, 202 when a request was filed and is
 * awaiting the college's decision. The distinction matters to the caller: one
 * means "you are signed out and erased", the other means "come back later".
 */
export async function DELETE(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* body is optional */ }

  // Typed confirmation. Deletion is irreversible and cascades across every
  // table, so a stray fetch or a mis-click must not be able to trigger it —
  // the client has to echo a specific word back.
  const confirm = String(body.confirm ?? "").trim().toUpperCase();
  if (confirm !== "DELETE") {
    return NextResponse.json(
      { error: "Confirmation required: send { confirm: \"DELETE\" }." },
      { status: 400 },
    );
  }

  const { data: profile } = await admin
    .from("profiles").select("org_id").eq("id", user.id).maybeSingle();
  const orgId = profile?.org_id ?? INTERNAL_ORG;

  // ── Enrolled student → file a request, do not delete ──────────────────────
  if (orgId !== INTERNAL_ORG) {
    const reason = typeof body.reason === "string" ? body.reason.trim().slice(0, 1000) : null;

    const { data: existing } = await admin
      .from("account_deletion_requests")
      .select("id, requested_at")
      .eq("user_id", user.id).eq("status", "pending")
      .maybeSingle();

    // Idempotent: clicking again returns the request already on file rather
    // than erroring on the partial unique index.
    if (existing) {
      return NextResponse.json(
        { status: "pending", request_id: existing.id, requested_at: existing.requested_at, already_open: true },
        { status: 202 },
      );
    }

    const { data: created, error } = await admin
      .from("account_deletion_requests")
      .insert({ user_id: user.id, org_id: orgId, reason })
      .select("id, requested_at")
      .single();
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });

    await logAudit({
      actorId: user.id,
      action: "account.deletion_requested",
      targetTable: "account_deletion_requests",
      targetId: created.id,
      metadata: { org_id: orgId },
    });

    return NextResponse.json(
      { status: "pending", request_id: created.id, requested_at: created.requested_at },
      { status: 202 },
    );
  }

  // ── Solo learner → erase now ──────────────────────────────────────────────
  // Audit BEFORE the delete: actor_id is `on delete set null`, so writing the
  // record first means it survives as an anonymised entry. Writing it after
  // would race the cascade and could land with no row to point at.
  await logAudit({
    actorId: user.id,
    action: "account.deleted_self",
    targetTable: "profiles",
    targetId: user.id,
    metadata: { org_id: orgId },
  });

  const { error } = await admin.auth.admin.deleteUser(user.id);
  if (error) {
    return NextResponse.json({ error: `Could not delete the account: ${error.message}` }, { status: 500 });
  }

  return NextResponse.json({ status: "deleted" });
}
