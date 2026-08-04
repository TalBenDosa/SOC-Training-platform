import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

type Ctx = { params: Promise<{ id: string }> };

const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

// ── POST /api/superadmin/orgs/[id]/members — attach an EXISTING user by email ─
// Enrollment of NEW students (invite links / domain / CSV) is Phase 2; here the
// super-admin attaches an account that already exists. Seat cap is enforced
// atomically by attach_member_if_seat_available().
export async function POST(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.member.add");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const email = String(body.email ?? "").trim();
  const role = String(body.role ?? "student");
  if (!email) return NextResponse.json({ error: "Email is required." }, { status: 400 });
  if (!["org_admin", "instructor", "student"].includes(role)) {
    return NextResponse.json({ error: "Invalid role." }, { status: 400 });
  }

  const { data: userId, error: lookupErr } = await admin.rpc("find_user_id_by_email", { p_email: email });
  if (lookupErr) return NextResponse.json({ error: lookupErr.message }, { status: 500 });
  if (!userId) {
    return NextResponse.json(
      { error: `No account exists for ${email}. They must sign up first (self-enrollment arrives in Phase 2).` },
      { status: 404 },
    );
  }

  const { data: result, error } = await admin.rpc("attach_member_if_seat_available", {
    p_org: orgId, p_user: userId, p_role: role,
  });
  if (error) {
    if (error.message.includes("seat_limit_reached")) {
      return NextResponse.json({ error: "The organization has reached its seat limit." }, { status: 409 });
    }
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
  return NextResponse.json({ ok: true, result });
}

// ── DELETE /api/superadmin/orgs/[id]/members — remove a member (frees a seat) ─
export async function DELETE(req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.member.remove");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id: orgId } = await params;

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const userId = String(body.user_id ?? "").trim();
  if (!userId) return NextResponse.json({ error: "user_id is required." }, { status: 400 });

  const { error } = await admin.from("org_members").delete().eq("org_id", orgId).eq("user_id", userId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  // Re-home the profile to the internal org so its NOT NULL org_id isn't left
  // pointing at an org they're no longer in. Their JWT (no active membership)
  // will carry no org, so access fails closed until they're re-assigned.
  await admin.from("profiles").update({ org_id: INTERNAL_ORG }).eq("id", userId);

  return NextResponse.json({ ok: true });
}
