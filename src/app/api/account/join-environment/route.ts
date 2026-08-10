import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { AFFILIATION_DAYS } from "@/lib/org/classCode";

/**
 * An EXISTING account redeems an access code → joins that environment and
 * switches into it. This is the multi-environment door for regular users:
 * before it existed, a registered student entering a second college's code
 * dead-ended at "User already registered" — the signup path can only create
 * accounts, and nothing else knew how to redeem a code.
 *
 * Memberships ACCUMULATE (joining B keeps A); the newly joined environment
 * becomes the active context. Unlike the super-admin's /superadmin/enter-org,
 * this path keeps every gate a real member passes through:
 *   - a live access code is required (same validation as signup);
 *   - the seat cap holds — attach_member_if_seat_available raises
 *     seat_limit_reached atomically, and also flips profiles.org_id, so the
 *     context switch rides the same serialised operation;
 *   - students get the 100-day affiliation clock in the NEW environment.
 *
 * One asymmetry is deliberate: if the caller is already org_admin/instructor
 * of the code's org, we only switch context — running attach with 'student'
 * would silently DEMOTE them for redeeming their own class's code.
 */
export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const code = String(body.code ?? "").trim().toUpperCase();
  if (!code) return NextResponse.json({ error: "code is required." }, { status: 400 });

  // Same liveness rules the signup trigger applies.
  const { data: codeRow } = await admin
    .from("org_codes").select("org_id")
    .eq("code", code).gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (!codeRow) {
    return NextResponse.json({ error: "That access code isn't valid or has expired. Ask for today's code." }, { status: 400 });
  }
  const { data: org } = await admin
    .from("organizations").select("id, name, status")
    .eq("id", codeRow.org_id).maybeSingle();
  if (!org || !["active", "trial"].includes(org.status)) {
    return NextResponse.json({ error: "That access code isn't valid or has expired. Ask for today's code." }, { status: 400 });
  }

  const { data: existing } = await admin
    .from("org_members").select("role, status")
    .eq("org_id", org.id).eq("user_id", user.id).maybeSingle();

  if (existing?.status === "active" && ["org_admin", "instructor"].includes(existing.role)) {
    // Staff of this org — context switch only, never a demotion.
    const { error } = await admin.from("profiles").update({ org_id: org.id }).eq("id", user.id);
    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  } else {
    // Join (or reactivate) as a student, seat-capped and atomic. The function
    // also sets profiles.org_id, so the switch cannot detach from the join.
    const { error } = await admin.rpc("attach_member_if_seat_available", {
      p_org: org.id, p_user: user.id, p_role: "student",
    });
    if (error) {
      if ((error.message ?? "").includes("seat_limit_reached")) {
        return NextResponse.json({ error: `${org.name} has no seats left. Ask your instructor to free one up.` }, { status: 409 });
      }
      return NextResponse.json({ error: error.message }, { status: 500 });
    }
    await admin.from("org_members")
      .update({ affiliation_expires_at: new Date(Date.now() + AFFILIATION_DAYS * 86_400_000).toISOString() })
      .eq("org_id", org.id).eq("user_id", user.id);
  }

  await logAudit({
    actorId: user.id, action: "account.joined_environment",
    targetTable: "organizations", targetId: org.id, metadata: { via: "access_code" },
  });

  return NextResponse.json({ ok: true, org_name: org.name });
}
