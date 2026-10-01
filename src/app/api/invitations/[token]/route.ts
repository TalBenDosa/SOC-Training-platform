import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

type Ctx = { params: Promise<{ token: string }> };

/**
 * Public (pre-signup) lookup for the /join page: given an invitation token,
 * return the org name, role and whether it's still valid — nothing more. Backed
 * by the resolve_invitation() definer function; exposed by token only, so it
 * leaks nothing an invitee doesn't already hold. Exempt from the API session
 * gate (see PUBLIC_API_PREFIXES) because it runs before an account exists.
 */
export async function GET(_req: Request, { params }: Ctx) {
  const { token } = await params;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin.rpc("resolve_invitation", { p_token: token });
  if (error) {
    console.error("[invitations] resolve failed:", error.message);
    return NextResponse.json({ error: "Couldn't check this invitation — please try again." }, { status: 500 });
  }

  const row = Array.isArray(data) ? data[0] : data;
  if (!row) return NextResponse.json({ valid: false }, { status: 404 });

  // Whether the college still has a free seat (P5-04) — the signup page checks
  // it before submitting; the trigger's own "seat_limit_reached" never reaches
  // the browser in a readable form.
  let seatsAvailable = true;
  if (row.valid === true && row.org_id) {
    const { data: org } = await admin.from("organizations").select("seat_limit").eq("id", row.org_id).maybeSingle();
    if (org?.seat_limit && org.seat_limit > 0) {
      const { data: used } = await admin.rpc("org_seats_used", { p_org: row.org_id });
      if (typeof used === "number") seatsAvailable = used < org.seat_limit;
    }
  }

  return NextResponse.json({
    valid: row.valid === true,
    orgName: row.org_name ?? null,
    role: row.role ?? "student",
    email: row.email ?? null,
    seatsAvailable,
  });
}
