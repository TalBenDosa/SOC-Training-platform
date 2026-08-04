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
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const row = Array.isArray(data) ? data[0] : data;
  if (!row) return NextResponse.json({ valid: false }, { status: 404 });

  return NextResponse.json({
    valid: row.valid === true,
    orgName: row.org_name ?? null,
    role: row.role ?? "student",
    email: row.email ?? null,
  });
}
