import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * The 100-day renewal door (see 0028_org_codes.sql): an org student whose
 * affiliation clock ran out enters a CURRENT class code to reset it.
 *
 * Validation lives in the SECURITY DEFINER function renew_affiliation(), not
 * here — same-org-only, live-code-only — so the rule cannot drift between this
 * route and any future caller. This route only authenticates the user and maps
 * the function's exceptions to actionable messages.
 *
 * Deliberately reachable by a student whose affiliation HAS expired: this is
 * the one door an expired student must still be able to open.
 */
export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const code = String(body.code ?? "").trim();
  if (!code) return NextResponse.json({ error: "code is required." }, { status: 400 });

  const { error } = await admin.rpc("renew_affiliation", { p_user: user.id, p_code: code });
  if (error) {
    const msg = error.message ?? "";
    if (msg.includes("org_code_invalid")) {
      return NextResponse.json({ error: "That code isn't valid. Ask your instructor for today's code." }, { status: 400 });
    }
    if (msg.includes("org_code_wrong_org")) {
      return NextResponse.json({ error: "That code belongs to a different institution." }, { status: 400 });
    }
    if (msg.includes("not_an_org_student")) {
      return NextResponse.json({ error: "Only enrolled students renew an affiliation." }, { status: 400 });
    }
    return NextResponse.json({ error: msg }, { status: 500 });
  }

  await logAudit({
    actorId: user.id, action: "account.affiliation_renewed",
    targetTable: "org_members", metadata: { org_id: user.orgId },
  });
  return NextResponse.json({ ok: true });
}
