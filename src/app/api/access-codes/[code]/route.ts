import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Pre-signup access-code lookup — the code-gate twin of /api/invitations/[token].
 *
 * The entry flow is code-FIRST (Get access → enter code → registration form),
 * so the gate needs to know "is this a real, live code, and which college is
 * it?" before any account exists. Public by necessity (listed in the
 * middleware's PUBLIC_API_PREFIXES): the caller is by definition not signed in.
 *
 * Returns ONLY { valid, orgName } — no org id, no code metadata, no expiry.
 * Enumeration is not a practical risk (8 chars from a 31-letter alphabet is
 * ~8.5e11 combinations against a 24-hour-lived code, behind the middleware
 * rate limit), and the org NAME is what the next screen shows the student
 * anyway ("You're joining POC").
 *
 * Validation here is a UX courtesy: the trigger re-validates at signup, so a
 * code that expires between this check and submission still fails safely.
 */
type Ctx = { params: Promise<{ code: string }> };

export async function GET(_req: Request, { params }: Ctx) {
  const { code } = await params;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const cleaned = decodeURIComponent(code).trim().toUpperCase();
  if (!/^[A-Z0-9]{6,12}$/.test(cleaned)) {
    return NextResponse.json({ valid: false });
  }

  const { data: row } = await admin
    .from("org_codes")
    .select("org_id, expires_at")
    .eq("code", cleaned)
    .gt("expires_at", new Date().toISOString())
    .maybeSingle();
  if (!row) return NextResponse.json({ valid: false });

  const { data: org } = await admin
    .from("organizations")
    .select("name, status")
    .eq("id", row.org_id)
    .maybeSingle();
  if (!org || !["active", "trial"].includes(org.status)) {
    return NextResponse.json({ valid: false });
  }

  return NextResponse.json({ valid: true, orgName: org.name });
}
