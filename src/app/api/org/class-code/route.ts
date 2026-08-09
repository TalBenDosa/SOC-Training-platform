import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { getActiveCode, generateCode, nextGenerateAt, CODE_TTL_HOURS, AFFILIATION_DAYS } from "@/lib/org/classCode";

/**
 * The org admin's affiliation code (קוד שיוך) — see 0028_org_codes.sql.
 * GET returns the live code (if any) plus when a new one may be generated;
 * POST generates, at most once per 24h for an org admin. The platform
 * super-admin is exempt from the cooldown but generates for *their own token's
 * org* here — cross-org generation lives in /api/superadmin/org-codes.
 */

async function caller() {
  const gate = await requireOrgAdmin("org.class_code");
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, admin, user: gate.user };
}

export async function GET() {
  const c = await caller();
  if ("error" in c) return c.error;
  const [active, nextAt] = await Promise.all([
    getActiveCode(c.admin, c.orgId),
    nextGenerateAt(c.admin, c.orgId),
  ]);
  return NextResponse.json({
    active,
    next_generate_at: nextAt,
    code_ttl_hours: CODE_TTL_HOURS,
    affiliation_days: AFFILIATION_DAYS,
  });
}

export async function POST() {
  const c = await caller();
  if ("error" in c) return c.error;

  // One generation per 24h — the spec's "אחד חדש כל יום". The super-admin is
  // exempt: the spec explicitly grants them unrestricted generation.
  if (!c.user.isPlatformAdmin) {
    const nextAt = await nextGenerateAt(c.admin, c.orgId);
    if (nextAt) {
      return NextResponse.json(
        { error: "A code was already generated in the last 24 hours.", next_generate_at: nextAt },
        { status: 429 },
      );
    }
  }

  try {
    const active = await generateCode(c.admin, c.orgId, c.user.id);
    await logAudit({
      actorId: c.user.id, action: "org.class_code.generated",
      targetTable: "org_codes", metadata: { org_id: c.orgId },
    });
    return NextResponse.json({ active });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Generation failed." }, { status: 500 });
  }
}
