import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { generateCode } from "@/lib/org/classCode";

/**
 * Super-admin view of every org's affiliation code — the spec grants the
 * super-admin sight of ALL codes and the ability to generate for any org,
 * with no cooldown (the 24h limit binds org admins only).
 */

const INTERNAL_ORG = "d0d0d0d0-0000-4000-8000-000000000000";

/** GET — every real org, with its live code (or null) and last generation. */
export async function GET() {
  const gate = await requireSuperAdmin("superadmin.org_codes.list");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: orgs, error } = await admin
    .from("organizations")
    .select("id, name, slug, status")
    .neq("id", INTERNAL_ORG)
    .order("name");
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const nowIso = new Date().toISOString();
  const { data: codes } = await admin
    .from("org_codes")
    .select("org_id, code, created_at, expires_at")
    .order("created_at", { ascending: false });

  // Newest row per org; live only if still inside its 24h window.
  const latestByOrg = new Map<string, { code: string; created_at: string; expires_at: string }>();
  for (const c of codes ?? []) {
    if (!latestByOrg.has(c.org_id)) latestByOrg.set(c.org_id, c);
  }

  return NextResponse.json({
    orgs: (orgs ?? []).map(o => {
      const latest = latestByOrg.get(o.id) ?? null;
      const live = latest && latest.expires_at > nowIso ? latest : null;
      return {
        id: o.id, name: o.name, slug: o.slug, status: o.status,
        active_code: live,
        last_generated_at: latest?.created_at ?? null,
      };
    }),
  });
}

/** POST { org_id } — generate for any org. No cooldown for the super-admin. */
export async function POST(req: Request) {
  const gate = await requireSuperAdmin("superadmin.org_codes.generate");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const orgId = String(body.org_id ?? "").trim();
  if (!orgId) return NextResponse.json({ error: "org_id is required." }, { status: 400 });
  if (orgId === INTERNAL_ORG) {
    return NextResponse.json({ error: "The internal org does not take affiliation codes." }, { status: 400 });
  }

  const { data: org } = await admin.from("organizations").select("id").eq("id", orgId).maybeSingle();
  if (!org) return NextResponse.json({ error: "No such organisation." }, { status: 404 });

  try {
    const active = await generateCode(admin, orgId, gate.user.id);
    await logAudit({
      actorId: gate.user.id, action: "superadmin.org_code.generated",
      targetTable: "org_codes", metadata: { org_id: orgId },
    });
    return NextResponse.json({ active });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Generation failed." }, { status: 500 });
  }
}
