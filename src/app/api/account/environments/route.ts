import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { dbFail } from "@/lib/http/dbFail";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";

/**
 * A regular user's OWN environments (multi-tenant): list the ones they belong to and
 * switch the active one. A user accumulates memberships by redeeming a second access
 * code (see /api/account/join-environment); this is the everyday switcher for moving
 * between them (the super-admin has their own cross-tenant /superadmin/enter-org).
 *
 * Active context = profiles.org_id — the access-token hook (0086) stamps the JWT org
 * claims from the membership that matches it. A guard trigger (0005) blocks client
 * writes to profiles.org_id, so the switch goes through the service role AFTER verifying
 * the caller is an active member of the target org (you can only switch into your own).
 */
export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: mems, error } = await admin
    .from("org_members").select("org_id, role").eq("user_id", user.id).eq("status", "active");
  if (error) return dbFail(error, "api/account/environments", 500);
  const ids = (mems ?? []).map(m => m.org_id);
  // org_members → organizations is a real FK, but fetch names separately and merge to
  // avoid a silent-empty PostgREST embed (the project's known embed gotcha).
  const nameById = new Map<string, string>();
  if (ids.length) {
    const { data: orgs } = await admin.from("organizations").select("id, name").in("id", ids);
    for (const o of orgs ?? []) nameById.set(o.id, o.name);
  }
  const environments = (mems ?? [])
    .map(m => ({ org_id: m.org_id, name: nameById.get(m.org_id) ?? "Environment", role: m.role, is_current: m.org_id === user.orgId }))
    .sort((a, b) => a.name.localeCompare(b.name));
  return NextResponse.json({ environments, current_org_id: user.orgId }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  const orgId = String(body.org_id ?? "").trim();
  if (!orgId) return NextResponse.json({ error: "org_id is required." }, { status: 400 });
  if (orgId === user.orgId) return NextResponse.json({ ok: true, unchanged: true });

  // Security: you can only switch INTO an environment you are an active member of.
  const { data: mem, error: memErr } = await admin
    .from("org_members").select("org_id").eq("user_id", user.id).eq("org_id", orgId).eq("status", "active").maybeSingle();
  if (memErr) return dbFail(memErr, "api/account/environments", 500);
  if (!mem) return NextResponse.json({ error: "You're not a member of that environment." }, { status: 403 });

  const { data: org } = await admin.from("organizations").select("name").eq("id", orgId).maybeSingle();
  const { error: profErr } = await admin.from("profiles").update({ org_id: orgId }).eq("id", user.id);
  if (profErr) return dbFail(profErr, "api/account/environments", 500);

  await logAudit({ actorId: user.id, action: "account.switched_environment", targetTable: "organizations", targetId: orgId, metadata: { org_name: org?.name ?? null } });
  return NextResponse.json({ ok: true, org_name: org?.name ?? null });
}
