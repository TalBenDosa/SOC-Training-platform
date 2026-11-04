import { NextResponse } from "next/server";
import { dbFail } from "@/lib/http/dbFail";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { orgRoomsLocked, isMissingColumn } from "@/lib/org/roomLock";

/**
 * The org admin's own college settings. Today: whether Learning Rooms are locked
 * behind their prerequisites (organizations.rooms_locked, 0102). Rooms are open by
 * default; locking is the college admin's decision. Scoped to the org in the
 * caller's JWT, never another org's; written with the service role.
 */

async function caller(action: string) {
  const gate = await requireOrgAdmin(action);
  if ("error" in gate) return { error: gate.error };
  const orgId = gate.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, admin, user: gate.user };
}

export async function GET() {
  const c = await caller("org.settings.read");
  if ("error" in c) return c.error;
  const { data, error } = await c.admin.from("organizations")
    .select("rooms_locked, all_rooms_unlocked").eq("id", c.orgId).maybeSingle();
  // Before 0102 the setting does not exist yet: rooms are open and the switch is unavailable.
  if (isMissingColumn(error)) return NextResponse.json({ rooms_locked: false, available: false });
  if (error) return dbFail(error, "org/settings GET");
  return NextResponse.json({
    rooms_locked: orgRoomsLocked(data),
    // The super-admin bypass (0036) forces rooms open; the college switch then has no effect.
    forced_open: data?.all_rooms_unlocked === true,
    available: true,
  });
}

export async function PATCH(req: Request) {
  const c = await caller("org.settings.update");
  if ("error" in c) return c.error;
  let body: { rooms_locked?: unknown };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }
  if (typeof body?.rooms_locked !== "boolean") {
    return NextResponse.json({ error: "rooms_locked must be true or false." }, { status: 400 });
  }
  const { error } = await c.admin.from("organizations")
    .update({ rooms_locked: body.rooms_locked }).eq("id", c.orgId);
  if (isMissingColumn(error)) {
    return NextResponse.json({ error: "Room locking isn't available on this deployment yet." }, { status: 503 });
  }
  if (error) return dbFail(error, "org/settings PATCH");
  await logAudit({
    actorId: c.user.id, action: "org.settings.rooms_locked", targetTable: "organizations", targetId: c.orgId,
    metadata: { rooms_locked: body.rooms_locked },
  });
  return NextResponse.json({ rooms_locked: body.rooms_locked });
}
