import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { logAudit } from "@/lib/audit/logAudit";
import { cleanLine, cleanText, isUuid, sanitizeMemberIds } from "@/lib/plans/sanitize";
import { PlanDataError, activeMemberIds, fetchAll, loadOrgMembers, toPlanDataError } from "@/lib/plans/server";
import { PLAN_LIMITS, type GroupRow } from "@/lib/plans/types";

/**
 * Org groups (migration 0075) — named cohorts such as "Tier-1 analysts" that a
 * learning plan can target.
 *
 * org_admin only (requireOrgAdmin), every query pinned to the caller's own org
 * from their JWT, and the tenant boundary re-asserted with .eq("org_id") on each
 * statement because the service-role client bypasses RLS. Member ids are only
 * accepted if they are ACTIVE members of THIS org (never invited/removed members
 * or the platform super-admin; the composite FK in 0075 would reject other orgs
 * anyway). Writes are audited.
 */

export const runtime = "nodejs";

type Ctx = { orgId: string; userId: string; admin: NonNullable<ReturnType<typeof getSupabaseAdminClient>> };

async function gate(action: string): Promise<Ctx | { error: NextResponse }> {
  const g = await requireOrgAdmin(action);
  if ("error" in g) return { error: g.error };
  const orgId = g.user.orgId;
  if (!orgId) return { error: NextResponse.json({ error: "No organisation in session." }, { status: 400 }) };
  const admin = getSupabaseAdminClient();
  if (!admin) return { error: NextResponse.json({ error: "Server not configured." }, { status: 503 }) };
  return { orgId, userId: g.user.id, admin };
}

const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

/** Generic failure; a schema error (code ahead of migration 0075) is a 503. */
function dataFail(e: unknown, context: string, message: string) {
  console.error(`[groups] ${context}:`, e instanceof Error ? e.message : e);
  if (e instanceof PlanDataError && e.kind === "schema") return fail(503, "Groups aren't available yet. Please try again shortly.");
  return fail(500, message);
}

async function readBody(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const b = await req.json();
    return b && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  } catch { return null; }
}

/** Ids of this org's ACTIVE members (platform admins excluded). */
async function memberIdSet(c: Ctx): Promise<Set<string>> {
  return activeMemberIds(await loadOrgMembers(c.admin, c.orgId));
}

/**
 * Make the group's ACTIVE membership exactly `wanted`: insert the missing,
 * delete active members who were unticked. Existing members who are currently
 * inactive aren't offered in the picker, so they are left untouched (they are
 * back in the group if reactivated; leaving the org removes them via the FK).
 */
async function syncMembers(c: Ctx, groupId: string, wanted: string[], activeIds: ReadonlySet<string>): Promise<boolean> {
  let cur: { user_id: string }[];
  try {
    cur = await fetchAll<{ user_id: string }>((from, to) =>
      c.admin.from("org_group_members").select("user_id").eq("org_id", c.orgId).eq("group_id", groupId)
        .order("user_id", { ascending: true }).range(from, to), "org_group_members");
  } catch { return false; }
  const have = new Set(cur.map(r => r.user_id));
  const want = new Set(wanted);
  const add = wanted.filter(id => !have.has(id));
  const remove = [...have].filter(id => !want.has(id) && activeIds.has(id));
  if (add.length) {
    const { error: e } = await c.admin.from("org_group_members")
      .insert(add.map(user_id => ({ group_id: groupId, user_id, org_id: c.orgId, added_by: c.userId })));
    if (e) return false;
  }
  // Chunked so a large removal never builds an over-long request URL.
  for (let i = 0; i < remove.length; i += 100) {
    const { error: e } = await c.admin.from("org_group_members")
      .delete().eq("org_id", c.orgId).eq("group_id", groupId).in("user_id", remove.slice(i, i + 100));
    if (e) return false;
  }
  return true;
}

// ── GET — groups + member ids ────────────────────────────────────────────────
export async function GET() {
  const c = await gate("org.groups.read");
  if ("error" in c) return c.error;

  let groupRows: { id: string; name: string; description: string | null; created_at: string }[];
  let members: { group_id: string; user_id: string }[];
  try {
    [groupRows, members] = await Promise.all([
      fetchAll<{ id: string; name: string; description: string | null; created_at: string }>((from, to) =>
        c.admin.from("org_groups").select("id, name, description, created_at").eq("org_id", c.orgId)
          .order("name", { ascending: true }).order("id", { ascending: true }).range(from, to), "org_groups"),
      fetchAll<{ group_id: string; user_id: string }>((from, to) =>
        c.admin.from("org_group_members").select("group_id, user_id").eq("org_id", c.orgId)
          .order("group_id", { ascending: true }).order("user_id", { ascending: true }).range(from, to), "org_group_members"),
    ]);
  } catch (e) {
    return dataFail(e, "list", "Could not load groups.");
  }

  const byGroup = new Map<string, string[]>();
  for (const m of members) byGroup.set(m.group_id, [...(byGroup.get(m.group_id) ?? []), m.user_id]);

  const groups: GroupRow[] = groupRows.map(g => ({
    id: g.id, name: g.name, description: g.description, created_at: g.created_at,
    member_ids: byGroup.get(g.id) ?? [],
  }));
  return NextResponse.json({ groups });
}

// ── POST — create a group ────────────────────────────────────────────────────
export async function POST(req: Request) {
  const c = await gate("org.groups.write");
  if ("error" in c) return c.error;
  const body = await readBody(req);
  if (!body) return fail(400, "Invalid JSON.");

  const name = cleanLine(body.name, PLAN_LIMITS.groupName);
  if (!name) return fail(400, "Give the group a name.");
  const description = cleanText(body.description, PLAN_LIMITS.groupDescription) || null;

  const { count } = await c.admin.from("org_groups").select("id", { count: "exact", head: true }).eq("org_id", c.orgId);
  if ((count ?? 0) >= PLAN_LIMITS.groupsPerOrg) return fail(400, `An organisation can have at most ${PLAN_LIMITS.groupsPerOrg} groups.`);

  let active: Set<string>;
  try { active = await memberIdSet(c); } catch (e) { return dataFail(e, "create: members", "Could not create the group."); }
  const memberIds = sanitizeMemberIds(body.member_ids, active);

  const { data, error } = await c.admin.from("org_groups")
    .insert({ org_id: c.orgId, name, description, created_by: c.userId })
    .select("id").single();
  if (error) {
    if (error.code === "23505") return fail(409, "A group with that name already exists.");
    return dataFail(toPlanDataError(error, "create"), "create", "Could not create the group.");
  }
  if (memberIds.length && !(await syncMembers(c, data.id, memberIds, active))) {
    return fail(500, "The group was created, but its members could not be saved.");
  }

  await logAudit({ actorId: c.userId, action: "org.groups.create", targetTable: "org_groups", targetId: data.id, metadata: { orgId: c.orgId, members: memberIds.length } });
  return NextResponse.json({ id: data.id });
}

// ── PATCH — rename / describe / set members ─────────────────────────────────
export async function PATCH(req: Request) {
  const c = await gate("org.groups.write");
  if ("error" in c) return c.error;
  const body = await readBody(req);
  if (!body) return fail(400, "Invalid JSON.");
  if (!isUuid(body.id)) return fail(400, "id is required.");
  const id = body.id;

  const { data: existing } = await c.admin.from("org_groups").select("id").eq("id", id).eq("org_id", c.orgId).maybeSingle();
  if (!existing) return fail(404, "No such group in your organisation.");

  const patch: Record<string, unknown> = {};
  if ("name" in body) {
    const name = cleanLine(body.name, PLAN_LIMITS.groupName);
    if (!name) return fail(400, "Give the group a name.");
    patch.name = name;
  }
  if ("description" in body) patch.description = cleanText(body.description, PLAN_LIMITS.groupDescription) || null;

  if (Object.keys(patch).length) {
    const { error } = await c.admin.from("org_groups").update(patch).eq("id", id).eq("org_id", c.orgId);
    if (error) {
      if (error.code === "23505") return fail(409, "A group with that name already exists.");
      return dataFail(toPlanDataError(error, "update"), "update", "Could not update the group.");
    }
  }

  let members: number | undefined;
  if ("member_ids" in body) {
    let active: Set<string>;
    try { active = await memberIdSet(c); } catch (e) { return dataFail(e, "update: members", "Could not update the group's members."); }
    const memberIds = sanitizeMemberIds(body.member_ids, active);
    if (!(await syncMembers(c, id, memberIds, active))) return fail(500, "Could not update the group's members.");
    members = memberIds.length;
  }

  await logAudit({ actorId: c.userId, action: "org.groups.update", targetTable: "org_groups", targetId: id, metadata: { orgId: c.orgId, fields: Object.keys(patch), members } });
  return NextResponse.json({ ok: true });
}

// ── DELETE — remove a group (its memberships and plan targets cascade) ──────
export async function DELETE(req: Request) {
  const c = await gate("org.groups.write");
  if ("error" in c) return c.error;
  const id = new URL(req.url).searchParams.get("id");
  if (!isUuid(id)) return fail(400, "id is required.");

  const { data, error } = await c.admin.from("org_groups").delete().eq("id", id).eq("org_id", c.orgId).select("id");
  if (error) return dataFail(toPlanDataError(error, "delete"), "delete", "Could not delete the group.");
  if (!data || data.length === 0) return fail(404, "No such group in your organisation.");

  await logAudit({ actorId: c.userId, action: "org.groups.delete", targetTable: "org_groups", targetId: id, metadata: { orgId: c.orgId } });
  return NextResponse.json({ ok: true });
}
