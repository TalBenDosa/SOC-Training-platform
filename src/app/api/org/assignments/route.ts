import { NextResponse } from "next/server";
import { getAuthedUser, requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOMS } from "@/data/rooms";
import { SCENARIOS } from "@/lib/sim/scenarios";

/**
 * Instructor-set coursework (migration 0021).
 *
 * GET is open to any signed-in member of the org — students must be able to see
 * what they were assigned, and their own completion against it. Progress is
 * DERIVED from room_progress/scenario_history rather than stored, so a room
 * finished last week counts the moment it's assigned today.
 *
 * POST/PATCH/DELETE require org_admin/instructor. Every query is pinned to the
 * caller's own org from their JWT, never a request parameter.
 */

export interface AssignmentItem { kind: "room" | "scenario"; id: string }
export interface AssignmentRow {
  id: string;
  title: string;
  instructions: string | null;
  items: AssignmentItem[];
  due_at: string | null;
  created_at: string;
  /** Resolved display titles, so clients don't bundle the content corpus. */
  item_titles: { kind: string; id: string; title: string }[];
  /** Completion for the CALLING user (students see their own progress). */
  my_done_ids?: string[];
  /** Cohort completion, staff only: how many active students finished all items. */
  cohort?: { completed: number; total: number };
}

const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS.map(r => [r.id, r.title]));
const SCENARIO_TITLE: Record<string, string> = Object.fromEntries(SCENARIOS.map(s => [s.slug, s.title]));

const titleFor = (it: AssignmentItem) =>
  (it.kind === "room" ? ROOM_TITLE[it.id] : SCENARIO_TITLE[it.id]) ?? it.id;

/** Whitelist + cap: only ids that actually exist in the corpus become items. */
function sanitizeItems(raw: unknown): AssignmentItem[] {
  if (!Array.isArray(raw)) return [];
  const out: AssignmentItem[] = [];
  const seen = new Set<string>();
  for (const r of raw) {
    if (!r || typeof r !== "object") continue;
    const kind = (r as { kind?: unknown }).kind;
    const id = (r as { id?: unknown }).id;
    if (typeof id !== "string") continue;
    if (kind !== "room" && kind !== "scenario") continue;
    const exists = kind === "room" ? ROOM_TITLE[id] !== undefined : SCENARIO_TITLE[id] !== undefined;
    if (!exists) continue;
    const key = `${kind}:${id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ kind, id });
    if (out.length >= 50) break;
  }
  return out;
}

// ── GET — assignments for the caller's org, with progress ────────────────────
export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  if (!user.orgId) return NextResponse.json({ assignments: [] });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: rows, error } = await admin
    .from("assignments")
    .select("id, title, instructions, items, due_at, created_at")
    .eq("org_id", user.orgId)
    .order("due_at", { ascending: true, nullsFirst: false });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const isStaff = user.orgRole === "org_admin" || user.orgRole === "instructor";

  // What the caller has finished — used for their own progress bars.
  const [myRooms, myScenarios] = await Promise.all([
    admin.from("room_progress").select("room_id").eq("user_id", user.id).not("completed_at", "is", null),
    admin.from("scenario_history").select("slug").eq("user_id", user.id),
  ]);
  const myDone = new Set<string>([
    ...(myRooms.data ?? []).map(r => `room:${r.room_id}`),
    ...(myScenarios.data ?? []).map(s => `scenario:${s.slug}`),
  ]);

  // Staff also get cohort completion. Pulled once for all assignments rather
  // than per-assignment to keep this a fixed number of queries.
  let orgRoomsByUser = new Map<string, Set<string>>();
  let activeStudentIds: string[] = [];
  if (isStaff) {
    const [members, rp, sh] = await Promise.all([
      admin.from("org_members").select("user_id, status").eq("org_id", user.orgId).eq("status", "active"),
      admin.from("room_progress").select("user_id, room_id").eq("org_id", user.orgId).not("completed_at", "is", null),
      admin.from("scenario_history").select("user_id, slug").eq("org_id", user.orgId),
    ]);
    activeStudentIds = (members.data ?? []).map(m => m.user_id);
    orgRoomsByUser = new Map(activeStudentIds.map(id => [id, new Set<string>()]));
    for (const r of rp.data ?? []) orgRoomsByUser.get(r.user_id)?.add(`room:${r.room_id}`);
    for (const s of sh.data ?? []) orgRoomsByUser.get(s.user_id)?.add(`scenario:${s.slug}`);
  }

  const assignments: AssignmentRow[] = (rows ?? []).map(row => {
    const items = sanitizeItems(row.items);
    const keys = items.map(i => `${i.kind}:${i.id}`);
    const base: AssignmentRow = {
      id: row.id,
      title: row.title,
      instructions: row.instructions,
      items,
      due_at: row.due_at,
      created_at: row.created_at,
      item_titles: items.map(i => ({ kind: i.kind, id: i.id, title: titleFor(i) })),
      my_done_ids: keys.filter(k => myDone.has(k)),
    };
    if (isStaff) {
      const completed = activeStudentIds.filter(id => {
        const done = orgRoomsByUser.get(id);
        return keys.length > 0 && done && keys.every(k => done.has(k));
      }).length;
      base.cohort = { completed, total: activeStudentIds.length };
    }
    return base;
  });

  // Staff also get a lightweight pick-list for the "new assignment" form.
  // Served from here rather than bundling ROOMS/SCENARIOS into the client:
  // ~110 id+title pairs is a few KB, the corpus itself is megabytes.
  const catalog = isStaff ? [
    ...ROOMS.map(r => ({ kind: "room" as const, id: r.id, title: r.title, group: r.category, difficulty: r.difficulty })),
    ...SCENARIOS.map(s => ({ kind: "scenario" as const, id: s.slug, title: s.title, group: "Scenario", difficulty: s.difficulty })),
  ] : undefined;

  return NextResponse.json({ assignments, is_staff: isStaff, catalog });
}

// ── POST — create an assignment (staff only) ─────────────────────────────────
export async function POST(req: Request) {
  const gate = await requireOrgAdmin("org.assignments.create");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const title = String(body.title ?? "").trim().slice(0, 160);
  if (!title) return NextResponse.json({ error: "Title is required." }, { status: 400 });
  const items = sanitizeItems(body.items);
  if (items.length === 0) return NextResponse.json({ error: "Add at least one room or scenario." }, { status: 400 });

  let due_at: string | null = null;
  if (body.due_at) {
    const d = new Date(String(body.due_at));
    if (Number.isNaN(d.getTime())) return NextResponse.json({ error: "Invalid due date." }, { status: 400 });
    due_at = d.toISOString();
  }

  const { data, error } = await admin.from("assignments").insert({
    org_id: orgId,
    title,
    instructions: String(body.instructions ?? "").trim().slice(0, 2000) || null,
    items,
    due_at,
    created_by: gate.user.id,
  }).select("id").single();
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ id: data.id });
}

// ── DELETE — remove an assignment (staff only, own org) ──────────────────────
export async function DELETE(req: Request) {
  const gate = await requireOrgAdmin("org.assignments.delete");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });

  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error: "id is required." }, { status: 400 });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  // .eq("org_id") as well as id — the service-role client bypasses RLS, so the
  // tenant boundary has to be re-asserted explicitly here.
  const { error } = await admin.from("assignments").delete().eq("id", id).eq("org_id", orgId);
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true });
}
