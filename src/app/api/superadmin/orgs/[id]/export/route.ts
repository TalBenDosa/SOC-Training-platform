import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { fetchAll, chunk } from "@/lib/plans/server";

type Ctx = { params: Promise<{ id: string }> };

/**
 * Full export of a college's data as JSON — for offboarding (hand the file to
 * the college) or backup before a purge. Super-admin only; downloaded as an
 * attachment. Covers the org, its roster, and every learner-data row.
 *
 * Every table is PAGED (PostgREST returns at most 1000 rows per request) and any
 * read error fails the whole export — this file is what an admin takes right
 * before the irreversible purge, so a silently truncated or partial file would
 * mean silent data loss. `row_counts` lets the recipient check completeness.
 */
export async function GET(_req: Request, { params }: Ctx) {
  const gate = await requireSuperAdmin("superadmin.org.export");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  const { data: org, error: orgErr } = await admin.from("organizations").select("*").eq("id", id).maybeSingle();
  if (orgErr) return NextResponse.json({ error: "Could not read the organisation." }, { status: 500 });
  if (!org) return NextResponse.json({ error: "Organization not found." }, { status: 404 });

  type Row = Record<string, unknown>;
  const byOrg = (table: string, order: string[]) => fetchAll<Row>((from, to) => {
    let q = admin.from(table).select("*").eq("org_id", id);
    for (const col of order) q = q.order(col, { ascending: true });
    return q.range(from, to);
  }, `export:${table}`);

  try {
    const members = await byOrg("org_members", ["user_id"]);
    const memberIds = members.map(m => String(m.user_id));

    // Per-user tables: profiles (identity) and lesson_progress (no org_id column)
    // are selected by MEMBERSHIP, not by profiles.org_id (the active context).
    const byMembers = async (table: string, select: string, order: string[]) => {
      const out: Row[] = [];
      for (const ids of chunk(memberIds, 200)) {
        out.push(...await fetchAll<Row>((from, to) => {
          let q = admin.from(table).select(select as "*").in(table === "profiles" ? "id" : "user_id", ids);
          for (const col of order) q = q.order(col, { ascending: true });
          return q.range(from, to);
        }, `export:${table}`));
      }
      return out;
    };

    const [profiles, userProgress, rooms, sessions, scenarios, quizzes, attempts, lessons] = await Promise.all([
      byMembers("profiles", "id, handle, display_name, xp, level, created_at", ["id"]),
      byOrg("user_progress", ["user_id"]),
      byOrg("room_progress", ["user_id", "room_id"]),
      byOrg("dashboard_sessions", ["id"]),
      byOrg("scenario_history", ["id"]),
      byOrg("quiz_progress", ["user_id", "quiz_slug"]),
      byOrg("task_attempts", ["id"]),
      byMembers("lesson_progress", "*", ["user_id", "lesson_key"]),
    ]);

    const payload = {
      exported_at: new Date().toISOString(),
      organization: org,
      row_counts: {
        members: members.length, profiles: profiles.length, user_progress: userProgress.length,
        room_progress: rooms.length, dashboard_sessions: sessions.length, scenario_history: scenarios.length,
        quiz_progress: quizzes.length, task_attempts: attempts.length, lesson_progress: lessons.length,
      },
      members,
      profiles,
      user_progress: userProgress,
      room_progress: rooms,
      dashboard_sessions: sessions,
      scenario_history: scenarios,
      quiz_progress: quizzes,
      task_attempts: attempts,
      lesson_progress: lessons,
    };

    return new NextResponse(JSON.stringify(payload, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="org-${org.slug}-export.json"`,
      },
    });
  } catch (e) {
    console.error("[superadmin export] failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "The export could not be completed — nothing was downloaded. Do not purge this organisation until a full export succeeds." }, { status: 500 });
  }
}
