import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOMS } from "@/data/rooms";

// Room ids are stored in the DB; titles live in the content corpus. Resolved
// HERE rather than in the client so /manage doesn't have to bundle the entire
// room corpus (megabytes of task content) just to render five labels.
const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS.map(r => [r.id, r.title]));

/**
 * Cohort analytics for an org-admin / instructor.
 *
 * Before this, /api/org/members returned a roster with ONE number per student
 * (total XP) and four org-wide counters — an instructor running a semester
 * could not see who was behind, what anyone scored, or which material the class
 * struggles with. This aggregates the learner tables into per-student rows plus
 * class-level signals.
 *
 * Always scoped to the CALLER'S OWN org: `orgId` comes from their JWT via
 * requireOrgAdmin(), never from a request parameter, so one college can never
 * read another's cohort. Uses the service-role client for the reads (same
 * pattern as /api/org/members) with every query pinned to that org_id.
 *
 * Aggregation happens in JS rather than SQL: a cohort is tens of students with
 * hundreds of progress rows, so the round-trip saving of a bespoke SQL view
 * isn't worth another migration to maintain.
 */

const DAY = 24 * 60 * 60 * 1000;

export interface StudentRow {
  user_id: string;
  handle: string | null;
  display_name: string | null;
  status: string;
  role: string;
  joined_at: string | null;
  xp: number;
  level: number;
  rooms_completed: number;
  rooms_started: number;
  /** Completed room ids — lets the client map coverage without a second call. */
  completed_room_ids: string[];
  scenarios_completed: number;
  scenario_avg_score: number | null;
  sessions: number;
  avg_detect_rate: number | null;
  last_active_at: string | null;
}

export async function GET() {
  const gate = await requireOrgAdmin("org.analytics");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const [membersRes, roomsRes, scenariosRes, sessionsRes] = await Promise.all([
    admin.from("org_members")
      .select("user_id, role, status, joined_at, profiles(handle, display_name, xp, level)")
      .eq("org_id", orgId),
    admin.from("room_progress")
      .select("user_id, room_id, completed_at, updated_at")
      .eq("org_id", orgId),
    admin.from("scenario_history")
      .select("user_id, score, completed_at")
      .eq("org_id", orgId),
    admin.from("dashboard_sessions")
      .select("user_id, detect_rate, played_at")
      .eq("org_id", orgId),
  ]);

  type RoomRow = { user_id: string; room_id: string; completed_at: string | null; updated_at: string | null };
  type ScenarioRow = { user_id: string; score: number | null; completed_at: string | null };
  type SessionRow = { user_id: string; detect_rate: number | null; played_at: string | null };

  const roomRows     = (roomsRes.data ?? []) as RoomRow[];
  const scenarioRows = (scenariosRes.data ?? []) as ScenarioRow[];
  const sessionRows  = (sessionsRes.data ?? []) as SessionRow[];

  const byUser = <T extends { user_id: string }>(rows: T[]) => {
    const m = new Map<string, T[]>();
    for (const r of rows) {
      const list = m.get(r.user_id);
      if (list) list.push(r); else m.set(r.user_id, [r]);
    }
    return m;
  };
  const roomsBy     = byUser(roomRows);
  const scenariosBy = byUser(scenarioRows);
  const sessionsBy  = byUser(sessionRows);

  const latest = (dates: (string | null | undefined)[]): string | null => {
    let best: number | null = null;
    for (const d of dates) {
      if (!d) continue;
      const t = Date.parse(d);
      if (!Number.isNaN(t) && (best === null || t > best)) best = t;
    }
    return best === null ? null : new Date(best).toISOString();
  };
  const avg = (nums: number[]): number | null =>
    nums.length === 0 ? null : Math.round(nums.reduce((s, n) => s + n, 0) / nums.length);

  const students: StudentRow[] = (membersRes.data ?? []).map(m => {
    const p = m.profiles as unknown as { handle?: string; display_name?: string; xp?: number; level?: number } | null;
    const rp = roomsBy.get(m.user_id) ?? [];
    const sc = scenariosBy.get(m.user_id) ?? [];
    const ds = sessionsBy.get(m.user_id) ?? [];
    const completed = rp.filter(r => r.completed_at);

    return {
      user_id: m.user_id,
      handle: p?.handle ?? null,
      display_name: p?.display_name ?? null,
      status: m.status,
      role: m.role,
      joined_at: m.joined_at,
      xp: p?.xp ?? 0,
      level: p?.level ?? 1,
      rooms_completed: completed.length,
      rooms_started: rp.length,
      completed_room_ids: completed.map(r => r.room_id),
      scenarios_completed: sc.length,
      scenario_avg_score: avg(sc.map(s => s.score ?? 0)),
      sessions: ds.length,
      avg_detect_rate: avg(ds.map(s => s.detect_rate ?? 0)),
      last_active_at: latest([
        ...rp.map(r => r.updated_at), ...rp.map(r => r.completed_at),
        ...sc.map(s => s.completed_at), ...ds.map(s => s.played_at),
      ]),
    };
  });

  // ── Class-level signals ────────────────────────────────────────────────────
  // "Hardest" = highest drop-off: started by several students but completed by
  // the fewest of them. A room only one person opened isn't evidence of
  // difficulty, so require at least 3 starters before ranking it.
  const roomStats = new Map<string, { started: number; completed: number }>();
  for (const r of roomRows) {
    const s = roomStats.get(r.room_id) ?? { started: 0, completed: 0 };
    s.started++;
    if (r.completed_at) s.completed++;
    roomStats.set(r.room_id, s);
  }
  const hardest_rooms = [...roomStats.entries()]
    .filter(([, s]) => s.started >= 3)
    .map(([room_id, s]) => ({
      room_id, title: ROOM_TITLE[room_id] ?? room_id,
      started: s.started, completed: s.completed,
      completion_rate: Math.round((s.completed / s.started) * 100),
    }))
    .sort((a, b) => a.completion_rate - b.completion_rate)
    .slice(0, 5);

  const now = Date.now();
  const activeStudents = students.filter(s => s.status === "active");
  const allScenarioScores = scenarioRows.map(s => s.score ?? 0);

  return NextResponse.json({
    students,
    class: {
      size: activeStudents.length,
      avg_scenario_score: avg(allScenarioScores),
      avg_rooms_completed: avg(activeStudents.map(s => s.rooms_completed)),
      total_rooms_completed: students.reduce((n, s) => n + s.rooms_completed, 0),
      active_7d: activeStudents.filter(s => s.last_active_at && now - Date.parse(s.last_active_at) < 7 * DAY).length,
      never_started: activeStudents.filter(s => !s.last_active_at).length,
      // Enrolled, did something once, but nothing for two weeks — the group an
      // instructor most needs surfaced while there's still time to intervene.
      dormant_14d: activeStudents.filter(s => s.last_active_at && now - Date.parse(s.last_active_at) >= 14 * DAY).length,
      hardest_rooms,
    },
  });
}
