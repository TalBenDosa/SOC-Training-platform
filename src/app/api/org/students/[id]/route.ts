import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOMS } from "@/data/rooms";

const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS.map(r => [r.id, r.title]));

/**
 * Per-student drill-down for an org-admin / instructor. Surfaces the timeline
 * and the fine-grained signals the roster row can't fit: every scenario run
 * (score + how long it took), room-by-room progress, and — newly surfaced —
 * the DECISION LATENCY already captured in room_progress.telemetry (how long
 * the student took to answer each task), which no view read before.
 *
 * Scoped to the caller's OWN org: orgId comes from the JWT via requireOrgAdmin,
 * and the target student is verified to be a member of THAT org before any of
 * their data is read — so one college can never open another's student.
 *
 * NOTE: "where the student erred" (wrong answers / attempts) is deliberately
 * NOT here — the room submit route is stateless and never records mistakes.
 * Capturing that is the separate P2 task (task_attempts table + stateful submit).
 */
type Ctx = { params: Promise<{ id: string }> };

interface TelemetryEntry { taskId?: string; decisionLatencyMs?: number; interactionCount?: number }

export interface StudentDetail {
  user_id: string;
  handle: string | null;
  display_name: string | null;
  role: string;
  status: string;
  joined_at: string | null;
  affiliation_expires_at: string | null;
  xp: number;
  level: number;
  last_active_at: string | null;
  summary: {
    rooms_completed: number;
    rooms_started: number;
    scenarios_completed: number;
    scenario_avg_score: number | null;
    sessions: number;
    avg_detect_rate: number | null;
    /** Median decision latency across every task the student answered (ms). */
    median_decision_latency_ms: number | null;
    tasks_answered: number;
  };
  rooms: Array<{
    room_id: string; title: string; completed: boolean;
    tasks_done: number; xp_earned: number;
    avg_decision_latency_ms: number | null;
    updated_at: string | null; completed_at: string | null;
  }>;
  scenarios: Array<{ slug: string; title: string; score: number | null; time_taken: number | null; completed_at: string | null }>;
  sessions: Array<{ detect_rate: number | null; played_at: string | null; duration_ms: number | null }>;
}

const avg = (n: number[]) => (n.length === 0 ? null : Math.round(n.reduce((s, x) => s + x, 0) / n.length));
const median = (n: number[]) => {
  if (n.length === 0) return null;
  const s = [...n].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
};
const latest = (dates: (string | null | undefined)[]) => {
  let best: number | null = null;
  for (const d of dates) { if (!d) continue; const t = Date.parse(d); if (!Number.isNaN(t) && (best === null || t > best)) best = t; }
  return best === null ? null : new Date(best).toISOString();
};

export async function GET(_req: Request, { params }: Ctx) {
  const gate = await requireOrgAdmin("org.student_detail");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { id } = await params;

  // The student MUST belong to the caller's org — verified before any read.
  const { data: member } = await admin
    .from("org_members")
    .select("user_id, role, status, joined_at, affiliation_expires_at, profiles(handle, display_name, xp, level)")
    .eq("org_id", orgId).eq("user_id", id).maybeSingle();
  if (!member) return NextResponse.json({ error: "No such student in your organisation." }, { status: 404 });

  const [roomsRes, scenariosRes, sessionsRes] = await Promise.all([
    admin.from("room_progress")
      .select("room_id, completed_task_ids, per_task_xp, xp_earned, telemetry, completed_at, updated_at")
      .eq("org_id", orgId).eq("user_id", id),
    admin.from("scenario_history")
      .select("slug, title, score, time_taken, completed_at")
      .eq("org_id", orgId).eq("user_id", id).order("completed_at", { ascending: false }),
    admin.from("dashboard_sessions")
      .select("detect_rate, played_at, duration_ms")
      .eq("org_id", orgId).eq("user_id", id).order("played_at", { ascending: false }),
  ]);

  type RoomRow = { room_id: string; completed_task_ids: string[] | null; per_task_xp: Record<string, number> | null; xp_earned: number | null; telemetry: TelemetryEntry[] | null; completed_at: string | null; updated_at: string | null };
  const roomRows = (roomsRes.data ?? []) as RoomRow[];
  const scenarioRows = (scenariosRes.data ?? []) as Array<{ slug: string; title: string | null; score: number | null; time_taken: number | null; completed_at: string | null }>;
  const sessionRows = (sessionsRes.data ?? []) as Array<{ detect_rate: number | null; played_at: string | null; duration_ms: number | null }>;

  const allLatencies: number[] = [];
  const rooms = roomRows.map(r => {
    const tel = Array.isArray(r.telemetry) ? r.telemetry : [];
    const lat = tel.map(t => t.decisionLatencyMs).filter((x): x is number => typeof x === "number" && x >= 0);
    allLatencies.push(...lat);
    return {
      room_id: r.room_id,
      title: ROOM_TITLE[r.room_id] ?? r.room_id,
      completed: Boolean(r.completed_at),
      tasks_done: (r.completed_task_ids ?? []).length,
      xp_earned: r.xp_earned ?? 0,
      avg_decision_latency_ms: avg(lat),
      updated_at: r.updated_at,
      completed_at: r.completed_at,
    };
  }).sort((a, b) => (Date.parse(b.updated_at ?? "0") || 0) - (Date.parse(a.updated_at ?? "0") || 0));

  const p = member.profiles as unknown as { handle?: string; display_name?: string; xp?: number; level?: number } | null;

  const detail: StudentDetail = {
    user_id: member.user_id,
    handle: p?.handle ?? null,
    display_name: p?.display_name ?? null,
    role: member.role,
    status: member.status,
    joined_at: member.joined_at,
    affiliation_expires_at: member.affiliation_expires_at ?? null,
    xp: p?.xp ?? 0,
    level: p?.level ?? 1,
    last_active_at: latest([
      ...roomRows.map(r => r.updated_at), ...roomRows.map(r => r.completed_at),
      ...scenarioRows.map(s => s.completed_at), ...sessionRows.map(s => s.played_at),
    ]),
    summary: {
      rooms_completed: roomRows.filter(r => r.completed_at).length,
      rooms_started: roomRows.length,
      scenarios_completed: scenarioRows.length,
      scenario_avg_score: avg(scenarioRows.map(s => s.score ?? 0)),
      sessions: sessionRows.length,
      avg_detect_rate: avg(sessionRows.map(s => s.detect_rate ?? 0)),
      median_decision_latency_ms: median(allLatencies),
      tasks_answered: allLatencies.length,
    },
    rooms,
    scenarios: scenarioRows.map(s => ({ slug: s.slug, title: s.title ?? s.slug, score: s.score, time_taken: s.time_taken, completed_at: s.completed_at })),
    sessions: sessionRows.map(s => ({ detect_rate: s.detect_rate, played_at: s.played_at, duration_ms: s.duration_ms })),
  };

  return NextResponse.json(detail);
}
