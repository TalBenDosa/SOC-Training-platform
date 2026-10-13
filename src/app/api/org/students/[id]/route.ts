import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOMS_META } from "@/data/roomsMeta";
import { fetchAll } from "@/lib/plans/server";
import { groupItems, summarize, type FirstTrySummary } from "@/lib/org/firstTry";
import { buildMistakeGroups, type MistakeGroup, type StoredAttempt } from "@/lib/org/mistakeView";

const ROOM_TITLE: Record<string, string> = Object.fromEntries(ROOMS_META.map(r => [r.id, r.title]));
const ROOM_CATEGORY: Record<string, string> = Object.fromEntries(ROOMS_META.map(r => [r.id, r.category]));

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
 * Where the student erred: every room submission (task_attempts, 0031) is read, each
 * question becomes one item, and the items NOT right on the first try are returned as
 * readable mistakes (question, first answer, right answer, explanation, tries), grouped by
 * room. first_try is the mastery measure; topics breaks it down by room category.
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
    /** Questions answered right on the first try (readings excluded). */
    first_try: FirstTrySummary;
  };
  /** Room topics (room category), weakest first: first-try accuracy per topic. */
  topics: Array<{ topic: string; items: number; first_try_correct: number; accuracy: number }>;
  /** Where the student erred — questions not right on the first try, grouped by room. */
  mistake_groups: MistakeGroup[];
  rooms: Array<{
    room_id: string; title: string; completed: boolean;
    tasks_done: number; xp_earned: number;
    avg_decision_latency_ms: number | null;
    updated_at: string | null; completed_at: string | null;
  }>;
  scenarios: Array<{ slug: string; title: string; score: number | null; time_taken: number | null; completed_at: string | null;
    /** The report the student submitted (attemptRecord.ts): verdict, reasoning, rubric score, pass. */
    report: { verdict?: string; verdictReason?: string; reportScore?: number; passed?: boolean } | null }>;
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
    .select("user_id, role, status, joined_at, affiliation_expires_at, profiles(handle, display_name, xp, level, is_platform_admin)")
    .eq("org_id", orgId).eq("user_id", id).maybeSingle();
  // The platform super-admin is a member of every org but hidden everywhere else
  // (roster, analytics, plans) — keep it hidden here too.
  const isPlatform = (member?.profiles as unknown as { is_platform_admin?: boolean } | null)?.is_platform_admin;
  if (!member || isPlatform) return NextResponse.json({ error: "No such student in your organisation." }, { status: 404 });

  // Every submission, paged (PostgREST caps a read at 1000 rows), so the first try of an
  // old question is never cut off by a recent burst of retries.
  // question_index arrived in 0078; on a database that predates it, read without it and take
  // the question number from the submission itself (log_analysis sends questionIndex).
  const COLS = "room_id, task_id, task_type, question_index, attempt_no, correct, submitted, latency_ms, created_at";
  const readAttempts = (cols: string) => fetchAll<StoredAttempt>((from, to) => admin.from("task_attempts")
    .select(cols)
    .eq("org_id", orgId).eq("user_id", id)
    .order("created_at", { ascending: true }).order("id", { ascending: true })
    .range(from, to) as unknown as PromiseLike<{ data: StoredAttempt[] | null; error: { message: string } | null }>, "student:attempts", 20_000);
  let attemptRows: StoredAttempt[];
  try {
    attemptRows = await readAttempts(COLS).catch(e => {
      if (!/question_index/.test(e instanceof Error ? e.message : String(e))) throw e;
      return readAttempts(COLS.replace(", question_index", "")).then(rows => rows.map(r => {
        const qi = (r.submitted as { questionIndex?: unknown } | null)?.questionIndex;
        return { ...r, question_index: typeof qi === "number" ? qi : null };
      }));
    });
  } catch (e) {
    console.error("[student detail] attempts load failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Could not load this student's answers right now. Please try again." }, { status: 500 });
  }

  const [roomsRes, scenariosRes, sessionsRes] = await Promise.all([
    admin.from("room_progress")
      .select("room_id, completed_task_ids, per_task_xp, xp_earned, telemetry, completed_at, updated_at")
      .eq("org_id", orgId).eq("user_id", id),
    admin.from("scenario_history")
      .select("slug, title, score, time_taken, completed_at, report")
      .eq("org_id", orgId).eq("user_id", id).order("completed_at", { ascending: false }),
    admin.from("dashboard_sessions")
      .select("detect_rate, played_at, duration_ms")
      .eq("org_id", orgId).eq("user_id", id).order("played_at", { ascending: false }),
  ]);

  type RoomRow = { room_id: string; completed_task_ids: string[] | null; per_task_xp: Record<string, number> | null; xp_earned: number | null; telemetry: TelemetryEntry[] | null; completed_at: string | null; updated_at: string | null };
  const roomRows = (roomsRes.data ?? []) as RoomRow[];
  const scenarioRows = (scenariosRes.data ?? []) as Array<{ slug: string; title: string | null; score: number | null; time_taken: number | null; completed_at: string | null; report: Record<string, unknown> | null }>;
  const sessionRows = (sessionsRes.data ?? []) as Array<{ detect_rate: number | null; played_at: string | null; duration_ms: number | null }>;
  const items = groupItems(attemptRows);
  const firstTry = summarize(items);
  const topicStats = new Map<string, { items: number; ok: number }>();
  for (const it of items) {
    const topic = ROOM_CATEGORY[it.room_id] ?? "College rooms";
    const t = topicStats.get(topic) ?? { items: 0, ok: 0 };
    t.items++; if (it.firstTryCorrect) t.ok++;
    topicStats.set(topic, t);
  }
  const topics = [...topicStats.entries()]
    .map(([topic, t]) => ({ topic, items: t.items, first_try_correct: t.ok, accuracy: Math.round((t.ok / t.items) * 100) }))
    .sort((a, b) => a.accuracy - b.accuracy || b.items - a.items);
  const mistakeGroups = await buildMistakeGroups(items, orgId, roomId => ROOM_CATEGORY[roomId] ?? null);

  const allLatencies: number[] = [];
  const rooms = roomRows.map(r => {
    const tel = Array.isArray(r.telemetry) ? r.telemetry : [];
    // FB-018: clamp idle/away time so a task left open can't skew decision-time stats.
    const lat = tel.map(t => t.decisionLatencyMs).filter((x): x is number => typeof x === "number" && x >= 0).map(x => Math.min(x, 5 * 60 * 1000));
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
      first_try: firstTry,
    },
    topics,
    mistake_groups: mistakeGroups,
    rooms,
    scenarios: scenarioRows.map(s => {
      const r = s.report as { verdict?: string; verdictReason?: string; reportScore?: number; passed?: boolean } | null;
      return { slug: s.slug, title: s.title ?? s.slug, score: s.score, time_taken: s.time_taken, completed_at: s.completed_at,
        report: r ? { verdict: r.verdict, verdictReason: typeof r.verdictReason === "string" ? r.verdictReason.slice(0, 1500) : undefined, reportScore: r.reportScore, passed: r.passed } : null };
    }),
    sessions: sessionRows.map(s => ({ detect_rate: s.detect_rate, played_at: s.played_at, duration_ms: s.duration_ms })),
  };

  return NextResponse.json(detail);
}
