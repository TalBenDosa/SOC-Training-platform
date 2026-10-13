import { NextResponse } from "next/server";
import { requireOrgAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { fetchAll } from "@/lib/plans/server";
import { groupItems } from "@/lib/org/firstTry";
import { skillStats, MIN_ITEMS, type AreaStat, type FirstAnswerRow } from "@/lib/org/skillStats";
import { commonMistakes, type CommonMistake } from "@/lib/org/commonMistakes";
import type { StoredAttempt } from "@/lib/org/mistakeView";
import { SKILL_AREAS } from "@/lib/skills/taxonomy";

/**
 * Class view of skills (org-admin): students × skill areas (right first try, from rooms +
 * quizzes + lesson checks + scenario questions), the class's mastery per area, and the
 * questions the class misses most with the wrong answer most of them chose.
 *
 * Org-scoped like /api/org/analytics: org id from the JWT, the platform super-admin hidden,
 * every read paged. graded_first_answers has no org_id (0078), so it is read for this org's
 * members only and, per student, only from when they joined this org.
 */
export interface SkillsResponse {
  areas: { id: string; label: string }[];
  students: Array<{ user_id: string; name: string; items: number; accuracy: number | null; areas: Record<string, { items: number; accuracy: number | null }> }>;
  class_areas: Array<AreaStat & { students_judged: number }>;
  common_mistakes: Array<CommonMistake & { reports: number }>;
  min_items: number;
}

export async function GET() {
  const gate = await requireOrgAdmin("org.skills");
  if ("error" in gate) return gate.error;
  const orgId = gate.user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const paged = <T,>(label: string, build: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>) =>
    fetchAll<T>(build, `skills:${label}`);
  const ATTEMPT_COLS = "id, user_id, room_id, task_id, task_type, question_index, attempt_no, correct, submitted, latency_ms, created_at";

  let members: Array<{ user_id: string; status: string; joined_at: string | null; profiles: unknown }>;
  let attempts: Array<StoredAttempt & { user_id: string }>;
  try {
    members = await paged("members", (f, t) => admin.from("org_members")
      .select("user_id, status, joined_at, profiles(handle, display_name, is_platform_admin)")
      .eq("org_id", orgId).order("user_id", { ascending: true }).range(f, t) as never);
    const readAttempts = (cols: string) => paged<StoredAttempt & { user_id: string }>("attempts", (f, t) => admin.from("task_attempts")
      .select(cols).eq("org_id", orgId).order("id", { ascending: true }).range(f, t) as never);
    // question_index arrived in 0078; an older database still loads (question number from the submission).
    attempts = await readAttempts(ATTEMPT_COLS).catch(e => {
      if (!/question_index/.test(e instanceof Error ? e.message : String(e))) throw e;
      return readAttempts(ATTEMPT_COLS.replace(", question_index", "")).then(rows => rows.map(r => {
        const qi = (r.submitted as { questionIndex?: unknown } | null)?.questionIndex;
        return { ...r, question_index: typeof qi === "number" ? qi : null };
      }));
    });
  } catch (e) {
    console.error("[org skills] load failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Could not load skills right now. Please try again." }, { status: 500 });
  }

  const students = members.filter(m => m.status === "active" && !(m.profiles as { is_platform_admin?: boolean } | null)?.is_platform_admin);
  const ids = students.map(m => m.user_id);
  const joinedAt = new Map(students.map(m => [m.user_id, Date.parse(m.joined_at ?? "1970-01-01T00:00:00Z") || 0]));

  // First answers for these students, in chunks (an IN list per request).
  const firstsBy = new Map<string, FirstAnswerRow[]>();
  for (let i = 0; i < ids.length; i += 100) {
    const chunk = ids.slice(i, i + 100);
    const { data, error } = await admin.from("graded_first_answers")
      .select("user_id, kind, content_id, question_id, correct, created_at").in("user_id", chunk).limit(50_000);
    if (error) { console.error("[org skills] first answers:", error.message); break; }
    for (const r of (data ?? []) as Array<FirstAnswerRow & { user_id: string; created_at: string }>) {
      if (Date.parse(r.created_at) < (joinedAt.get(r.user_id) ?? 0)) continue;
      const list = firstsBy.get(r.user_id) ?? [];
      list.push(r); firstsBy.set(r.user_id, list);
    }
  }

  const attemptsBy = new Map<string, StoredAttempt[]>();
  for (const a of attempts) {
    if (!joinedAt.has(a.user_id)) continue;
    const list = attemptsBy.get(a.user_id) ?? [];
    list.push(a); attemptsBy.set(a.user_id, list);
  }

  const itemsBy = new Map(students.map(m => [m.user_id, groupItems(attemptsBy.get(m.user_id) ?? [])]));
  const pooled = new Map<string, { items: number; ok: number; judged: number }>();
  const rows = students.map(m => {
    const p = m.profiles as { handle?: string; display_name?: string } | null;
    const stats = skillStats(itemsBy.get(m.user_id) ?? [], firstsBy.get(m.user_id) ?? []);
    let items = 0, ok = 0;
    const areas: Record<string, { items: number; accuracy: number | null }> = {};
    for (const s of stats) {
      areas[s.area] = { items: s.items, accuracy: s.accuracy };
      items += s.items; ok += s.firstTryCorrect;
      const c = pooled.get(s.area) ?? { items: 0, ok: 0, judged: 0 };
      c.items += s.items; c.ok += s.firstTryCorrect; if (s.items >= MIN_ITEMS) c.judged++;
      pooled.set(s.area, c);
    }
    return { user_id: m.user_id, name: p?.display_name || p?.handle || m.user_id.slice(0, 8), items, accuracy: items ? Math.round((ok / items) * 100) : null, areas };
  }).sort((a, b) => a.name.localeCompare(b.name));

  const class_areas = SKILL_AREAS.map(a => {
    const c = pooled.get(a.id) ?? { items: 0, ok: 0, judged: 0 };
    return { area: a.id, label: a.label, items: c.items, firstTryCorrect: c.ok, accuracy: c.items ? Math.round((c.ok / c.items) * 100) : null,
      sources: { room: 0, quiz: 0, lesson: 0, scenario: 0 }, students_judged: c.judged };
  });

  const mistakes = await commonMistakes(itemsBy as Map<string, ReturnType<typeof groupItems<StoredAttempt>>>, orgId);
  // How many learners reported each of those questions (content_feedback, "room:task").
  const reportCount = new Map<string, number>();
  if (mistakes.length) {
    const { data } = await admin.from("content_feedback").select("target_id")
      .eq("target_kind", "room_task").in("target_id", mistakes.map(m => `${m.room_id}:${m.task_id}`)).limit(2000);
    for (const r of (data ?? []) as { target_id: string }[]) reportCount.set(r.target_id, (reportCount.get(r.target_id) ?? 0) + 1);
  }

  const body: SkillsResponse = {
    areas: SKILL_AREAS.map(a => ({ id: a.id, label: a.label })),
    students: rows,
    class_areas,
    common_mistakes: mistakes.map(m => ({ ...m, reports: reportCount.get(`${m.room_id}:${m.task_id}`) ?? 0 })),
    min_items: MIN_ITEMS,
  };
  return NextResponse.json(body);
}

