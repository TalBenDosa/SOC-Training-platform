import "server-only";
/**
 * Writers for the learner's own progress records (migration 0101): live-feed incident
 * reports, quiz / lesson-check attempts and standalone EDR case results.
 *
 * Every write is best effort. These rows feed the Progress page only; no XP, pass or
 * credit is ever read from them, so a failed insert (or a database that predates 0101)
 * must never fail the grade the learner is waiting for. Service-role client only: the
 * tables have no client write grants.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

/** PostgREST / Postgres error that means "this column or table does not exist yet". */
export function isMissingSchema(err: { message?: string; code?: string } | null | undefined, name?: string): boolean {
  if (!err) return false;
  const msg = err.message ?? "";
  const missing = err.code === "42703" || err.code === "42P01" || err.code === "PGRST204" || err.code === "PGRST205"
    || /does not exist|could not find the .* (column|table)/i.test(msg);
  return missing && (!name || msg.includes(name));
}

const text = (v: unknown, n: number): string | null => {
  if (typeof v !== "string") return null;
  const t = v.trim();
  return t ? t.slice(0, n) : null;
};
const texts = (v: unknown, count: number, n: number): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim() !== "").slice(0, count).map(x => x.slice(0, n)) : [];
const iso = (v: unknown): string | null => {
  const t = typeof v === "number" ? v : typeof v === "string" ? Date.parse(v) : NaN;
  if (!Number.isFinite(t)) return null;
  // A timestamp more than a day away from now is a clock problem, not a response time.
  if (Math.abs(Date.now() - t) > 86_400_000) return null;
  return new Date(t).toISOString();
};
const int = (v: unknown, lo: number, hi: number): number | null =>
  typeof v === "number" && Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.round(v))) : null;

async function insert(admin: SupabaseClient, table: string, row: Record<string, unknown>): Promise<boolean> {
  const { error } = await admin.from(table).insert(row);
  if (error) {
    if (!isMissingSchema(error)) console.error(`[progress record] ${table} insert failed:`, error.message);
    return false;
  }
  return true;
}

export interface IncidentRecordInput {
  userId: string;
  orgId: string | null;
  outcome: "passed" | "failed" | "missed";
  /** Client-reported context of the incident (the live feed is a client simulation). */
  incident: Record<string, unknown> | null | undefined;
  company?: unknown;
  title?: unknown;
  mitre?: unknown;
  summary?: unknown;
  score?: number | null;
  subScores?: { attack: number; ioc: number; action: number } | null;
  gradedBy?: "ai" | "deterministic" | null;
  feedback?: unknown;
  strengths?: unknown;
  gaps?: unknown;
  missedTell?: unknown;
}

export async function recordIncident(admin: SupabaseClient, i: IncidentRecordInput): Promise<boolean> {
  const ctx = i.incident && typeof i.incident === "object" ? i.incident : {};
  const title = text(i.title ?? ctx.title, 300) ?? "Live-feed incident";
  const sev = typeof ctx.severity === "string" && ["critical", "high", "medium", "low"].includes(ctx.severity) ? ctx.severity : null;
  return insert(admin, "dashboard_incidents", {
    user_id: i.userId,
    ...(i.orgId ? { org_id: i.orgId } : {}),
    shift_key: text(ctx.shiftKey, 64),
    incident_key: text(ctx.incidentKey, 120),
    story_id: text(ctx.storyId, 120),
    title,
    company: text(i.company, 120),
    severity: sev,
    mitre: texts(i.mitre ?? ctx.mitre, 30, 40),
    outcome: i.outcome,
    injected_at: iso(ctx.injectedAt),
    first_opened_at: iso(ctx.firstOpenedAt),
    report_opened_at: iso(ctx.reportOpenedAt),
    report_score: int(i.score, 0, 100),
    attack_score: i.subScores ? int(i.subScores.attack, 0, 40) : null,
    ioc_score: i.subScores ? int(i.subScores.ioc, 0, 30) : null,
    action_score: i.subScores ? int(i.subScores.action, 0, 30) : null,
    graded_by: i.gradedBy ?? null,
    feedback: text(i.feedback, 4000),
    strengths: texts(i.strengths, 10, 500),
    gaps: texts(i.gaps, 10, 500),
    summary: text(i.summary, 4000),
    missed_tell: text(i.missedTell, 600),
  });
}

export async function recordLearningAttempt(admin: SupabaseClient, a: {
  userId: string; orgId: string | null; kind: "quiz" | "lesson"; contentId: string;
  correct: number; total: number; scorePct: number; passed: boolean;
}): Promise<boolean> {
  return insert(admin, "learning_attempts", {
    user_id: a.userId,
    ...(a.orgId ? { org_id: a.orgId } : {}),
    kind: a.kind,
    content_id: a.contentId.slice(0, 300),
    score_pct: Math.min(100, Math.max(0, Math.round(a.scorePct))),
    correct: Math.max(0, a.correct),
    total: Math.max(0, a.total),
    passed: a.passed,
  });
}

export async function recordEdrResult(admin: SupabaseClient, r: {
  userId: string; orgId: string | null; caseId: string; title: string | null; chosen: string | null; correct: boolean; durationMs: number | null;
}): Promise<boolean> {
  return insert(admin, "edr_case_results", {
    user_id: r.userId,
    ...(r.orgId ? { org_id: r.orgId } : {}),
    case_id: r.caseId.slice(0, 120),
    title: r.title ? r.title.slice(0, 300) : null,
    chosen: r.chosen ? r.chosen.slice(0, 120) : null,
    correct: r.correct,
    duration_ms: r.durationMs == null ? null : int(r.durationMs, 0, 86_400_000),
  });
}
