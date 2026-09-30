import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { fetchAll } from "@/lib/plans/server";

/**
 * Platform-wide student list for the super-admin — every member across every
 * environment in one table, with per-student metrics and their college, so the
 * owner can see everyone who has entered the system without opening each org.
 *
 * Super-admin only (requireSuperAdmin) and deliberately cross-tenant (service
 * role) — the one place that view is allowed. Aggregated in JS, same shape as
 * /api/org/analytics but across all orgs and carrying org_id/org_name.
 *
 * Every read is PAGED (PostgREST returns at most 1000 rows per request — it
 * used to cut task_attempts etc. silently, giving wrong metrics and missing
 * students) and any failed read fails the request instead of showing zeros.
 */

export interface GlobalStudentRow {
  user_id: string;
  org_id: string;
  org_name: string;
  handle: string | null;
  display_name: string | null;
  email: string | null;
  role: string;
  status: string;
  joined_at: string | null;
  xp: number;
  level: number;
  rooms_completed: number;
  rooms_started: number;
  scenarios_completed: number;
  scenario_avg_score: number | null;
  mistakes: number;
  last_active_at: string | null;
}

const avg = (n: number[]) => (n.length === 0 ? null : Math.round(n.reduce((s, x) => s + x, 0) / n.length));
const latest = (dates: (string | null | undefined)[]) => {
  let best: number | null = null;
  for (const d of dates) { if (!d) continue; const t = Date.parse(d); if (!Number.isNaN(t) && (best === null || t > best)) best = t; }
  return best === null ? null : new Date(best).toISOString();
};

export async function GET() {
  const gate = await requireSuperAdmin("superadmin.students");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  type MemberRow = { org_id: string; user_id: string; role: string; status: string; joined_at: string | null; profiles: unknown };
  type R = { user_id: string; completed_at?: string | null; updated_at?: string | null };
  type ScRow = { user_id: string; score: number | null; completed_at: string | null };
  type DsRow = { user_id: string; played_at: string | null };
  type AtRow = { user_id: string; correct: boolean };
  let memberRows: MemberRow[], roomRows: R[], scRows: ScRow[], dsRows: DsRow[], atRows: AtRow[];
  let orgRows: { id: string; name: string }[];
  const emailBy = new Map<string, string>();
  try {
    [memberRows, roomRows, scRows, dsRows, atRows, orgRows] = await Promise.all([
      fetchAll<MemberRow>((f, t) => admin.from("org_members").select("org_id, user_id, role, status, joined_at, profiles(handle, display_name, xp, level)").order("org_id").order("user_id").range(f, t), "superadmin:members"),
      fetchAll<R>((f, t) => admin.from("room_progress").select("user_id, completed_at, updated_at").order("user_id").order("room_id").range(f, t), "superadmin:rooms"),
      fetchAll<ScRow>((f, t) => admin.from("scenario_history").select("user_id, score, completed_at").order("id").range(f, t), "superadmin:scenarios"),
      fetchAll<DsRow>((f, t) => admin.from("dashboard_sessions").select("user_id, played_at").order("id").range(f, t), "superadmin:sessions"),
      // Only the wrong answers are needed (the "mistakes" metric).
      fetchAll<AtRow>((f, t) => admin.from("task_attempts").select("user_id, correct").eq("correct", false).order("id").range(f, t), "superadmin:attempts"),
      fetchAll<{ id: string; name: string }>((f, t) => admin.from("organizations").select("id, name").order("id").range(f, t), "superadmin:orgs"),
    ]);
    // Member emails (0032 org_member_emails is per-org) — one paged call per org,
    // merged into one user_id→email map.
    const perOrg = await Promise.all(orgRows.map(o => fetchAll<{ user_id: string; email: string }>(
      (f, t) => admin.rpc("org_member_emails", { p_org: o.id }).range(f, t), "superadmin:emails")));
    for (const list of perOrg) for (const e of list) emailBy.set(e.user_id, e.email);
  } catch (e) {
    console.error("[superadmin students]", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Couldn't load the student list — please try again." }, { status: 500 });
  }

  const orgName = new Map<string, string>(orgRows.map(o => [o.id, o.name]));

  const group = <T extends { user_id: string }>(rows: T[]) => {
    const m = new Map<string, T[]>();
    for (const r of rows) { const l = m.get(r.user_id); if (l) l.push(r); else m.set(r.user_id, [r]); }
    return m;
  };
  const roomsBy = group(roomRows), scBy = group(scRows), dsBy = group(dsRows), atBy = group(atRows);

  const students: GlobalStudentRow[] = memberRows.map(m => {
    const p = m.profiles as unknown as { handle?: string; display_name?: string; xp?: number; level?: number } | null;
    const rp = roomsBy.get(m.user_id) ?? [];
    const sc = scBy.get(m.user_id) ?? [];
    const ds = dsBy.get(m.user_id) ?? [];
    const at = atBy.get(m.user_id) ?? [];
    const completed = rp.filter(r => r.completed_at);
    return {
      user_id: m.user_id,
      org_id: m.org_id,
      org_name: orgName.get(m.org_id) ?? "—",
      handle: p?.handle ?? null,
      display_name: p?.display_name ?? null,
      email: emailBy.get(m.user_id) ?? null,
      role: m.role,
      status: m.status,
      joined_at: m.joined_at,
      xp: p?.xp ?? 0,
      level: p?.level ?? 1,
      rooms_completed: completed.length,
      rooms_started: rp.length,
      scenarios_completed: sc.length,
      scenario_avg_score: avg(sc.map(s => s.score ?? 0)),
      mistakes: at.filter(a => !a.correct).length,
      last_active_at: latest([
        ...rp.map(r => r.updated_at), ...rp.map(r => r.completed_at),
        ...sc.map(s => s.completed_at), ...ds.map(s => s.played_at),
      ]),
    };
  }).sort((a, b) => (Date.parse(b.last_active_at ?? "0") || 0) - (Date.parse(a.last_active_at ?? "0") || 0));

  const orgs = [...orgName.entries()].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));

  return NextResponse.json({ students, orgs });
}
