import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Platform-wide student list for the super-admin — every member across every
 * environment in one table, with per-student metrics and their college, so the
 * owner can see everyone who has entered the system without opening each org.
 *
 * Super-admin only (requireSuperAdmin) and deliberately cross-tenant (service
 * role) — the one place that view is allowed. Aggregated in JS, same shape as
 * /api/org/analytics but across all orgs and carrying org_id/org_name.
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

  const [membersRes, roomsRes, scenariosRes, sessionsRes, attemptsRes, orgsRes] = await Promise.all([
    admin.from("org_members").select("org_id, user_id, role, status, joined_at, profiles(handle, display_name, xp, level)"),
    admin.from("room_progress").select("user_id, completed_at, updated_at"),
    admin.from("scenario_history").select("user_id, score, completed_at"),
    admin.from("dashboard_sessions").select("user_id, played_at"),
    admin.from("task_attempts").select("user_id, correct"),
    admin.from("organizations").select("id, name"),
  ]);

  const orgName = new Map<string, string>((orgsRes.data ?? []).map(o => [o.id, o.name]));

  // Member emails (0032 org_member_emails is per-org) — call it for each org and
  // merge into one user_id→email map. The dataset is platform-small.
  const emailBy = new Map<string, string>();
  await Promise.all([...orgName.keys()].map(async orgId => {
    const { data } = await admin.rpc("org_member_emails", { p_org: orgId });
    for (const e of (data ?? []) as Array<{ user_id: string; email: string }>) emailBy.set(e.user_id, e.email);
  }));

  type R = { user_id: string; completed_at?: string | null; updated_at?: string | null };
  const roomRows = (roomsRes.data ?? []) as R[];
  const scRows = (scenariosRes.data ?? []) as Array<{ user_id: string; score: number | null; completed_at: string | null }>;
  const dsRows = (sessionsRes.data ?? []) as Array<{ user_id: string; played_at: string | null }>;
  const atRows = (attemptsRes.data ?? []) as Array<{ user_id: string; correct: boolean }>;

  const group = <T extends { user_id: string }>(rows: T[]) => {
    const m = new Map<string, T[]>();
    for (const r of rows) { const l = m.get(r.user_id); if (l) l.push(r); else m.set(r.user_id, [r]); }
    return m;
  };
  const roomsBy = group(roomRows), scBy = group(scRows), dsBy = group(dsRows), atBy = group(atRows);

  const students: GlobalStudentRow[] = (membersRes.data ?? []).map(m => {
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
