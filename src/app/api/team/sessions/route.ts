import { NextResponse } from "next/server";
import { getAuthedUser, requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { resolveTeamStory } from "@/lib/team/buildTimeline";

/**
 * Team-SOC sessions (Phase 0.3). Create = org_admin/instructor only, and always
 * pinned to the caller's OWN org (org id from the JWT, never the body); invitees
 * must be active members of that same org. List = every session I'm a member of,
 * plus (for staff) every session in my org. Reads/writes use the service-role
 * client but are authorised here; the DB RLS (0049) is the second gate.
 */

const ROLES = new Set(["t1", "t2", "t3", "lead", "de", "ti", "mgr", "instructor", "observer"]);
const DIFF = new Set(["easy", "medium", "hard"]);
const FORMATS = new Set(["team_shift", "handover", "vs", "rotation"]);
const COMPANY_IDS = new Set(COMPANY_PROFILES.map(c => c.id));

// ── POST — create a session + invite members ────────────────────────────────
export async function POST(req: Request) {
  const gate = await requireOrgStaff("team.session.create");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const orgId = user.orgId;
  if (!orgId) return NextResponse.json({ error: "No organisation in session." }, { status: 400 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  const company_id = String(body.company_id ?? "");
  if (!COMPANY_IDS.has(company_id)) return NextResponse.json({ error: "Unknown company." }, { status: 400 });
  const difficulty = DIFF.has(String(body.difficulty)) ? String(body.difficulty) : "medium";
  const format = FORMATS.has(String(body.format)) ? String(body.format) : "team_shift";
  // Optional staff-chosen storyline (an attack-story id). Must be one the builder
  // would offer for this company + difficulty; empty = random pick at /start.
  const scenario_id = body.scenario_id ? String(body.scenario_id).slice(0, 120) : null;
  if (scenario_id && !resolveTeamStory(company_id, difficulty as "easy" | "medium" | "hard", scenario_id)) {
    return NextResponse.json({ error: "That storyline isn't available for this company and difficulty." }, { status: 400 });
  }

  const rawInvites = Array.isArray(body.invites) ? body.invites : [];
  const invites = rawInvites
    .map(i => ({ user_id: String((i as Record<string, unknown>)?.user_id ?? ""), role: String((i as Record<string, unknown>)?.role ?? "t1") }))
    .filter(i => i.user_id && ROLES.has(i.role) && i.role !== "instructor")
    .slice(0, 12);

  // Only invitees who are ACTIVE members of THIS org are allowed on the roster.
  const invIds = invites.map(i => i.user_id);
  const { data: orgMembers } = await admin
    .from("org_members").select("user_id")
    .eq("org_id", orgId).eq("status", "active")
    .in("user_id", invIds.length ? invIds : ["00000000-0000-0000-0000-000000000000"]);
  const validSet = new Set((orgMembers ?? []).map(m => m.user_id));

  const { data: sess, error } = await admin
    .from("team_sessions")
    .insert({ org_id: orgId, created_by: user.id, company_id, difficulty, format, scenario_id, schema_version: 2 })   // new sessions are v2 from birth (0071)
    .select("id").single();
  if (error || !sess) {
    if (error) console.error("[team create] session insert:", error.message);   // no raw DB text to the client (S12)
    return NextResponse.json({ error: "Could not create the session." }, { status: 500 });
  }

  // Creator joins as instructor (runs it, excluded from the ready-check); invitees
  // join as their assigned role, status 'invited' until they click ready.
  const rows = [{ session_id: sess.id, user_id: user.id, role: "instructor", status: "active", invited_by: user.id }];
  for (const i of invites) {
    if (i.user_id !== user.id && validSet.has(i.user_id)) {
      rows.push({ session_id: sess.id, user_id: i.user_id, role: i.role, status: "invited", invited_by: user.id });
    }
  }
  const { error: memErr } = await admin.from("team_session_members").insert(rows);
  if (memErr) {
    console.error("[team create] roster insert:", memErr.message);
    // Don't leave a session with no owner behind.
    await admin.from("team_sessions").delete().eq("id", sess.id);
    return NextResponse.json({ error: "Could not add the invited members." }, { status: 500 });
  }

  return NextResponse.json({ ok: true, id: sess.id });
}

// ── GET — sessions I can see (my memberships; staff also see their org's) ────
export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const staff = user.isPlatformAdmin || user.orgRole === "org_admin" || user.orgRole === "instructor";

  const { data: myMem } = await admin.from("team_session_members")
    .select("session_id, role, status").eq("user_id", user.id);
  const mine = new Map((myMem ?? []).map(m => [m.session_id, { role: m.role, status: m.status }]));

  let sessions: Record<string, unknown>[] = [];
  if (staff && user.orgId) {
    const { data } = await admin.from("team_sessions").select("*").eq("org_id", user.orgId).order("created_at", { ascending: false }).limit(100);
    sessions = data ?? [];
  } else {
    const ids = [...mine.keys()];
    const { data } = await admin.from("team_sessions").select("*").in("id", ids.length ? ids : ["00000000-0000-0000-0000-000000000000"]).order("created_at", { ascending: false }).limit(100);
    sessions = data ?? [];
  }

  // one roster read for all listed sessions → per-session counts (no N+1)
  const ids = sessions.map(s => s.id as string);
  const { data: allMem } = await admin.from("team_session_members")
    .select("session_id, role, status").in("session_id", ids.length ? ids : ["00000000-0000-0000-0000-000000000000"]);
  const counts = new Map<string, { players: number; ready: number }>();
  for (const m of allMem ?? []) {
    const c = counts.get(m.session_id) ?? { players: 0, ready: 0 };
    if (m.role !== "instructor") { c.players++; if (m.status === "ready" || m.status === "active") c.ready++; }
    counts.set(m.session_id, c);
  }

  // Never ship the grading answer-key (seed → deterministic timeline + verdicts)
  // or other spoiler fields to a non-staff member.
  const redact = (row: Record<string, unknown>) => {
    if (staff) return row;
    const { seed: _seed, config: _config, scenario_id: _scn, ...safe } = row;
    void _seed; void _config; void _scn;
    return safe;
  };
  return NextResponse.json({
    sessions: sessions.map(s => ({
      ...redact(s),
      my_role: mine.get(s.id as string)?.role ?? null,
      player_count: counts.get(s.id as string)?.players ?? 0,
      ready_count: counts.get(s.id as string)?.ready ?? 0,
    })),
    is_staff: staff,
  });
}
