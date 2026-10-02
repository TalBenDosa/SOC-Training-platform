import { NextResponse } from "next/server";
import { parseTenant, tenantFromConfig, TENANT_TEMPLATE, type Tenant } from "@/lib/team/tenant";
import { asObject } from "@/lib/http/body";
import { getAuthedUser, requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { resolveTeamStory, teamStoryFilter } from "@/lib/team/buildTimeline";
import { sanitizeStack } from "@/lib/logs/native";
import { sanitizeEnv } from "@/lib/team/environment";
import { SINGLE_SEAT, rosterConflict } from "@/lib/team/roster";
import { liveAffiliationFilter } from "@/lib/team/membership";

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
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid JSON." }, { status: 400 }); }

  // The exercise runs as the instructor's own organization (English name = its domain) on the
  // template environment; without a name, a Live-SOC company as before (older clients).
  let tenant: Tenant | null = null;
  if (body.tenant_name !== undefined) {
    const t = parseTenant(body.tenant_name);
    if ("error" in t) return NextResponse.json({ error: t.error }, { status: 400 });
    tenant = t;
  }
  const company_id = tenant ? TENANT_TEMPLATE : String(body.company_id ?? "");
  if (!COMPANY_IDS.has(company_id)) return NextResponse.json({ error: "Unknown company." }, { status: 400 });
  const difficulty = DIFF.has(String(body.difficulty)) ? String(body.difficulty) : "medium";
  const format = FORMATS.has(String(body.format)) ? String(body.format) : "team_shift";
  // Optional staff-chosen storyline (an attack-story id). Must be one the builder
  // would offer for this company + difficulty; empty = random pick at /start.
  const scenario_id = body.scenario_id ? String(body.scenario_id).slice(0, 120) : null;
  // Security products the session runs on (spec §3) — only categories that differ from the company.
  const stack = sanitizeStack(body.stack);
  // A named organization's environment: the platforms it runs and its industry (which stories fit).
  const env = tenant ? sanitizeEnv(body.env) : null;
  const pinned = scenario_id ? resolveTeamStory(company_id, difficulty as "easy" | "medium" | "hard", scenario_id, env, stack) : null;
  if (scenario_id && !pinned) {
    return NextResponse.json({ error: env ? "That storyline isn't available for this environment and difficulty." : "That storyline isn't available for this company and difficulty." }, { status: 400 });
  }
  // QA M7: judged on the INSTANTIATED story (company pool + EDR), the same check the
  // timeline's random pick uses — the storyline list offers exactly these.
  if (pinned && !teamStoryFilter(company_id, stack, env)(pinned)) {
    return NextResponse.json({ error: Object.keys(stack).length
      ? "The chosen products can't show every step of that storyline — pick another storyline or keep the company's products."
      : "That storyline can't run on this company's products — pick another storyline." }, { status: 400 });
  }

  const rawInvites = Array.isArray(body.invites) ? body.invites : [];
  const invites = rawInvites
    .map(i => ({ user_id: String((i as Record<string, unknown>)?.user_id ?? ""), role: String((i as Record<string, unknown>)?.role ?? "t1") }))
    .filter(i => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(i.user_id) && ROLES.has(i.role) && i.role !== "instructor")
    // QA L12: one row per person (the first role given wins) — a repeated invitee used to fail the roster insert with a 500.
    .filter((i, k, all) => all.findIndex(x => x.user_id.toLowerCase() === i.user_id.toLowerCase()) === k)
    .slice(0, 12);
  for (const seat of SINGLE_SEAT) {
    if (invites.filter(i => i.role === seat).length > 1) {
      return NextResponse.json({ error: `${seat === "mgr" ? "SOC Manager" : "Tier-3"} is a single-seat role — invite one person to it.` }, { status: 400 });
    }
  }

  // Only invitees who are ACTIVE members of THIS org, affiliation not expired (M1), are allowed on the roster.
  const invIds = invites.map(i => i.user_id);
  const { data: orgMembers } = await admin
    .from("org_members").select("user_id")
    .eq("org_id", orgId).eq("status", "active").or(liveAffiliationFilter())
    .in("user_id", invIds.length ? invIds : ["00000000-0000-0000-0000-000000000000"]);
  const validSet = new Set((orgMembers ?? []).map(m => m.user_id));

  const { data: sess, error } = await admin
    .from("team_sessions")
    .insert({ org_id: orgId, created_by: user.id, company_id, difficulty, format, scenario_id, schema_version: 2, config: { ...(Object.keys(stack).length ? { stack } : {}), ...(tenant ? { tenant: { name: tenant.name } } : {}), ...(env ? { env } : {}) } })   // new sessions are v2 from birth (0071)
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
    const conflict = rosterConflict(memErr, "");
    if (conflict) return NextResponse.json({ error: conflict }, { status: 409 });
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
      tenant_name: tenantFromConfig((s as { config?: unknown }).config)?.name ?? null,
      my_role: mine.get(s.id as string)?.role ?? null,
      player_count: counts.get(s.id as string)?.players ?? 0,
      ready_count: counts.get(s.id as string)?.ready ?? 0,
    })),
    is_staff: staff,
  });
}
