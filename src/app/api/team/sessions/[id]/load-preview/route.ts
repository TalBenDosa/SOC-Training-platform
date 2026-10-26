import { NextResponse } from "next/server";
import { tenantFromConfig } from "@/lib/team/tenant";
import { envFromConfig } from "@/lib/team/environment";
import { planFromConfig, loadWithPlan, attackCount, type AttackPlan } from "@/lib/team/attackPlan";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { buildFittedTimeline } from "@/lib/team/fitTimeline";
import { teamLoad, withShiftMinutes, sanitizeShiftMinutes, SHIFT_CHOICES } from "@/lib/team/load";
import type { WorkloadPreview } from "@/lib/team/workloadPreview";
import { sanitizeStack } from "@/lib/logs/native/stack";

/**
 * GET /api/team/sessions/[id]/load-preview — staff only, own org.
 *
 * Builds the exercise exactly as /start would (same plan, roster, shift, products, seed) WITHOUT
 * saving anything, and measures the work it asks of each tier (workloadPreview.ts). When it is
 * more than the team can do, it also measures the alternatives the instructor can pick: one
 * storyline fewer, a longer shift, one more Tier-1 analyst (Tal, 2026-10-25: "I don't want a
 * negative overload like the first exercise").
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const gate = await requireOrgStaff("team.session.start");
  if ("error" in gate) return gate.error;
  const { user } = gate;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data: sess } = await admin.from("team_sessions").select("id, org_id, status, company_id, difficulty, seed, scenario_id, config").eq("id", id).maybeSingle();
  if (!sess) return NextResponse.json({ error: "Session not found." }, { status: 404 });
  if (!user.isPlatformAdmin && sess.org_id !== user.orgId) return NextResponse.json({ error: "Not your session." }, { status: 403 });
  if (!["easy", "medium", "hard"].includes(sess.difficulty)) return NextResponse.json({ error: "Unknown difficulty." }, { status: 400 });

  const { data: members, error: membersErr } = await admin.from("team_session_members").select("role, status").eq("session_id", id);
  if (membersErr) return NextResponse.json({ error: "Couldn't read the team." }, { status: 503 });
  const roster = (members ?? []) as { role: string; status?: string }[];

  const plan = planFromConfig(sess.config, sess.scenario_id);
  const shiftMin = sanitizeShiftMinutes((sess.config as { shift_min?: unknown } | null)?.shift_min);
  const stack = sanitizeStack((sess.config as { stack?: unknown } | null)?.stack);
  const env = envFromConfig(sess.config);
  const tenant = tenantFromConfig(sess.config);
  const d = sess.difficulty as "easy" | "medium" | "hard";

  const measure = (p: AttackPlan, shift: number | null, team: { role: string; status?: string }[]): WorkloadPreview & { stories: number } | null => {
    try {
      const planned = loadWithPlan(withShiftMinutes(teamLoad(d, team), shift), p);
      // The exercise /start will seed: built, measured and fitted to the team (fitTimeline.ts).
      const { load, workload } = buildFittedTimeline({ companyId: sess.company_id, difficulty: d, seed: sess.seed, slots: p.slots, load: planned, stack, tenant, env, opts: { bonus: false }, roster: team });
      return { ...workload, stories: load.stories };
    } catch { return null; }
  };

  const current = measure(plan, shiftMin, roster);
  if (!current) return NextResponse.json({ error: "Couldn't build the exercise for a preview." }, { status: 500 });

  const alternatives: { kind: "fewer_stories" | "longer_shift" | "more_tier1"; label: string; preview: WorkloadPreview }[] = [];
  if (current.level === "over") {
    const n = attackCount(plan, loadWithPlan(withShiftMinutes(teamLoad(d, roster), shiftMin), plan));
    if (n > 1) {
      const fewer = measure({ ...plan, count: n - 1, slots: plan.slots.slice(0, n - 1) }, shiftMin, roster);
      if (fewer) alternatives.push({ kind: "fewer_stories", label: `${n - 1} storyline${n - 1 === 1 ? "" : "s"} instead of ${n}`, preview: fewer });
    }
    const longer = SHIFT_CHOICES.find(m => m > current.shiftMin);
    if (longer) {
      const p = measure(plan, longer, roster);
      if (p) alternatives.push({ kind: "longer_shift", label: `a ${longer}-minute shift`, preview: p });
    }
    const plusOne = measure(plan, shiftMin, [...roster, { role: "t1", status: "ready" }]);
    if (plusOne) alternatives.push({ kind: "more_tier1", label: "one more Tier-1 analyst", preview: plusOne });
  }
  return NextResponse.json({ preview: current, alternatives }, { headers: { "Cache-Control": "private, no-store" } });
}
