import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { sanitizeStack } from "@/lib/logs/native";
import { teamStoryFilter, teamStoryPool } from "@/lib/team/buildTimeline";
import { sanitizeEnv, type TeamEnv } from "@/lib/team/environment";
import { TENANT_TEMPLATE } from "@/lib/team/tenant";
import { storyCategory } from "@/lib/team/storyCategory";

/**
 * Team-SOC storylines (read-only) — the attack stories the Session Builder can
 * pin as a session's primary incident (exercise-report #18: "no scenario choice").
 * Same candidate set the timeline draws from (teamStoryPool: company source fit, or a
 * named organization's environment — `env` — plus the difficulty's complexity tier), so
 * POST /api/team/sessions and /start accept exactly what is listed here (resolveTeamStory).
 *
 * Titles name the attack, so this is staff-only (same gate as creating a
 * session) — players never learn the storyline; the session's scenario_id is
 * already redacted from non-staff reads. Served from a route (not imported into
 * the page) so the story corpus stays out of the client bundle.
 */
const DIFF = new Set(["easy", "medium", "hard"]);
const COMPANY_IDS = new Set(COMPANY_PROFILES.map(c => c.id));

export async function GET(req: Request) {
  const g = await requireOrgStaff();
  if ("error" in g) return g.error;

  const url = new URL(req.url);
  const company = url.searchParams.get("company") ?? "";
  const difficulty = url.searchParams.get("difficulty") ?? "";
  if (!COMPANY_IDS.has(company) || !DIFF.has(difficulty)) {
    return NextResponse.json({ error: "Unknown company or difficulty." }, { status: 400 });
  }
  // Vendor choice (spec §3): only storylines every event of which the chosen products can
  // really show — judged on the instantiated story, the same predicate POST /sessions,
  // /start and the timeline use (QA M7: the raw authored events could disagree).
  let stack = {};
  try { stack = sanitizeStack(JSON.parse(url.searchParams.get("stack") ?? "{}")); } catch { stack = {}; }
  // A named organization (the template environment): its platforms and industry decide the pool.
  let env: TeamEnv | null = null;
  const envParam = url.searchParams.get("env");
  if (envParam !== null && company === TENANT_TEMPLATE) {
    try { env = sanitizeEnv(JSON.parse(envParam)); } catch { env = sanitizeEnv(null); }
  }
  const fits = teamStoryFilter(company, stack, env);
  const stories = teamStoryPool(company, difficulty as "easy" | "medium" | "hard", env, stack)
    .filter(fits)
    .map(s => ({ id: s.id, title: s.title, complexity: s.complexity, steps: s.events.length, category: storyCategory(s.id) }))
    .sort((a, b) => a.title.localeCompare(b.title));
  return NextResponse.json({ storylines: stories });
}
