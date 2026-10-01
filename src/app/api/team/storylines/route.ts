import { NextResponse } from "next/server";
import { requireOrgStaff } from "@/lib/auth/apiGuard";
import { storiesForCompany } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import { sanitizeStack, storyFitsStack } from "@/lib/logs/native";

/**
 * Team-SOC storylines (read-only) — the attack stories the Session Builder can
 * pin as a session's primary incident (exercise-report #18: "no scenario choice").
 * Same candidate set the timeline draws from (storiesForCompany: company source
 * fit + the difficulty's complexity tier), so POST /api/team/sessions and /start
 * accept exactly what is listed here (resolveTeamStory).
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
  // Vendor choice (spec §3): only storylines every event of which the chosen products can really show.
  let stack = {};
  try { stack = sanitizeStack(JSON.parse(url.searchParams.get("stack") ?? "{}")); } catch { stack = {}; }
  const stories = storiesForCompany(company, difficulty as "easy" | "medium" | "hard")
    .filter(s => Object.keys(stack).length === 0 || storyFitsStack(s.events, company, stack))
    .map(s => ({ id: s.id, title: s.title, complexity: s.complexity, steps: s.events.length }))
    .sort((a, b) => a.title.localeCompare(b.title));
  return NextResponse.json({ storylines: stories });
}
