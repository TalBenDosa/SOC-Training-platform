/**
 * POST /api/dashboard/shift: open a solo SOC Dashboard training (Stage B1).
 *
 * The server deals the training's first attack story, keeps its answer in dashboard_shifts and
 * returns the story for the browser to run. Reports are later graded only against the answer kept
 * here (/api/dashboard/incident-report with the shiftId). Signed-in learners only: a guest's
 * training stays in the browser and is never recorded.
 *
 * Body: { companyId, difficulty }. 401 guest, 404 unknown company, 429 too many trainings,
 * 503 storage not ready (the browser then runs an unrecorded practice training).
 */
import { NextResponse } from "next/server";
import { randomUUID } from "node:crypto";
import { asObject } from "@/lib/http/body";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { dealBuiltInStory, dealOrgStory, isBuiltInCompany, shiftStoryOf, type SoloDifficulty } from "@/lib/dashboard/soloShift";
import { insertShift, orgCompanyFor, recentStoryIds, ShiftSchemaMissing, shiftsInLastHour, SHIFTS_PER_HOUR } from "@/lib/dashboard/shiftStore";

export const runtime = "nodejs";
export const maxDuration = 30;

const LEVELS: SoloDifficulty[] = ["easy", "medium", "hard"];

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to record your training.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Training records are not available." }, { status: 503 });

  let body: Record<string, unknown>;
  try { body = asObject(await req.json()); } catch { return NextResponse.json({ error: "Invalid request body." }, { status: 400 }); }
  const companyId = typeof body.companyId === "string" ? body.companyId.slice(0, 120) : "";
  const difficulty = LEVELS.find(l => l === body.difficulty);
  if (!companyId || !difficulty) return NextResponse.json({ error: "companyId and difficulty are required." }, { status: 400 });

  try {
    if ((await shiftsInLastHour(admin, user.id)) >= SHIFTS_PER_HOUR) {
      return NextResponse.json({ error: "Too many trainings started in the last hour. Try again later." }, { status: 429 });
    }
    let story;
    if (isBuiltInCompany(companyId)) {
      story = dealBuiltInStory(companyId, difficulty, await recentStoryIds(admin, user.id), randomUUID());
    } else {
      const org = await orgCompanyFor(companyId);
      if (!org) return NextResponse.json({ error: "Unknown company." }, { status: 404 });
      story = dealOrgStory(org);
    }
    const shiftId = await insertShift(admin, {
      user_id: user.id, org_id: user.orgId, company_id: companyId, difficulty,
      stories: [shiftStoryOf(story, Date.now())],
    });
    return NextResponse.json({ shiftId, story }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof ShiftSchemaMissing) return NextResponse.json({ error: "Training records are not set up yet." }, { status: 503 });
    console.error("[dashboard/shift] start failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Could not start the training." }, { status: 500 });
  }
}
