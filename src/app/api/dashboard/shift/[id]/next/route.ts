/**
 * POST /api/dashboard/shift/[id]/next: deal the next attack story of a running solo training
 * (after a passing report, or after the debrief of a missed attack). Its answer joins the shift's
 * record; the story goes to the browser. Never a story this shift already dealt.
 */
import { NextResponse } from "next/server";
import { randomUUID } from "node:crypto";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { dealBuiltInStory, dealOrgStory, isBuiltInCompany, MAX_STORIES_PER_SHIFT, shiftStoryOf } from "@/lib/dashboard/soloShift";
import { loadShift, orgCompanyFor, recentStoryIds, saveStories, ShiftSchemaMissing } from "@/lib/dashboard/shiftStore";

export const runtime = "nodejs";
export const maxDuration = 30;

export async function POST(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to record your training.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Training records are not available." }, { status: 503 });
  const { id } = await params;

  try {
    const shift = await loadShift(admin, id, user.id);
    if (!shift || shift.ended_at) return NextResponse.json({ error: "This training is not running." }, { status: 404 });
    if (shift.stories.length >= MAX_STORIES_PER_SHIFT) {
      return NextResponse.json({ error: "This training has no more attacks." }, { status: 409 });
    }
    // This shift's stories first (newest first), then the learner's history.
    const own = shift.stories.map(s => s.storyId).reverse();
    let story;
    if (isBuiltInCompany(shift.company_id)) {
      const recent = [...own, ...(await recentStoryIds(admin, user.id)).filter(x => !own.includes(x))];
      story = dealBuiltInStory(shift.company_id, shift.difficulty, recent, randomUUID());
    } else {
      const org = await orgCompanyFor(shift.company_id);
      if (!org) return NextResponse.json({ error: "Unknown company." }, { status: 404 });
      story = dealOrgStory(org);
    }
    await saveStories(admin, shift.id, [...shift.stories, shiftStoryOf(story, Date.now())]);
    return NextResponse.json({ story }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    if (e instanceof ShiftSchemaMissing) return NextResponse.json({ error: "Training records are not set up yet." }, { status: 503 });
    console.error("[dashboard/shift/next] failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ error: "Could not deal the next attack." }, { status: 500 });
  }
}
