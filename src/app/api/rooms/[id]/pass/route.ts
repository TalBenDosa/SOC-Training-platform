import { NextResponse } from "next/server";
import { ContentUnavailableError } from "@/lib/content/unavailable";
import { paramOf } from "@/lib/http/params";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser, canPreviewDrafts } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { roomPassCredit, roomPassScore, type GradedAttempt } from "@/lib/rooms/mastery";

export const runtime = "nodejs";

/**
 * GET /api/rooms/[id]/pass: the signed-in student's pass credit per task in this
 * room (src/lib/rooms/mastery.ts), computed from their graded attempts. The room
 * page reads it on load, so a task answered correctly on a retry still counts in
 * the score and is not listed as "missed" after a reload (QA-ROOM-2). Read only.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ guest: true });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let room: Awaited<ReturnType<typeof getEffectiveRoom>>;
  try { room = await getEffectiveRoom(paramOf((await params).id), user.orgId ?? null, canPreviewDrafts(user)); }
  catch (e) { if (e instanceof ContentUnavailableError) return NextResponse.json({ error: "This content couldn't be loaded just now." }, { status: 503 }); throw e; }
  if (!room) return NextResponse.json({ error: "Room not found." }, { status: 404 });

  const { data, error } = await admin.from("task_attempts")
    .select("task_id, xp_awarded, question_index, correct")
    .eq("user_id", user.id).eq("room_id", room.id)
    .or("correct.eq.true,xp_awarded.gt.0")
    .order("task_id").order("question_index")
    .limit(1000);
  if (error) return NextResponse.json({ error: "Couldn't read your answers." }, { status: 503 });
  const attempts = (data ?? []) as GradedAttempt[];
  const pass = roomPassScore(room, attempts);
  return NextResponse.json(
    { perTaskCredit: roomPassCredit(room, attempts), passPct: pass.max > 0 ? pass.score / pass.max : 1 },
    { headers: { "Cache-Control": "private, no-store" } },
  );
}
