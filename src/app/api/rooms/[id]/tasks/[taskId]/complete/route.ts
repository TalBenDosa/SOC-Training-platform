import { NextResponse } from "next/server";
import { findTask } from "@/lib/rooms/grading";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser, canPreviewDrafts } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { ROOM_PASS_THRESHOLD, gradeableTaskMax, readingXp } from "@/lib/rooms/xp";

export const runtime = "nodejs";

/**
 * Records that a signed-in student finished one room task and credits its XP —
 * the ONLY writer of room_progress (client writes revoked in 0078).
 *
 * The XP is never taken from the request. It is:
 *   - reading task  → the task's pre-defined engagement XP (readingXp);
 *   - graded task   → the best xp_awarded the server recorded for this student's
 *                     graded submissions of the task (per sub-question for
 *                     log_analysis), i.e. pre-defined task xp with the attempt
 *                     rules applied at grading time.
 * record_room_task then merges it atomically (per-task best, never lowered),
 * marks the task completed and stamps completed_at when every task is done and
 * the gradeable score meets ROOM_PASS_THRESHOLD. profiles.xp is recomputed by
 * the room_progress trigger; the new total is returned so the page shows the
 * authoritative figure.
 *
 * Guests (no account) get { guest: true } — their progress stays in localStorage.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string; taskId: string }> },
) {
  const { id: rawRoomId, taskId: rawTaskId } = await params;
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ ok: true, guest: true });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const room = await getEffectiveRoom(decodeURIComponent(rawRoomId), user.orgId ?? null, canPreviewDrafts(user));
  if (!room) return NextResponse.json({ error: "Room not found." }, { status: 404 });
  const task = findTask(room, decodeURIComponent(rawTaskId));
  if (!task) return NextResponse.json({ error: "Task not found." }, { status: 404 });

  let body: Record<string, unknown> = {};
  try {
    const b = await req.json();
    if (b && typeof b === "object" && !Array.isArray(b)) body = b as Record<string, unknown>;
  } catch { /* an empty body is fine — telemetry is optional */ }

  // ── The task's XP, from server-held records only ────────────────────────────
  let taskXp = 0;
  if (task.type === "reading") {
    taskXp = readingXp(task);
  } else {
    const { data: attempts, error } = await admin.from("task_attempts")
      .select("xp_awarded, question_index")
      .eq("user_id", user.id).eq("room_id", room.id).eq("task_id", task.id);
    if (error) return NextResponse.json({ error: "Couldn't read your answers — please try again." }, { status: 503 });
    if (task.type === "log_analysis") {
      const best = new Map<number, number>();
      for (const a of attempts ?? []) {
        const qi = typeof a.question_index === "number" ? a.question_index : -1;
        best.set(qi, Math.max(best.get(qi) ?? 0, a.xp_awarded ?? 0));
      }
      taskXp = [...best.values()].reduce((s, v) => s + v, 0);
    } else {
      taskXp = Math.max(0, ...(attempts ?? []).map(a => a.xp_awarded ?? 0));
    }
  }

  // Optional behavioural telemetry for the instructor view — bounded, not scored.
  const rawTele = body.telemetry;
  const telemetry = rawTele && typeof rawTele === "object" && !Array.isArray(rawTele) && JSON.stringify(rawTele).length <= 4_000
    ? rawTele : null;

  const { data, error } = await admin.rpc("record_room_task", {
    p_user: user.id,
    p_org: user.orgId ?? null,
    p_room: room.id,
    p_task: task.id,
    p_task_xp: taskXp,
    p_room_task_ids: room.tasks.map(t => t.id),
    p_gradeable: gradeableTaskMax(room),
    p_pass_threshold: ROOM_PASS_THRESHOLD,
    p_telemetry: telemetry,
  });
  if (error) {
    console.error("[room complete] record_room_task failed:", error.message);
    return NextResponse.json({ error: "Couldn't save your progress — please try again." }, { status: 503 });
  }
  const row = (Array.isArray(data) ? data[0] : data) as
    { task_xp: number; room_xp: number; room_completed_at: string | null; newly_completed: boolean } | undefined;

  const { data: prof } = await admin.from("profiles").select("xp").eq("id", user.id).maybeSingle();

  return NextResponse.json({
    ok: true,
    taskXp: row?.task_xp ?? taskXp,
    roomXp: row?.room_xp ?? null,
    completedAt: row?.room_completed_at ?? null,
    newlyCompleted: row?.newly_completed ?? false,
    totalXp: prof?.xp ?? null,
  }, { headers: { "Cache-Control": "private, no-store" } });
}
