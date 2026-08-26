import { NextResponse } from "next/server";
import { findTask, gradeTask } from "@/lib/rooms/grading";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

export const runtime = "nodejs";

/**
 * Grades one Room task submission server-side (see src/lib/rooms/grading.ts
 * for why). No auth GATE: Rooms are usable by guests (progress kept in
 * localStorage) as well as signed-in users, and grading itself has no
 * user-specific side effect — the caller still persists the result via the
 * existing storage facade, exactly as before this endpoint existed.
 *
 * It DOES, however, record the attempt for a signed-in student (task_attempts,
 * migration 0031) so the instructor drill-down can show WHERE a student erred —
 * what they submitted, whether it was right, which try it was. Best-effort and
 * non-blocking: a guest, or a failed insert, never affects the grade returned.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string; taskId: string }> },
) {
  const { id: roomId, taskId } = await params;

  // Fetched once: the session gives org context for resolving an org-authored
  // room AND identifies the student for the attempt log below.
  const user = await getAuthedUser();

  // Resolves static built-ins AND org-authored DB rooms (the latter get their
  // answer key merged in from the service-role-only key table).
  const room = await getEffectiveRoom(decodeURIComponent(roomId), user?.orgId ?? null);
  if (!room) return NextResponse.json({ error: "Room not found." }, { status: 404 });

  const task = findTask(room, decodeURIComponent(taskId));
  if (!task) return NextResponse.json({ error: "Task not found." }, { status: 404 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  // Pass the resolved room so written_report grading can scan its shown content
  // (reading + events) for legitimately-citable indicators, not just the task's
  // hand-authored referenceIocs — otherwise a correct citation of room-visible
  // evidence is wrongly branded "fabricated".
  const result = gradeTask(task, body, room);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  // Record the attempt for a signed-in student — best-effort, never blocks the
  // grade. Written via the service role with user_id + org_id from the session.
  try {
    const admin = getSupabaseAdminClient();
    if (user && admin) {
      const b = (body ?? {}) as Record<string, unknown>;
      const attemptNo = Number(b.attemptNumber);
      const latency = Number(b.latencyMs ?? b.decisionLatencyMs);
      // Store the submission minus bookkeeping fields — just what they answered.
      const { attemptNumber: _a, latencyMs: _l, decisionLatencyMs: _d, ...submitted } = b;
      void _a; void _l; void _d;
      await admin.from("task_attempts").insert({
        user_id: user.id,
        org_id: user.orgId ?? null,
        room_id: room.id,
        task_id: task.id,
        task_type: task.type,
        correct: result.correct,
        submitted,
        attempt_no: Number.isFinite(attemptNo) && attemptNo > 0 ? attemptNo : 1,
        latency_ms: Number.isFinite(latency) && latency >= 0 ? Math.round(latency) : null,
      });
    }
  } catch { /* telemetry is a convenience, never a hard dependency */ }

  return NextResponse.json({
    correct: result.correct,
    xpEarned: result.xpEarned,
    reveal: result.reveal,
  });
}
