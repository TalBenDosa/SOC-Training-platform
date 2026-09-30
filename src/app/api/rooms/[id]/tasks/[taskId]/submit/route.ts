import { NextResponse } from "next/server";
import { findTask, gradeTask } from "@/lib/rooms/grading";
import { getEffectiveRoom } from "@/lib/rooms/resolve";
import { getAuthedUser, canPreviewDrafts } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { retryXp } from "@/lib/rooms/xp";

export const runtime = "nodejs";

/**
 * Grades one Room task submission server-side (see src/lib/rooms/grading.ts
 * for why). No auth GATE: Rooms are usable by guests (progress kept in
 * localStorage) as well as signed-in users.
 *
 * For a signed-in student every graded submission is RECORDED (task_attempts)
 * with the XP the server awarded for it — the pre-defined task/question xp with
 * the attempt rules applied from the server's own attempt count (0078). That
 * row is the source of the task's XP: POST …/complete credits the best
 * xp_awarded into room_progress. The instructor drill-down reads the same rows.
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
  const room = await getEffectiveRoom(decodeURIComponent(roomId), user?.orgId ?? null, canPreviewDrafts(user));
  if (!room) return NextResponse.json({ error: "Room not found." }, { status: 404 });

  const task = findTask(room, decodeURIComponent(taskId));
  if (!task) return NextResponse.json({ error: "Task not found." }, { status: 404 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  const b = (body && typeof body === "object" && !Array.isArray(body) ? body : {}) as Record<string, unknown>;
  const admin = getSupabaseAdminClient();
  const record = !!(user && admin);   // signed-in → this attempt is recorded and is the source of the task's XP
  const qIndex = task.type === "log_analysis" && typeof b.questionIndex === "number" ? Math.floor(b.questionIndex) : null;

  // Attempt number from the SERVER's own history, never the client's claim
  // (the client could otherwise always say "first try" for full credit). For
  // log_analysis each sub-question counts separately. A higher client claim is
  // still honoured for the reveal UX — it can only lower XP, never raise it.
  //
  // The number is CLAIMED atomically in the database (claim_task_attempt, 0080):
  // a count followed by a separate insert let parallel requests — one per option
  // of a question — all read "0 previous" and all grade as the first try.
  let attemptNo = Math.max(1, Math.min(1000, Math.floor(Number(b.attemptNumber)) || 1));
  if (record) {
    const { data: claimed, error: claimErr } = await admin!.rpc("claim_task_attempt", {
      p_user: user!.id, p_room: room.id, p_task: task.id, p_qidx: qIndex,
    });
    if (claimErr || typeof claimed !== "number") {
      if (claimErr) console.error("[room submit] claim_task_attempt failed:", claimErr.message);
      return NextResponse.json({ error: "Couldn't check your previous attempts — please try again." }, { status: 503 });
    }
    attemptNo = Math.max(attemptNo, claimed);
  }

  // Pass the resolved room so written_report grading can scan its shown content
  // (reading + events) for legitimately-citable indicators, not just the task's
  // hand-authored referenceIocs — otherwise a correct citation of room-visible
  // evidence is wrongly branded "fabricated".
  const result = gradeTask(task, { ...b, attemptNumber: attemptNo >= 2 ? 2 : 1 }, room);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }
  // Pre-defined task XP with the retry rule applied (see src/lib/rooms/xp.ts).
  const xpAwarded = retryXp(task.type, result.xpEarned, attemptNo);

  // Record the attempt for a signed-in student. This row is where the task's XP
  // comes from (POST …/complete credits the best xp_awarded), so a failed write
  // fails the request instead of silently losing the student's points.
  if (record) {
    const latency = Number(b.latencyMs ?? b.decisionLatencyMs);
    // Store the submission minus bookkeeping fields — just what they answered.
    const { attemptNumber: _a, latencyMs: _l, decisionLatencyMs: _d, ...rawSubmitted } = b;
    void _a; void _l; void _d;
    // Bounded: the body is client-controlled, and a written report is the
    // largest legitimate answer (~8k chars). Anything bigger is not stored.
    const size = JSON.stringify(rawSubmitted).length;
    const submitted = size <= 20_000 ? rawSubmitted : { _omitted: "submission too large to store", size };
    const { error: insErr } = await admin!.from("task_attempts").insert({
      user_id: user!.id,
      org_id: user!.orgId ?? null,
      room_id: room.id,
      task_id: task.id,
      task_type: task.type,
      correct: result.correct,
      submitted,
      attempt_no: attemptNo,
      question_index: qIndex,
      xp_awarded: xpAwarded,
      latency_ms: Number.isFinite(latency) && latency >= 0 ? Math.min(Math.round(latency), 86_400_000) : null,
    });
    if (insErr) {
      console.error("[room submit] could not record attempt:", insErr.message);
      return NextResponse.json({ error: "Couldn't save your answer — please try again." }, { status: 503 });
    }
  }

  return NextResponse.json({
    correct: result.correct,
    xpEarned: xpAwarded,
    attemptNo,
    reveal: result.reveal,
  });
}
