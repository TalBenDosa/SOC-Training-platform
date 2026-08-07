import { NextResponse } from "next/server";
import { findRoom, findTask, gradeTask } from "@/lib/rooms/grading";

export const runtime = "nodejs";

/**
 * Grades one Room task submission server-side (see src/lib/rooms/grading.ts
 * for why). No auth gate: Rooms are usable by guests (progress kept in
 * localStorage) as well as signed-in users, and grading itself has no
 * user-specific side effect — the caller still persists the result via the
 * existing storage facade, exactly as before this endpoint existed.
 */
export async function POST(
  req: Request,
  { params }: { params: Promise<{ id: string; taskId: string }> },
) {
  const { id: roomId, taskId } = await params;

  const room = findRoom(decodeURIComponent(roomId));
  if (!room) return NextResponse.json({ error: "Room not found." }, { status: 404 });

  const task = findTask(room, decodeURIComponent(taskId));
  if (!task) return NextResponse.json({ error: "Task not found." }, { status: 404 });

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  const result = gradeTask(task, body);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status });
  }

  return NextResponse.json({
    correct: result.correct,
    xpEarned: result.xpEarned,
    reveal: result.reveal,
  });
}
