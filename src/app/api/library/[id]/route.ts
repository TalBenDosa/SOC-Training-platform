import { NextResponse } from "next/server";
import { paramOf } from "@/lib/http/params";
import { getAuthedUser, requireAdmin } from "@/lib/auth/apiGuard";
import { BUILTIN_LESSONS } from "@/data/builtinLessons";

export const runtime = "nodejs";

/**
 * GET /api/library/[id]: one built-in Lesson Library lesson, loaded when a
 * reader opens it. The /learn grid only carries the small LIBRARY_INDEX; this
 * route is the single server function that holds the full BUILTIN_LESSONS.
 *
 *   default      the reader's copy: no `quiz` (the library reader never shows
 *                it, and it carries the answer key)
 *   ?full=1      the complete lesson, quiz included, for the admin syllabus
 *                editor; admin only
 *
 * Access matches the /learn page: the edge middleware's default-deny already
 * requires a session (and an active licence) for every /api route.
 */
const BY_ID = new Map((BUILTIN_LESSONS as unknown as { id: string }[]).map(l => [l.id, l]));

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const lesson = BY_ID.get(paramOf(id)) as ({ quiz?: unknown } & Record<string, unknown>) | undefined;
  if (!lesson) return NextResponse.json({ error: "Lesson not found." }, { status: 404 });

  if (new URL(req.url).searchParams.get("full") === "1") {
    const gate = await requireAdmin();
    if ("error" in gate) return gate.error;
    return NextResponse.json(lesson, { headers: { "Cache-Control": "private, no-store" } });
  }

  // Defense in depth on top of the middleware; React-cache()d, so no extra round-trip.
  await getAuthedUser();
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { quiz, ...reader } = lesson;
  // Content only changes with a deploy, so a short private cache makes reopening instant.
  return NextResponse.json(reader, { headers: { "Cache-Control": "private, max-age=600" } });
}
