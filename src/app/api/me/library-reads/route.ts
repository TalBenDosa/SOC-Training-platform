import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { isMissingSchema } from "@/lib/progress/record";
import { scopeOrg } from "@/lib/progress/scope";
import { LIBRARY_INDEX } from "@/data/libraryIndex";

export const runtime = "nodejs";

/**
 * Lesson Library lessons the signed-in learner has studied (migration 0111,
 * library_reads), for Recommended Tracks progress across devices.
 *
 *   GET   -> { ids: string[] }   this learner, CURRENT organisation only (iron rule)
 *   POST  { lessonId, studied }  marks or unmarks one built-in library lesson
 *
 * The user id comes from the session, never from the body; the lesson must be a
 * built-in library lesson. A database without 0111 answers { ids: [], unavailable: true }
 * on GET and 204 on POST, so the page falls back to the browser's own marks and never
 * shows the learner an error. Cross-site writes are refused by the middleware (CSRF).
 */

const BUILTIN_LESSON_IDS = new Set(LIBRARY_INDEX.map(l => l.id));

export async function GET() {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to sync your studied lessons.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ ids: [], unavailable: true });

  const scope = { orgId: user.orgId ?? null };
  const { data, error } = await scopeOrg(
    admin.from("library_reads").select("lesson_id").eq("user_id", user.id),
    scope,
  ).limit(2000);
  if (error) {
    if (!isMissingSchema(error)) console.error("[library-reads] read failed:", error.message);
    return NextResponse.json({ ids: [], unavailable: true });
  }
  const ids = ((data ?? []) as { lesson_id: string }[]).map(r => r.lesson_id).filter(id => BUILTIN_LESSON_IDS.has(id));
  return NextResponse.json({ ids }, { headers: { "Cache-Control": "private, no-store" } });
}

export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Sign in to sync your studied lessons.", guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return new NextResponse(null, { status: 204 });

  let body: Record<string, unknown>;
  try {
    const raw = await req.text();
    if (raw.length > 500) return NextResponse.json({ error: "Too large." }, { status: 413 });
    const parsed = JSON.parse(raw);
    body = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }
  const lessonId = typeof body.lessonId === "string" ? body.lessonId : "";
  if (typeof body.studied !== "boolean" || !lessonId) {
    return NextResponse.json({ error: "lessonId and studied (true|false) are required." }, { status: 400 });
  }
  if (!BUILTIN_LESSON_IDS.has(lessonId)) return NextResponse.json({ error: "Not found." }, { status: 404 });

  const { error } = await admin.rpc("set_library_read", {
    p_user: user.id, p_org: user.orgId ?? null, p_lesson: lessonId, p_studied: body.studied,
  });
  if (error) {
    // Not deployed yet (42883 function / 42P01 table): the browser keeps the mark.
    if (!/42883|42P01|PGRST202|does not exist|could not find/i.test(`${error.code ?? ""} ${error.message}`)) {
      console.error("[library-reads] write failed:", error.message);
      return NextResponse.json({ error: "Couldn't save that right now." }, { status: 500 });
    }
    return new NextResponse(null, { status: 204 });
  }
  return NextResponse.json({ saved: true });
}
