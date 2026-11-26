import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

export const runtime = "nodejs";

/**
 * One presence beat (migration 0123, user_presence_days): "this learner is on the platform now".
 * Sent by <PresenceBeat /> from every app page: once when the app opens, then once a minute while
 * the tab is visible and the learner did something in the last two minutes, and once more when the
 * page is left. The org admin's "last seen", visits and active time come from these rows.
 *
 * The user and the organisation come from the validated session, never from the body; the body
 * carries only the active seconds since the last beat, capped at 120 here and in record_presence.
 * Guests are not recorded. A missing table (code deployed before the migration) and any failure
 * are answered 204: presence is best effort and must never show the learner an error.
 */
export async function POST(req: Request) {
  const done = () => new NextResponse(null, { status: 204 });
  const user = await getAuthedUser();
  if (!user) return done();
  const admin = getSupabaseAdminClient();
  if (!admin) return done();

  let seconds = 0;
  try {
    const raw = await req.text();
    if (raw.length > 200) return NextResponse.json({ error: "Too large." }, { status: 413 });
    const n = Math.floor(Number((raw ? JSON.parse(raw) : {})?.seconds));
    if (Number.isFinite(n) && n > 0) seconds = Math.min(n, 120);
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }

  const { error } = await admin.rpc("record_presence", { p_user: user.id, p_org: user.orgId ?? null, p_seconds: seconds });
  if (error && !/42883|42P01|PGRST202|does not exist|could not find/i.test(`${error.code ?? ""} ${error.message}`)) {
    console.error("[presence] record failed:", error.message);
  }
  return done();
}
