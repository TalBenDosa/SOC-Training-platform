import { NextResponse } from "next/server";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { FILM_EVENT_KINDS, FILM_EVENTS_PER_HOUR, filmIdent, filmNum, filmPath } from "@/lib/media/filmEvent";

export const runtime = "nodejs";

/**
 * One room-film playback event (migration 0117, film_playback_events), sent by the film player as a
 * beacon. Signed-in learners only; guests and a missing table (code deployed before the migration)
 * are answered 204: telemetry is best effort and must never show the learner an error.
 */
export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return new NextResponse(null, { status: 204 });
  const admin = getSupabaseAdminClient();
  if (!admin) return new NextResponse(null, { status: 204 });

  let body: Record<string, unknown>;
  try {
    const raw = await req.text();
    if (raw.length > 2000) return NextResponse.json({ error: "Too large." }, { status: 413 });
    const parsed = JSON.parse(raw);
    body = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return NextResponse.json({ error: "Invalid JSON." }, { status: 400 });
  }
  const kind = typeof body.kind === "string" && FILM_EVENT_KINDS.has(body.kind) ? body.kind : null;
  const src = filmPath(body.src);
  if (!kind || !src) return NextResponse.json({ error: "kind and a film src are required." }, { status: 400 });

  const since = new Date(Date.now() - 3_600_000).toISOString();
  const { count, error: countError } = await admin.from("film_playback_events")
    .select("id", { count: "exact", head: true }).eq("user_id", user.id).gte("created_at", since);
  if (countError) {
    if (!/42P01|does not exist/i.test(`${countError.code ?? ""} ${countError.message}`)) console.error("[film-event] count failed:", countError.message);
    return new NextResponse(null, { status: 204 });
  }
  if ((count ?? 0) >= FILM_EVENTS_PER_HOUR) return new NextResponse(null, { status: 204 });

  const netType = typeof body.netType === "string" && /^[\w-]{1,16}$/.test(body.netType) ? body.netType : null;
  const { error } = await admin.from("film_playback_events").insert({
    user_id: user.id,
    org_id: user.orgId ?? null,
    room_id: filmIdent(body.roomId, 120),
    clip_key: filmIdent(body.clipKey, 60),
    src_path: src,
    kind,
    wait_ms: kind === "recovered" ? (() => { const w = filmNum(body.waitMs, 3_600_000); return w == null ? null : Math.round(w); })() : null,
    position_s: filmNum(body.positionS, 86_400),
    duration_s: filmNum(body.durationS, 86_400),
    net_type: netType,
    downlink_mbps: filmNum(body.downlinkMbps, 100_000),
  });
  if (error && !/42P01|does not exist/i.test(`${error.code ?? ""} ${error.message}`)) console.error("[film-event] insert failed:", error.message);
  return new NextResponse(null, { status: 204 });
}
