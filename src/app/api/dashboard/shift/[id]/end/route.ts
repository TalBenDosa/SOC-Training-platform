/**
 * POST /api/dashboard/shift/[id]/end: close a solo training and write its dashboard_sessions row.
 *
 * The counts that matter (attacks presented and caught, detection rate, XP) come from the server's
 * own record: a story is presented once its first phase could have reached the feed, caught when a
 * report against it passed here, and XP follows the dashboard's rule per caught story plus the
 * mission bonus. The browser adds only its activity telemetry (rows opened, false negatives, catch
 * speed, duration), clamped. Called once; a repeat returns the row already written.
 *
 * Body: { fnCount?, eventsOpenedCount?, avgCatchMs?, durationMs? }.
 */
import { NextResponse } from "next/server";
import { asObject } from "@/lib/http/body";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { shiftTotals } from "@/lib/dashboard/soloShift";
import { loadShift, ShiftSchemaMissing } from "@/lib/dashboard/shiftStore";

export const runtime = "nodejs";

const clampInt = (v: unknown, max: number): number => {
  const n = typeof v === "number" && Number.isFinite(v) ? Math.round(v) : 0;
  return Math.min(Math.max(n, 0), max);
};

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ saved: false, guest: true }, { status: 401 });
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ saved: false }, { status: 503 });
  const { id } = await params;
  let body: Record<string, unknown> = {};
  try { body = asObject(await req.json()); } catch { /* telemetry is optional */ }

  try {
    const shift = await loadShift(admin, id, user.id);
    if (!shift) return NextResponse.json({ saved: false, error: "Unknown training." }, { status: 404 });
    if (shift.ended_at) return NextResponse.json({ saved: !!shift.session_id, sessionId: shift.session_id });

    const now = Date.now();
    const totals = shiftTotals(shift.stories, now);
    const sinceStart = now - Date.parse(shift.started_at);
    const opened = clampInt(body.eventsOpenedCount, 20_000);
    const fn = clampInt(body.fnCount, 10_000);
    // Close first, so a repeated call never writes a second row.
    const { data: closed, error: closeErr } = await admin.from("dashboard_shifts")
      .update({ ended_at: new Date(now).toISOString() }).eq("id", shift.id).is("ended_at", null).select("id");
    if (closeErr) throw new Error(closeErr.message);
    if (!closed?.length) return NextResponse.json({ saved: false });

    // A training with nothing in it (closed before any attack and without a single row opened) is not a session.
    if (totals.presented === 0 && totals.caught === 0 && opened === 0 && fn === 0) return NextResponse.json({ saved: false, empty: true });
    // dashboard_sessions.org_id is required; a learner with no active organization keeps the shift record only.
    if (!shift.org_id) return NextResponse.json({ saved: false });

    const avg = body.avgCatchMs == null ? null : clampInt(body.avgCatchMs, 6 * 3600 * 1000);
    const { data: row, error } = await admin.from("dashboard_sessions").insert({
      user_id: user.id, org_id: shift.org_id,
      played_at: new Date(now).toISOString(),
      xp_earned: totals.xp,
      detect_rate: totals.detectRate,
      fn_count: fn,
      avg_catch_ms: totals.caught > 0 ? avg : null,
      attacks_caught_count: totals.caught,
      attacks_presented_count: totals.presented,
      events_opened_count: opened,
      duration_ms: Math.min(clampInt(body.durationMs, 6 * 3600 * 1000) || sinceStart, sinceStart),
    }).select("id").single();
    if (error) throw new Error(error.message);
    const sessionId = (row as { id: string }).id;
    await admin.from("dashboard_shifts").update({ session_id: sessionId }).eq("id", shift.id);
    return NextResponse.json({ saved: true, sessionId, ...totals });
  } catch (e) {
    if (e instanceof ShiftSchemaMissing) return NextResponse.json({ saved: false }, { status: 503 });
    console.error("[dashboard/shift/end] failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ saved: false }, { status: 500 });
  }
}
