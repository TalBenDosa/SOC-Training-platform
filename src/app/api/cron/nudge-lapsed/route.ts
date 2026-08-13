import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { constantTimeEquals } from "@/lib/security/constantTimeEquals";
import { sendEmail } from "@/lib/email/sendEmail";
import { lapsedNudgeEmail } from "@/lib/email/templates";

/**
 * Emails learners who started but have gone quiet, then stamps
 * profiles.last_nudged_at so nobody is chased twice inside the cooldown.
 *
 * Auth mirrors /api/cron/expire-orgs: CRON_SECRET as a Bearer token when set
 * (that's what Vercel Cron sends), otherwise a platform super-admin so a human
 * can trigger it. The route is exempt from the middleware session gate — this
 * secret IS its authentication.
 *
 * Safety properties, because this is the one job that talks to real people:
 *  · `?dry=1` returns exactly who WOULD be mailed and sends nothing. Run this
 *    first after any change to the targeting rule.
 *  · The cooldown lives in SQL (lapsed_students), not here, so a bug in this
 *    route cannot turn a daily cron into daily spam.
 *  · last_nudged_at is stamped only for addresses that actually sent, so a
 *    provider outage doesn't silently consume someone's cooldown.
 *  · With RESEND_API_KEY unset, sendEmail no-ops — this ships dormant and
 *    activates when the email domain is configured (go-live blocker 2).
 */

// Scheduled WEEKLY (Mon 08:00) in vercel.json, not daily: the SQL cooldown
// already prevents repeats, but a weekly cadence keeps the blast radius small
// and lands on a Monday morning rather than mid-weekend.
const IDLE_DAYS = 7;
const COOLDOWN_DAYS = 14;
const MAX_PER_RUN = 200;

interface LapsedRow {
  user_id: string;
  email: string;
  display_name: string | null;
  org_name: string | null;
  last_active: string;
}

async function run(dry: boolean) {
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const { data, error } = await admin.rpc("lapsed_students", {
    p_idle_days: IDLE_DAYS,
    p_cooldown_days: COOLDOWN_DAYS,
    p_limit: MAX_PER_RUN,
  });
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  const rows = (data ?? []) as LapsedRow[];
  if (dry) {
    return NextResponse.json({
      dry_run: true,
      would_email: rows.length,
      recipients: rows.map(r => ({
        name: r.display_name,
        org: r.org_name,
        days_idle: Math.floor((Date.now() - Date.parse(r.last_active)) / 86_400_000),
      })),
    });
  }

  const base = process.env.NEXT_PUBLIC_SITE_URL ?? "https://soc-training-platform-jade.vercel.app";
  const sentIds: string[] = [];
  let skipped = 0;

  for (const r of rows) {
    const daysAway = Math.max(1, Math.floor((Date.now() - Date.parse(r.last_active)) / 86_400_000));
    const { subject, html, text } = lapsedNudgeEmail({
      name: r.display_name || "there",
      daysAway,
      resumeLink: `${base}/rooms`,
    });
    const res = await sendEmail({ to: r.email, subject, html, text });
    if (res.ok) sentIds.push(r.user_id);
    else skipped++;
  }

  // Stamp only the ones that actually went out.
  if (sentIds.length > 0) {
    await admin.from("profiles").update({ last_nudged_at: new Date().toISOString() }).in("id", sentIds);
  }

  return NextResponse.json({ candidates: rows.length, sent: sentIds.length, skipped });
}

async function authorized(req: Request): Promise<boolean> {
  const secret = process.env.CRON_SECRET;
  if (secret) {
    // Constant-time compare — a plain === on the secret is a timing side-channel.
    return constantTimeEquals(req.headers.get("authorization") ?? "", `Bearer ${secret}`);
  }
  const gate = await requireSuperAdmin("superadmin.cron.nudge");
  return !("error" in gate);
}

export async function GET(req: Request) {
  if (!(await authorized(req))) {
    return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  }
  const dry = new URL(req.url).searchParams.get("dry") === "1";
  return run(dry);
}

export async function POST(req: Request) {
  return GET(req);
}
