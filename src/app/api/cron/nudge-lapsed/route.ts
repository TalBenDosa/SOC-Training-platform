import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { constantTimeEquals } from "@/lib/security/constantTimeEquals";
import { sendEmailBatch } from "@/lib/email/sendEmail";
import { lapsedNudgeEmail } from "@/lib/email/templates";

export const maxDuration = 120;

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

  // CLAIM before sending: stamp last_nudged_at only on rows still eligible
  // (never nudged, or past the cooldown) and send only to the rows this run
  // actually claimed. A concurrent or repeated run (Vercel may deliver a cron
  // twice) then claims nothing, and a run killed mid-way doesn't re-send.
  const now = new Date().toISOString();
  const cutoff = new Date(Date.now() - COOLDOWN_DAYS * 86_400_000).toISOString();
  const { data: claimedRows, error: claimErr } = rows.length
    ? await admin.from("profiles").update({ last_nudged_at: now })
        .in("id", rows.map(r => r.user_id))
        .or(`last_nudged_at.is.null,last_nudged_at.lt.${cutoff}`)
        .select("id")
    : { data: [], error: null };
  if (claimErr) return NextResponse.json({ error: "Could not claim recipients." }, { status: 500 });
  const claimed = new Set((claimedRows ?? []).map(r => String(r.id)));
  const toSend = rows.filter(r => claimed.has(r.user_id));

  // Paced batch send (respects the provider's rate limit; a sequential loop of
  // single sends hit 429s and could outlive the function).
  const batch = await sendEmailBatch(toSend.map(r => {
    const daysAway = Math.max(1, Math.floor((Date.now() - Date.parse(r.last_active)) / 86_400_000));
    const { subject, html, text } = lapsedNudgeEmail({ name: r.display_name || "there", daysAway, resumeLink: `${base}/rooms` });
    return { to: r.email, subject, html, text };
  }));
  const sentIds = toSend.filter((_, i) => batch.sent[i]).map(r => r.user_id);
  const failedIds = toSend.filter((_, i) => !batch.sent[i]).map(r => r.user_id);
  const skipped = failedIds.length + (rows.length - toSend.length);

  // Release the claim for sends that didn't go out, so the next run retries them.
  // (Includes the no-provider-key case, where nothing is sent at all.)
  if (failedIds.length > 0) {
    await admin.from("profiles").update({ last_nudged_at: null }).in("id", failedIds).eq("last_nudged_at", now);
  }

  return NextResponse.json({ candidates: rows.length, sent: sentIds.length, skipped });
}

async function authorized(req: Request): Promise<boolean> {
  const secret = process.env.CRON_SECRET;
  // WEB-03: GET (sends real emails) must never ride an admin's cookie on a
  // cross-site link — it needs the cron secret; the session fallback is POST-only.
  if (!secret && req.method === "GET") return false;
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
