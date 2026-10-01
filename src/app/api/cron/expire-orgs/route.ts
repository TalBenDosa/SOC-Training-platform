import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { constantTimeEquals } from "@/lib/security/constantTimeEquals";
import { purgeOrphanUploads } from "@/lib/storage/purgeOrphanUploads";
import { awardTeamXp, sessionsMissingXp } from "@/lib/team/awardTeamXp";

/**
 * Flips organizations whose license window has passed to status='expired'.
 * Meant to run on a schedule (Vercel Cron): add to vercel.json
 *   { "crons": [{ "path": "/api/cron/expire-orgs", "schedule": "0 3 * * *" }] }
 *
 * Auth: when CRON_SECRET is set, the caller must present it as a Bearer token
 * (Vercel Cron sends `Authorization: Bearer $CRON_SECRET`). Otherwise it falls
 * back to requiring a platform super-admin, so a human can trigger it manually.
 * The route is exempt from the middleware session gate (it has no user session);
 * this secret is its authentication.
 */
async function run() {
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { data, error } = await admin.rpc("expire_due_orgs");
  if (error) {
    console.error("[cron/expire-orgs] expire_due_orgs failed:", error.message);
    return NextResponse.json({ error: "Couldn't expire organisations." }, { status: 500 });
  }
  // SEC-17: the same daily run clears abandoned (never-finalized) uploads.
  const uploads = await purgeOrphanUploads(admin).catch(e => { console.error("[cron/expire-orgs] purge failed:", (e as Error).message); return null; });
  // 0087: team sessions that ended without an XP award (reaped, or the award at
  // end-time failed) are awarded here.
  let teamXp = 0;
  for (const sid of await sessionsMissingXp(admin, 20)) {
    try { await awardTeamXp(admin, sid); teamXp++; }
    catch (e) { console.error(`[cron/expire-orgs] team XP for ${sid} failed:`, (e as Error).message); }
  }
  // E-20 (QA phase 7): one summary line per run, so the logs show it ran.
  console.info(`[cron/expire-orgs] done: expired=${data ?? 0} orphanUploads=${JSON.stringify(uploads)} teamXpAwarded=${teamXp}`);
  return NextResponse.json({ expired: data ?? 0, orphanUploads: uploads, teamXpAwarded: teamXp });
}

async function authorized(req: Request): Promise<boolean> {
  const secret = process.env.CRON_SECRET;
  // WEB-03: a GET is reachable by a cross-site top-level link carrying the admin's
  // Lax cookie — so GET needs the cron secret, never the session fallback.
  if (!secret && req.method === "GET") {
    // E-20: otherwise the daily run fails as a silent 401.
    console.error("[cron/expire-orgs] CRON_SECRET is not set — the scheduled run was refused. Set it in the Vercel project settings.");
    return false;
  }
  if (secret) {
    const auth = req.headers.get("authorization") ?? "";
    // Constant-time compare — a plain === on the secret is a timing side-channel.
    return constantTimeEquals(auth, `Bearer ${secret}`);
  }
  const gate = await requireSuperAdmin("superadmin.cron.expire");
  return !("error" in gate);
}

export async function GET(req: Request) {
  if (!(await authorized(req))) return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  return run();
}

export async function POST(req: Request) {
  if (!(await authorized(req))) return NextResponse.json({ error: "Unauthorized." }, { status: 401 });
  return run();
}
