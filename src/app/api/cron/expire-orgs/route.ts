import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { constantTimeEquals } from "@/lib/security/constantTimeEquals";

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
  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ expired: data ?? 0 });
}

async function authorized(req: Request): Promise<boolean> {
  const secret = process.env.CRON_SECRET;
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
