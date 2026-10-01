import { NextResponse } from "next/server";
import { requireSuperAdmin } from "@/lib/auth/apiGuard";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { opsLevel, type OpsEvent, type OpsHealthRow } from "@/lib/ops/opsHealth";

/** GET — platform health for /superadmin (QA phase 7, E-06). Super-admin only. */
export async function GET() {
  const gate = await requireSuperAdmin("superadmin.ops_health");
  if ("error" in gate) return gate.error;
  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  const [h, ev] = await Promise.all([
    admin.from("team_ops_health").select("*").maybeSingle(),
    admin.from("team_ops_events").select("at, kind, session_id, detail").order("at", { ascending: false }).limit(20),
  ]);
  if (h.error) console.error("[ops-health] team_ops_health read failed:", h.error.message);
  if (ev.error) console.error("[ops-health] team_ops_events read failed:", ev.error.message);
  const health = (h.data as OpsHealthRow | null) ?? null;
  const events = ((ev.data ?? []) as OpsEvent[]).map(e => ({ ...e, detail: e.detail ? e.detail.slice(0, 300) : null }));
  return NextResponse.json({ health, events, ...opsLevel(health) });
}
