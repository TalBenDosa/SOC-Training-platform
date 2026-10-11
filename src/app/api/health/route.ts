import { NextResponse } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Liveness. `?deep=1` also checks the database with one cheap read and answers
 * 503 when it fails (QA phase 7, E-06) — for an uptime probe. Public, so it
 * reports only up/down, never error text.
 */
export async function GET(req: Request) {
  const base = { service: "hack-the-soc", version: "1.0.0", uptime: process.uptime() };
  if (new URL(req.url).searchParams.get("deep") !== "1") return NextResponse.json({ status: "ok", ...base });

  const admin = getSupabaseAdminClient();
  if (!admin) return NextResponse.json({ status: "degraded", db: "unconfigured", ...base }, { status: 503 });
  const started = Date.now();
  try {
    const { error } = await admin.from("organizations").select("id", { head: true, count: "exact" }).limit(1).abortSignal(AbortSignal.timeout(5000));
    if (error) throw new Error(error.message);
    return NextResponse.json({ status: "ok", db: "ok", db_ms: Date.now() - started, ...base }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    console.error("[health] deep check failed:", e instanceof Error ? e.message : e);
    return NextResponse.json({ status: "degraded", db: "down", ...base }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
