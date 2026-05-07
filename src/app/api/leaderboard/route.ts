import { NextResponse } from "next/server";

export async function GET() {
  // In production, this hits public.leaderboard view in Supabase.
  return NextResponse.json({
    rows: Array.from({ length: 24 }, (_, i) => ({
      handle: `analyst-${(i + 1).toString().padStart(3, "0")}`,
      xp: Math.round(82_000 * Math.pow(0.92, i)) + (24 - i) * 50,
      level: Math.min(99, Math.floor((Math.round(82_000 * Math.pow(0.92, i))) / 1000) + 1),
      badges: Math.max(0, 24 - i),
    })),
  });
}
