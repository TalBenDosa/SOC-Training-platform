import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth/apiGuard";
import { ALL_QUIZZES } from "@/lib/quizzes/data";

/**
 * Admin-only: the built-in quizzes WITH their answer keys, for the content
 * console's quiz editor. The console used to import ALL_QUIZZES in the browser,
 * which published every answer inside a public /_next/static chunk.
 */
export async function GET() {
  const gate = await requireAdmin();
  if ("error" in gate) return gate.error;
  return NextResponse.json({ quizzes: ALL_QUIZZES }, { headers: { "Cache-Control": "private, no-store" } });
}
