import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { refreshSupabaseSession } from "@/lib/supabase/middleware";

/**
 * Edge middleware — two responsibilities, composed:
 *
 * 1. API rate limiting (all routes under /api/*).
 *    WHY: ~10 API routes call paid LLM providers (Anthropic / OpenAI) and, before
 *    this, were reachable with NO authentication and NO throttling. On a public
 *    deployment that is a financial-DoS vector (anyone can drain the API budget)
 *    and a prompt-injection surface. This caps request volume per client IP.
 *
 *    SCOPE / LIMITS: counters live in per-instance memory, so on a serverless/
 *    edge platform they reset on cold start and aren't shared across instances.
 *    This is a deliberate FIRST layer; production MUST back it with a durable
 *    store (Upstash Redis / Vercel KV) keyed by IP + user id, plus real auth on
 *    the write endpoints. Tracked in PRODUCTION_READINESS_PLAN.md (Phase 0/4).
 *
 * 2. Supabase session refresh (all page routes).
 *    Auth tokens are short-lived; touching the session here on every navigation
 *    keeps a signed-in user logged in. No-op when Supabase isn't configured.
 */

// Expensive endpoints that spend money / do heavy work → tight limit.
const EXPENSIVE = [
  "/api/scenarios/generate",
  "/api/quizzes/generate",
  "/api/lessons/generate",
  "/api/lessons/generate-stream",
  "/api/lessons/import-pptx",
  "/api/lessons/validate",
  "/api/lessons/export-pptx",
  "/api/dashboard/ai-grade",
  "/api/dashboard/incident-report",
  "/api/admin/",
];

function isExpensive(pathname: string): boolean {
  if (EXPENSIVE.some(p => pathname.startsWith(p))) return true;
  // Per-scenario grading is also an LLM call.
  if (pathname.startsWith("/api/scenarios/") && pathname.endsWith("/grade")) return true;
  return false;
}

function clientIp(req: NextRequest): string {
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) return fwd.split(",")[0].trim();
  return req.headers.get("x-real-ip") ?? "unknown";
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // ── 1. API rate limiting (unchanged behavior, only for /api/*) ──────────────
  if (pathname.startsWith("/api/")) {
    const ip = clientIp(req);
    const expensive = isExpensive(pathname);
    // Expensive: 10 req / min. General API: 100 req / min.
    const limit = expensive ? 10 : 100;
    const windowMs = 60_000;
    const key = `${expensive ? "x" : "g"}:${ip}`;

    const { ok, retryAfter } = checkRateLimit(key, limit, windowMs);
    if (!ok) {
      return NextResponse.json(
        { error: "Too many requests — slow down and try again shortly." },
        { status: 429, headers: { "Retry-After": String(retryAfter) } },
      );
    }
    // API routes don't need session-cookie refresh (they read the cookie as-is).
    return NextResponse.next();
  }

  // ── 2. Supabase session refresh (page routes) ────────────────────────────────
  return refreshSupabaseSession(req, NextResponse.next());
}

// Run on API routes (rate limiting) and page routes (session refresh) — skip
// static assets, images, and Next internals.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
