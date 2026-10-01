import type { NextRequest } from "next/server";

/**
 * CSRF backstop (SEC-09). Cookie-authenticated state changes relied on
 * SameSite=Lax alone. A state-changing API call must come from this site: the
 * browser's Sec-Fetch-Site says so directly; older browsers send Origin, which
 * must be this origin. Server-to-server callers (Vercel cron, curl) send
 * neither and are judged by their own credentials.
 */
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
export function isCrossSiteWrite(req: NextRequest): boolean {
  if (SAFE_METHODS.has(req.method)) return false;
  if (req.nextUrl.pathname.startsWith("/api/cron/")) return false;
  const site = req.headers.get("sec-fetch-site");
  if (site) return site !== "same-origin" && site !== "none";
  const origin = req.headers.get("origin");
  if (origin) return origin !== req.nextUrl.origin;
  return false;
}
