import { NextResponse, NextRequest } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { refreshSupabaseSession } from "@/lib/supabase/middleware";
import { createServerClient } from "@supabase/ssr";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "@/lib/supabase/config";
import { decodeOrgClaim } from "@/lib/auth/orgClaim";
import { buildPageCsp, makeNonce } from "@/lib/security/csp";
import { isCrossSiteWrite } from "@/lib/security/csrf";
import { hasBadUuidSegment } from "@/lib/http/params";
import { isAuthOutage } from "@/lib/auth/authOutage";

/**
 * Edge middleware — two responsibilities, composed:
 *
 * 1. API rate limiting (all routes under /api/*).
 *    WHY: ~10 API routes call paid LLM providers (Anthropic / OpenAI) and, before
 *    this, were reachable with NO authentication and NO throttling. On a public
 *    deployment that is a financial-DoS vector (anyone can drain the API budget)
 *    and a prompt-injection surface. This caps request volume per client IP.
 *
 *    STORE: durable when UPSTASH_REDIS_REST_URL/TOKEN are set (cross-instance
 *    fixed-window over Upstash REST); otherwise falls back to a per-instance
 *    in-memory counter that resets on cold start. See src/lib/security/rateLimit.ts.
 *    Write endpoints are additionally gated by real auth (getUser) below.
 *
 * 2. Supabase session refresh (all page routes).
 *    Auth tokens are short-lived; touching the session here on every navigation
 *    keeps a signed-in user logged in. No-op when Supabase isn't configured.
 */

// Expensive endpoints that spend money / do heavy work → tight limit.
const EXPENSIVE = [
  "/api/scenarios/generate",
  "/api/quizzes/generate",
  // Whole /api/lessons/ subtree is paid: /generate*, /import-pptx, /validate,
  // /export-pptx AND the dynamic /api/lessons/[slug] generator. The [slug] route
  // was the only student-reachable paid path escaping both the 10/min limit and
  // the per-org LLM budget — the prefix closes that gap.
  "/api/lessons/",
  "/api/dashboard/incident-report",
  "/api/admin/",
  "/api/org/media",   // file uploads — heavy body, tight limit
  "/api/org/content", // per-org authoring writes — content jsonb, tight limit
];

// Cheap, non-LLM lesson endpoints under the paid /api/lessons/ prefix: per-question
// knowledge-check grading and lesson completion. Counting them against the 10/min
// "expensive" budget meant one lesson (load + N graded questions + complete) could
// hit 429 — and a whole class behind one office IP shares that budget — so the pass
// was never recorded and the lesson's XP never credited.
function isCheapLessonCall(pathname: string, method: string): boolean {
  if (!pathname.startsWith("/api/lessons/")) return false;
  if (pathname.endsWith("/quiz/grade") || pathname.endsWith("/complete")) return true;
  // GET /api/lessons/<path--lesson> is every lesson page load. Path lessons are
  // hand-authored; the route only calls a model on a cache miss and checks the
  // AI budget first (lessonContent.ts), so it must not share the 10/min bucket.
  return method === "GET" && /^\/api\/lessons\/[^/]+$/.test(pathname);
}

export function isExpensive(pathname: string, method = "GET"): boolean {
  if (isCheapLessonCall(pathname, method)) return false;
  // Opening a college file (GET /api/org/media/<id>/url) is a signed-URL read,
  // not an upload — only the upload paths are heavy.
  if (pathname.startsWith("/api/org/media") && method === "GET") return false;
  if (EXPENSIVE.some(p => pathname.startsWith(p))) return true;
  // Per-scenario grading is also an LLM call.
  if (pathname.startsWith("/api/scenarios/") && pathname.endsWith("/grade")) return true;
  return false;
}

function clientIp(req: NextRequest): string {
  // Derive the rate-limit key from a PLATFORM-TRUSTED source, not a
  // client-controlled one. On Vercel, `x-real-ip` is set by the platform to the
  // true edge-observed client IP and cannot be spoofed through the proxy. The
  // left-most `x-forwarded-for` entry, by contrast, is whatever the client sent
  // (the platform APPENDS the real hop), so keying on it let an attacker rotate
  // the header to get a fresh bucket per request — defeating the limiter on the
  // unauthenticated routes it exists to protect. Prefer x-real-ip; if only XFF
  // is present, take the RIGHT-most hop (closest to the platform edge).
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  const fwd = req.headers.get("x-forwarded-for");
  if (fwd) {
    const hops = fwd.split(",");
    return hops[hops.length - 1].trim();
  }
  return "unknown";
}

/**
 * The only API paths reachable without a session. Deliberately tiny:
 *  - /api/health      — liveness probe, returns no user or content data
 *  - /api/auth/*      — the sign-in flow itself, which by definition runs
 *                       before a session exists
 *  - /api/cron/*      — scheduled jobs (Vercel Cron) that have no user session;
 *                       authenticated by CRON_SECRET inside the route instead
 *  - /api/invitations/* — pre-signup invite lookup for the /join page; returns
 *                       only an org name + validity, keyed by an opaque token
 * Everything else is closed by default (see the gate in middleware()).
 */
const PUBLIC_API_PREFIXES = ["/api/health", "/api/auth/", "/api/cron/", "/api/invitations/", "/api/access-codes/"];

function isPublicApi(pathname: string): boolean {
  return PUBLIC_API_PREFIXES.some(p => pathname === p || pathname.startsWith(p));
}

/**
 * Is there a real, server-validated session on this request?
 *
 * Uses getUser(), which verifies the JWT against the Supabase auth server,
 * rather than getSession(), which would trust whatever cookie was sent. A
 * forged or expired cookie therefore cannot pass this gate.
 *
 * Returns true when Supabase isn't configured: that is local/guest mode with no
 * accounts at all, and blanket-401ing the API would break a developer's own
 * instance. The privileged surfaces stay closed regardless — /admin is gated
 * separately in refreshSupabaseSession(), and every admin route calls
 * requireAdmin(), which fails closed when there is no auth backend.
 */
// Bound the auth call so a slow provider yields a fast, retriable 503 rather
// than hanging the Edge middleware into a 504 (MIDDLEWARE_INVOCATION_TIMEOUT).
const API_AUTH_TIMEOUT = Symbol("api-auth-timeout");
function withApiAuthTimeout<T>(p: Promise<T>, ms = 4000): Promise<T | typeof API_AUTH_TIMEOUT> {
  return Promise.race([p, new Promise<typeof API_AUTH_TIMEOUT>(r => setTimeout(() => r(API_AUTH_TIMEOUT), ms))]);
}

/**
 * API paths a member of a college whose licence lapsed may still call (SEC-04):
 * their own account (export / delete / password / join another environment /
 * renew), and accepting an invitation elsewhere. Mirrors the page gate, which
 * locks every page but /license.
 */
const LICENCE_EXEMPT_API = ["/api/account", "/api/invitations/", "/api/notifications"];
function isLicenceExemptApi(pathname: string): boolean {
  return LICENCE_EXEMPT_API.some(p => p.endsWith("/") ? pathname.startsWith(p) : pathname === p || pathname.startsWith(`${p}/`));
}

async function getApiAuth(req: NextRequest): Promise<{ authed: boolean; orgId: string | null; userId?: string; timedOut?: boolean; licenceLocked?: boolean }> {
  if (!isSupabaseConfigured) return { authed: true, orgId: null };
  const supabase = createServerClient(supabaseUrl!, supabaseAnonKey!, {
    cookies: {
      getAll() { return req.cookies.getAll(); },
      setAll() { /* read-only probe — no cookie writes on the API path */ },
    },
  });
  const userResult = await withApiAuthTimeout(supabase.auth.getUser());
  if (userResult === API_AUTH_TIMEOUT) return { authed: false, orgId: null, timedOut: true };
  // E-05: the auth service failing is a 503 (retry), not "signed out" (401).
  if (!userResult.data.user && isAuthOutage(userResult.error)) return { authed: false, orgId: null, timedOut: true };
  if (!userResult.data.user) return { authed: false, orgId: null };
  // Read the tenant from the (validated) session so expensive routes can be
  // budgeted per-org. Absent pre-migration → no org limit, unchanged behaviour.
  const sessionResult = await withApiAuthTimeout(supabase.auth.getSession());
  const token = sessionResult === API_AUTH_TIMEOUT ? undefined : sessionResult.data.session?.access_token;
  const claim = decodeOrgClaim(token);
  return {
    authed: true, orgId: claim.orgId, userId: userResult.data.user.id,
    // Only an explicit `false` locks (null = no claim), and never the platform admin.
    licenceLocked: claim.orgActive === false && !claim.isPlatformAdmin,
  };
}

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // ── 1. API rate limiting + default-deny auth (only for /api/*) ──────────────
  if (pathname.startsWith("/api/")) {
    if (isCrossSiteWrite(req)) {
      return NextResponse.json({ error: "Cross-site request refused." }, { status: 403 });
    }
    if (hasBadUuidSegment(pathname)) return NextResponse.json({ error: "Not found." }, { status: 404 });   // E-23
    const ip = clientIp(req);
    const expensive = isExpensive(pathname, req.method);
    // Expensive: 10 req / min. General API: 100 req / min.
    const limit = expensive ? 10 : 100;
    const windowMs = 60_000;
    const tooMany = (retryAfter: number, error = "Too many requests — slow down and try again shortly.") =>
      NextResponse.json({ error }, { status: 429, headers: { "Retry-After": String(retryAfter) } });

    if (isPublicApi(pathname)) {
      // No session on these paths → the client IP is the only key. The code /
      // invitation lookups get a wider budget (E-02): a whole class registering at
      // once behind one college NAT makes ~3 lookups each and tripped the 100/min
      // limit — students were then told their valid code was dead. 300/min is still
      // ~4e5 guesses a day against ~8.5e11 codes that live 24 h.
      const lookup = pathname.startsWith("/api/access-codes/") || pathname.startsWith("/api/invitations/");
      const { ok, retryAfter } = await checkRateLimit(`${expensive ? "x" : lookup ? "l" : "g"}:${ip}`, lookup && !expensive ? 300 : limit, windowMs);
      if (!ok) return tooMany(retryAfter);
      return NextResponse.next();
    }

    // ── 1b. Default-deny for the API surface ─────────────────────────────────
    // Individual routes already guard themselves (requireAdmin / getAuthedUser),
    // but that is opt-in: a route added later with no guard is public by
    // default, and that is exactly how `GET /api/scenarios/[slug]` came to serve
    // its full answer key to anonymous callers. This flips the default — a new
    // route is closed unless its prefix is listed above.
    //
    // A coarse per-IP ceiling runs BEFORE the auth call so a flood can't turn
    // every request into a Supabase auth round-trip. It is deliberately high: a
    // whole class often shares one college NAT address.
    const flood = await checkRateLimit(`ip:${ip}`, 600, windowMs);
    if (!flood.ok) return tooMany(flood.retryAfter);

    const { authed, orgId, userId, timedOut, licenceLocked } = await getApiAuth(req);
    // Auth provider slow → fast retriable 503, never a hung 504.
    if (timedOut) {
      return NextResponse.json(
        { error: "Authentication is temporarily unavailable — please retry." },
        { status: 503, headers: { "Retry-After": "2" } },
      );
    }
    if (!authed) {
      return NextResponse.json({ error: "Authentication required." }, { status: 401 });
    }
    // SEC-04: a suspended / expired college was locked out of PAGES only — its
    // members (and admins) kept the whole API with their session cookie.
    if (licenceLocked && !isLicenceExemptApi(pathname)) {
      return NextResponse.json({ error: "Your college's licence isn't active. Contact your administrator." }, { status: 403 });
    }

    // Per-USER budget (per-IP only in local/guest mode with no accounts): keying
    // signed-in traffic on the IP made ~30 students behind one NAT share a
    // single 10/min "expensive" budget, so lesson loads and scenario submits 429'd.
    const who = userId ? `u:${userId}` : ip;
    const own = await checkRateLimit(`${expensive ? "x" : "g"}:${who}`, limit, windowMs);
    if (!own.ok) return tooMany(own.retryAfter);

    // Per-ORG budget guard on expensive (paid-LLM) routes: a whole college's
    // students share one pool, so one tenant can't drain another's spend. The
    // monthly AI budget (checkAiBudget) is the hard cost cap; this only smooths
    // bursts, sized so a full class submitting at once is not refused.
    if (expensive && orgId) {
      const orgCheck = await checkRateLimit(`xorg:${orgId}`, 200, windowMs);
      if (!orgCheck.ok) return tooMany(orgCheck.retryAfter, "Your organisation is sending requests too quickly — please wait a moment.");
    }

    // API routes don't need session-cookie refresh (they read the cookie as-is).
    return NextResponse.next();
  }

  // ── 2. Page routes: per-request CSP nonce + Supabase session refresh ─────────
  // Next.js reads the nonce from the REQUEST's CSP header and stamps it on its
  // scripts; the same policy goes on the response (SEC-03).
  const nonce = makeNonce();
  const csp = buildPageCsp({ nonce, dev: process.env.NODE_ENV !== "production", supabaseUrl });
  const headers = new Headers(req.headers);
  headers.set("x-nonce", nonce);
  headers.set("content-security-policy", csp);
  const pageReq = new NextRequest(req, { headers });
  const res = await refreshSupabaseSession(pageReq, NextResponse.next({ request: { headers } }));
  res.headers.set("Content-Security-Policy", csp);
  return res;
}

// Run on API routes (rate limiting) and page routes (session refresh) — skip
// static assets, images, media, and Next internals. Media (mp4/webm/vtt) must be
// excluded like images so self-hosted lesson videos stream publicly without the
// auth middleware intercepting each byte-range request (otherwise an anonymous
// request 307-redirects and seeking breaks); lesson assets are public by design,
// the gating is at the page level.
export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon\\.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|mp4|webm|m4v|vtt)$).*)"],
};
