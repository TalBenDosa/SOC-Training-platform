/**
 * Session refresh + page-route access control for src/middleware.ts (edge runtime).
 *
 * Two jobs:
 *
 * 1. Refresh. Supabase auth tokens are short-lived; touching the session on
 *    every navigation refreshes the token so a signed-in user isn't silently
 *    logged out.
 *
 * 2. Gate. Before this, middleware ONLY refreshed — no page route was ever
 *    protected. A live check against production confirmed that /, /admin,
 *    /dashboard, /scenarios, /progress and /learn all returned 200 to an
 *    anonymous caller, so the whole platform including the content-authoring
 *    panel was public. The API layer was already enforcing (every generate/
 *    admin route returns 401 to a stranger), so this was UI and content
 *    exposure rather than a data breach — but /admin has no business rendering
 *    for someone who is not the owner.
 *
 * Middleware is the right layer for this: it runs server-side before the page
 * renders or its RSC payload is serialised, so unlike a client-side redirect
 * there is no window in which protected markup reaches the browser.
 */
import { createServerClient } from "@supabase/ssr";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "./config";

/** Reachable without signing in: the landing page and the auth flow itself. */
const PUBLIC_PREFIXES = [
  "/login",
  "/signup",
  "/update-password",
  "/auth",          // callback / email-confirmation routes
];

/** Admin-only. Content authoring — the panel the platform owner edits with. */
const ADMIN_PREFIXES = ["/admin"];

function isPublicPath(pathname: string): boolean {
  if (pathname === "/") return true;
  return PUBLIC_PREFIXES.some(p => pathname === p || pathname.startsWith(p + "/"));
}

function isAdminPath(pathname: string): boolean {
  return ADMIN_PREFIXES.some(p => pathname === p || pathname.startsWith(p + "/"));
}

export async function refreshSupabaseSession(req: NextRequest, res: NextResponse): Promise<NextResponse> {
  const { pathname } = req.nextUrl;

  // Without Supabase the app runs in local/guest mode (localStorage only, no
  // accounts, no shared data). Gating everything would lock an operator out of
  // their own local instance, so pass through — but NEVER for /admin, which
  // must not become reachable merely because auth happens to be unconfigured.
  // Failing closed on the one privileged surface is the safe default.
  if (!isSupabaseConfigured) {
    if (isAdminPath(pathname)) {
      return NextResponse.redirect(new URL("/login?reason=admin_requires_auth", req.url));
    }
    return res;
  }

  const supabase = createServerClient(supabaseUrl!, supabaseAnonKey!, {
    cookies: {
      getAll() {
        return req.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) req.cookies.set(name, value);
        res = NextResponse.next({ request: req });
        for (const { name, value, options } of cookiesToSet) res.cookies.set(name, value, options);
      },
    },
  });

  // getUser() (not getSession()) — it validates the JWT against the auth server
  // instead of trusting the cookie, so a forged or expired cookie cannot get
  // past this gate. Same reasoning as src/lib/auth/apiGuard.ts.
  const { data: { user } } = await supabase.auth.getUser();

  if (isPublicPath(pathname)) return res;

  // ── Not signed in → login, remembering where they were headed ──────────────
  if (!user) {
    const to = new URL("/login", req.url);
    to.searchParams.set("next", pathname + req.nextUrl.search);
    return NextResponse.redirect(to);
  }

  // ── Signed in, but /admin additionally requires role='admin' ───────────────
  if (isAdminPath(pathname)) {
    const { data: profile } = await supabase
      .from("profiles")
      .select("role")
      .eq("id", user.id)
      .maybeSingle();

    // Fail closed: a missing profile row or a read error is NOT admin.
    if (profile?.role !== "admin") {
      return NextResponse.redirect(new URL("/?reason=forbidden", req.url));
    }
  }

  return res;
}
