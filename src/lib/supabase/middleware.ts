/**
 * Session-refresh helper for src/middleware.ts (edge runtime). Supabase auth
 * tokens are short-lived; this refreshes them on every navigation so a signed-in
 * user doesn't get silently logged out. No-op (passes the request through
 * unchanged) when Supabase isn't configured — guest/localStorage mode.
 */
import { createServerClient } from "@supabase/ssr";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "./config";

export async function refreshSupabaseSession(req: NextRequest, res: NextResponse): Promise<NextResponse> {
  if (!isSupabaseConfigured) return res;

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

  // Touches the session, which refreshes the token if needed and (re)writes
  // the auth cookie via setAll above.
  await supabase.auth.getUser();
  return res;
}
