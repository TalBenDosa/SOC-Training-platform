import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getSupabaseServerClient } from "@/lib/supabase/server";

/**
 * Only allow redirecting to a SAME-ORIGIN relative path. Without this, `next`
 * is attacker-controlled and `${origin}${next}` becomes an open redirect:
 *   next="@evil.com"   → https://app@evil.com   (host = evil.com via userinfo)
 *   next=".evil.com"   → https://app.evil.com    (attacker subdomain)
 *   next="//evil.com"  → protocol-relative → evil.com
 * A path must start with a single "/" and not "//" or "/\" (which browsers
 * treat as protocol-relative). Anything else falls back to the app home.
 */
function safeNext(raw: string | null): string {
  if (!raw || !raw.startsWith("/")) return "/rooms";
  if (raw.startsWith("//") || raw.startsWith("/\\")) return "/rooms";
  return raw;
}

/**
 * Landed on after the user clicks an email confirmation link. Exchanges the
 * one-time `code` for a session (sets the auth cookie via the server client),
 * then redirects into the app.
 */
export async function GET(req: NextRequest) {
  const { searchParams, origin } = new URL(req.url);
  const code = searchParams.get("code");
  const next = safeNext(searchParams.get("next"));

  if (code) {
    const supabase = await getSupabaseServerClient();
    if (supabase) {
      await supabase.auth.exchangeCodeForSession(code);
    }
  }

  return NextResponse.redirect(`${origin}${next}`);
}
