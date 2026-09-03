import "server-only";
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getSupabaseAdminClient } from "@/lib/supabase/admin";
import { sendEmail } from "@/lib/email/sendEmail";
import { passwordResetEmail } from "@/lib/email/templates";

/**
 * Self-contained password-reset request — deliberately NOT Supabase's built-in
 * resetPasswordForEmail.
 *
 * Why: the built-in flow routes the email through the project's Site URL +
 * Redirect-URLs allowlist, and a stale/missing entry there silently bounces the
 * user to the site root (where a real student hit a "create account / email
 * exists" dead end). It also uses PKCE, so the emailed link only works in the
 * SAME browser it was requested from.
 *
 * This route instead mints a STATELESS Supabase recovery token via the admin
 * API (`generateLink` — generates only, sends nothing), builds the link
 * ourselves against the request's own origin, and sends it with our own verified
 * Resend sender. The result: the link is immune to the Site-URL/allowlist config
 * AND works cross-device (the /update-password page verifies the token_hash with
 * verifyOtp, which needs no code-verifier).
 *
 * Security posture:
 *  - Always responds 200 {ok:true} whether or not the email exists (no account
 *    enumeration); a non-existent address simply sends nothing.
 *  - Best-effort in-memory rate limiting per email + per IP (a speed bump against
 *    inbox-bombing / quota exhaustion; matches the platform's memory-based
 *    limiter posture).
 *  - Admin client is server-only and never reaches the browser bundle.
 */

export const runtime = "nodejs";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ── Best-effort in-memory rate limit ────────────────────────────────────────
type Bucket = { count: number; resetAt: number };
const byEmail = new Map<string, Bucket>();
const byIp = new Map<string, Bucket>();
const EMAIL_LIMIT = { max: 3, windowMs: 15 * 60_000 };   // 3 / 15 min per email
const IP_LIMIT = { max: 12, windowMs: 60 * 60_000 };     // 12 / hour per IP

function hit(map: Map<string, Bucket>, key: string, lim: { max: number; windowMs: number }): boolean {
  const now = Date.now();
  const b = map.get(key);
  if (!b || now > b.resetAt) { map.set(key, { count: 1, resetAt: now + lim.windowMs }); return true; }
  if (b.count >= lim.max) return false;
  b.count++;
  return true;
}
// Opportunistic cleanup so the maps can't grow unbounded on a long-lived instance.
function sweep(map: Map<string, Bucket>) {
  if (map.size < 5000) return;
  const now = Date.now();
  for (const [k, b] of map) if (now > b.resetAt) map.delete(k);
}

function clientIp(req: NextRequest): string {
  const xff = req.headers.get("x-forwarded-for");
  return (xff ? xff.split(",")[0] : "").trim() || req.headers.get("x-real-ip") || "unknown";
}

export async function POST(req: NextRequest) {
  let email = "";
  try {
    const body = await req.json();
    email = String(body?.email ?? "").trim().toLowerCase();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request." }, { status: 400 });
  }
  if (!EMAIL_RE.test(email)) {
    // Shape error only — reveals nothing about account existence.
    return NextResponse.json({ ok: false, error: "Enter a valid email address." }, { status: 400 });
  }

  const ip = clientIp(req);
  sweep(byEmail); sweep(byIp);
  if (!hit(byIp, ip, IP_LIMIT) || !hit(byEmail, email, EMAIL_LIMIT)) {
    return NextResponse.json(
      { ok: false, error: "Too many reset requests. Please wait a few minutes and try again." },
      { status: 429 },
    );
  }

  const admin = getSupabaseAdminClient();
  const origin = req.nextUrl.origin; // the domain the user is actually on

  // Do the real work but NEVER leak whether the account exists — always 200.
  if (admin) {
    try {
      const { data, error } = await admin.auth.admin.generateLink({
        type: "recovery",
        email,
        options: { redirectTo: `${origin}/update-password` },
      });
      const tokenHash = data?.properties?.hashed_token;
      if (!error && tokenHash) {
        const resetLink = `${origin}/update-password?token_hash=${encodeURIComponent(tokenHash)}&type=recovery`;
        const msg = passwordResetEmail({ resetLink });
        const sent = await sendEmail({ to: email, subject: msg.subject, html: msg.html, text: msg.text });
        if (!sent.ok && !sent.skipped) {
          console.error(`[request-reset] email send failed for a user: ${sent.error}`);
        }
      } else if (error && !/user not found|not found|no user/i.test(error.message)) {
        // A genuine server error (not "user doesn't exist") is worth logging.
        console.error(`[request-reset] generateLink error: ${error.message}`);
      }
    } catch (e) {
      console.error("[request-reset] threw:", e instanceof Error ? e.message : String(e));
    }
  } else {
    console.info("[request-reset] admin client not configured — reset email skipped");
  }

  return NextResponse.json({ ok: true });
}
