import "server-only";
import { asObject } from "@/lib/http/body";
import { NextResponse, after } from "next/server";
import { emailOrigin } from "@/lib/http/siteOrigin";
import type { NextRequest } from "next/server";
import { checkRateLimit } from "@/lib/security/rateLimit";
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

// ── Rate limit ──────────────────────────────────────────────────────────────
// Shared store (Upstash when configured — the same one the middleware uses), so
// the budget is per client, not per serverless instance.
const EMAIL_LIMIT = { max: 3, windowMs: 15 * 60_000 };   // 3 / 15 min per email
const IP_LIMIT = { max: 12, windowMs: 60 * 60_000 };     // 12 / hour per IP
/** Reset emails one address can receive per day (SEC-06). */
const RESET_PER_ADDRESS_PER_DAY = 6;
/** Reset emails the whole platform sends per day — protects the provider quota (SEC-06). */
const RESET_EMAIL_DAILY_BUDGET = (() => {
  const n = Number(process.env.RESET_EMAIL_DAILY_BUDGET);
  return Number.isInteger(n) && n > 0 ? n : 300;
})();

// Same trusted-source rule as src/middleware.ts: x-real-ip is set by the
// platform; the LEFT-most x-forwarded-for entry is whatever the client sent, so
// only the right-most hop is used when x-real-ip is absent.
function clientIp(req: NextRequest): string {
  const real = req.headers.get("x-real-ip");
  if (real) return real.trim();
  const xff = req.headers.get("x-forwarded-for");
  if (xff) { const hops = xff.split(","); return hops[hops.length - 1].trim(); }
  return "unknown";
}

export async function POST(req: NextRequest) {
  let email = "";
  try {
    const body = asObject<{ email?: unknown }>(await req.json());
    email = String(body?.email ?? "").trim().toLowerCase();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request." }, { status: 400 });
  }
  if (!EMAIL_RE.test(email)) {
    // Shape error only — reveals nothing about account existence.
    return NextResponse.json({ ok: false, error: "Enter a valid email address." }, { status: 400 });
  }

  const ip = clientIp(req);
  const ipOk = (await checkRateLimit(`reset-ip:${ip}`, IP_LIMIT.max, IP_LIMIT.windowMs)).ok;
  const emailOk = ipOk && (await checkRateLimit(`reset-email:${email}`, EMAIL_LIMIT.max, EMAIL_LIMIT.windowMs)).ok;
  if (!ipOk || !emailOk) {
    return NextResponse.json(
      { ok: false, error: "Too many reset requests. Please wait a few minutes and try again." },
      { status: 429 },
    );
  }

  const admin = getSupabaseAdminClient();
  const origin = emailOrigin(req); // canonical site URL — never the request's Host (P-03)

  // Do the real work but NEVER leak whether the account exists — always 200.
  // It runs AFTER the response is sent (after()): awaiting generateLink + the
  // email send made an existing account measurably slower to answer than an
  // unknown one, which revealed whether an email is registered.
  if (admin) after(async () => {
    try {
      const { data, error } = await admin.auth.admin.generateLink({
        type: "recovery",
        email,
        options: { redirectTo: `${origin}/update-password` },
      });
      const tokenHash = data?.properties?.hashed_token;
      if (!error && tokenHash) {
        const resetLink = `${origin}/update-password?token_hash=${encodeURIComponent(tokenHash)}&type=recovery`;
        // SEC-06: the per-IP / per-address limits still let a distributed attacker
        // mail one victim ~300 resets a day and drain the provider's daily quota (then
        // every invite / reset fails for everyone). Two more ceilings, counted only for
        // emails actually sent, so unknown addresses can't burn them and the response
        // stays the same uniform 200.
        const day = new Date().toISOString().slice(0, 10);
        const perAddress = await checkRateLimit(`reset-day:${email}:${day}`, RESET_PER_ADDRESS_PER_DAY, 86_400_000);
        const platform = perAddress.ok ? await checkRateLimit(`reset-global:${day}`, RESET_EMAIL_DAILY_BUDGET, 86_400_000) : null;
        if (!perAddress.ok || !platform?.ok) {
          console.warn(`[request-reset] daily reset-email ceiling reached (${!perAddress.ok ? "per address" : "global"}) — not sent`);
          return;
        }
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
  });
  else console.info("[request-reset] admin client not configured — reset email skipped");

  return NextResponse.json({ ok: true });
}
