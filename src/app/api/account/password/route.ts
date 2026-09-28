import { NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { getAuthedUser } from "@/lib/auth/apiGuard";
import { getSupabaseServerClient } from "@/lib/supabase/server";
import { supabaseUrl, supabaseAnonKey, isSupabaseConfigured } from "@/lib/supabase/config";
import { logAudit } from "@/lib/audit/logAudit";
import { checkRateLimit } from "@/lib/security/rateLimit";
import { validatePasswordChange } from "@/app/(app)/account/accountValidation";

/**
 * POST — change the signed-in user's password (FB-011).
 *
 * Body: { current_password, new_password, confirm_password }
 *
 * WHY RE-AUTHENTICATE. A live session alone is not enough to change a password:
 * a hijacked session (stolen cookie, unlocked lab machine) would otherwise let
 * an attacker lock the real owner out. So the CURRENT password is verified first
 * with a fresh `signInWithPassword` for the session user's own email.
 *
 * HOW. The verification runs on a throwaway, non-persisting anon client — it
 * never touches the caller's cookies — and that throwaway session is revoked
 * right after (scope "local" = only that session). The password is then changed
 * through the caller's OWN cookie-bound session. That matters: Supabase Auth
 * revokes every session except the one making the change, so updating through
 * the throwaway client would silently sign the learner out of this browser too
 * (independent review of FB-011). Done this way, other devices are signed out
 * (a good thing after a password change) and this browser stays signed in.
 *
 * No service-role key is involved: the user can only ever change their OWN
 * password, because the email comes from the validated session, not the body.
 */
export async function POST(req: Request) {
  const user = await getAuthedUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  if (!user.email) {
    return NextResponse.json({ error: "This account has no email login, so it has no password to change." }, { status: 400 });
  }
  if (!isSupabaseConfigured) return NextResponse.json({ error: "Server not configured." }, { status: 503 });

  let body: Record<string, unknown> = {};
  try { body = await req.json(); } catch { /* validated below */ }
  if (!body || typeof body !== "object" || Array.isArray(body)) body = {};

  const v = validatePasswordChange({
    current: body.current_password,
    next: body.new_password,
    confirm: body.confirm_password,
  });
  if (!v.ok) return NextResponse.json({ error: v.error }, { status: 400 });

  // Per-user cap on verification attempts. The session holder already "is" the
  // user, but without this the route would be a current-password guessing
  // oracle whose attempts all come from the server's IP (sidestepping
  // Supabase's per-IP auth limits).
  const rl = await checkRateLimit(`pw-change:${user.id}`, 5, 15 * 60 * 1000);
  if (!rl.ok) {
    return NextResponse.json(
      { error: "Too many attempts. Wait a few minutes and try again, or use \"Forgot your password?\"." },
      { status: 429, headers: { "Retry-After": String(rl.retryAfter) } },
    );
  }

  const verifier = createClient(supabaseUrl!, supabaseAnonKey!, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });

  const { data: signIn, error: signInErr } = await verifier.auth.signInWithPassword({
    email: user.email,
    password: v.value.current,
  });
  if (signInErr || !signIn.user || signIn.user.id !== user.id) {
    await logAudit({
      actorId: user.id,
      action: "account.password_change_denied",
      targetTable: "auth.users",
      targetId: user.id,
      metadata: { reason: signInErr?.status === 429 ? "auth_rate_limited" : "bad_current_password" },
    });
    if (signInErr?.status === 429) {
      return NextResponse.json({ error: "Too many sign-in attempts. Please wait a few minutes and try again." }, { status: 429 });
    }
    return NextResponse.json({ error: "Your current password is incorrect.", field: "current_password" }, { status: 400 });
  }

  // The current password is proven — drop the throwaway session straight away.
  await verifier.auth.signOut({ scope: "local" }).catch(() => {});

  const own = await getSupabaseServerClient();
  if (!own) return NextResponse.json({ error: "Server not configured." }, { status: 503 });
  const { error: updErr } = await own.auth.updateUser({ password: v.value.next });
  if (updErr) {
    const code = (updErr as { code?: string }).code;
    if (code === "same_password") {
      return NextResponse.json({ error: "The new password must be different from your current one.", field: "new_password" }, { status: 400 });
    }
    if (code === "weak_password") {
      return NextResponse.json({ error: `That password is too weak: ${updErr.message}`, field: "new_password" }, { status: 400 });
    }
    if (code === "reauthentication_needed" || code === "session_not_found") {
      return NextResponse.json({ error: "For security, sign out and sign back in, then change your password." }, { status: 401 });
    }
    return NextResponse.json({ error: "Could not update your password. Please try again." }, { status: 500 });
  }

  await logAudit({
    actorId: user.id,
    action: "account.password_changed",
    targetTable: "auth.users",
    targetId: user.id,
  });

  return NextResponse.json({ ok: true });
}
