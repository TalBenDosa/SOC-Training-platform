import "server-only";
import { createClient } from "@supabase/supabase-js";
import { supabaseUrl, supabaseAnonKey } from "@/lib/supabase/config";
import { checkRateLimit } from "@/lib/security/rateLimit";

export type PasswordCheck = "ok" | "bad" | "rate_limited" | "unavailable";

/**
 * Prove the signed-in person knows the account's CURRENT password — a fresh
 * signInWithPassword on a throwaway client, for the session user's own email.
 * Used before irreversible / takeover-grade actions (password change, account
 * deletion — SEC-12): a hijacked session alone must not be enough.
 *
 * Per-user cap (shared by every caller): without it the route would be a
 * password-guessing oracle whose attempts all come from the server's IP,
 * sidestepping Supabase's per-IP auth limits.
 */
export async function verifyCurrentPassword(user: { id: string; email: string | null }, password: string): Promise<PasswordCheck> {
  if (!supabaseUrl || !supabaseAnonKey || !user.email) return "unavailable";
  if (!password) return "bad";
  const rl = await checkRateLimit(`pw-change:${user.id}`, 5, 15 * 60 * 1000);
  if (!rl.ok) return "rate_limited";
  const verifier = createClient(supabaseUrl, supabaseAnonKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const { data, error } = await verifier.auth.signInWithPassword({ email: user.email, password });
  if (error?.status === 429) return "rate_limited";
  if (error || !data.user || data.user.id !== user.id) return "bad";
  await verifier.auth.signOut({ scope: "local" }).catch(() => {});
  return "ok";
}
