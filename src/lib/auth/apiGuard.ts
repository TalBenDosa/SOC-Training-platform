import "server-only";
/**
 * API route auth guards. The single place server-side route handlers decide who
 * may call them. Two postures, both FAIL CLOSED:
 *
 *  - `requireAdmin()` — hard gate for staff-only tooling (content generation,
 *    validation, admin endpoints). 401 if not signed in, 403 if signed in but
 *    not `role='admin'`. When Supabase isn't configured the client is null and
 *    this returns 401 — i.e. a deployment with no auth backend cannot reach
 *    admin tooling at all, which is the safe default.
 *
 *  - `getAuthedUser()` — soft check for student-facing LLM routes. Those routes
 *    already have a zero-cost heuristic/stub fallback, so instead of rejecting
 *    guests we gate only the PAID LLM path behind a signed-in user: a guest gets
 *    the same fallback as a no-API-key deployment (works, costs nothing), a
 *    signed-in user gets the real AI. This closes the anonymous-spend hole
 *    without breaking the guest experience.
 *
 * `supabase.auth.getUser()` (not `getSession()`) is used deliberately — it
 * validates the JWT with the Supabase auth server rather than trusting the
 * cookie, so a forged/expired cookie can't impersonate a user or an admin.
 */
import { NextResponse } from "next/server";
import { getSupabaseServerClient } from "@/lib/supabase/server";

export interface AuthedUser {
  id: string;
  email: string | null;
  role: string;
}

/** The signed-in user (with role from `profiles`), or null if not signed in / Supabase not configured. */
export async function getAuthedUser(): Promise<AuthedUser | null> {
  const supabase = await getSupabaseServerClient();
  if (!supabase) return null;

  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return null;

  const { data: profile } = await supabase
    .from("profiles")
    .select("role")
    .eq("id", user.id)
    .maybeSingle();

  return { id: user.id, email: user.email ?? null, role: profile?.role ?? "analyst" };
}

type Gate = { user: AuthedUser } | { error: NextResponse };

/** Hard gate: caller must be a signed-in admin. Use for staff-only / content-authoring routes. */
export async function requireAdmin(): Promise<Gate> {
  const user = await getAuthedUser();
  if (!user) {
    return { error: NextResponse.json({ error: "Authentication required." }, { status: 401 }) };
  }
  if (user.role !== "admin") {
    return { error: NextResponse.json({ error: "Admin access required." }, { status: 403 }) };
  }
  return { user };
}
