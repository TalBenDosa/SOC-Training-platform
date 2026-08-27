import "server-only";
/**
 * The SINGLE validated auth read per request.
 *
 * `supabase.auth.getUser()` is a NETWORK round-trip to the Supabase auth server
 * — it validates the JWT rather than trusting the cookie, which is why the whole
 * codebase uses it over getSession(). The cost of that guarantee is one auth
 * round-trip per call. Before this module, every consumer on the entry path made
 * that call independently: the (app) layout's affiliation gate, then
 * getAuthedUser() in the page, each hitting the auth server afresh on the SAME
 * request — 2–3 serial round-trips per signed-in navigation, none shared.
 *
 * Wrapping the read in React `cache()` memoises it for the lifetime of a single
 * server render / request, so every consumer in that render shares ONE
 * getUser(). getSession() decodes the JWT from the cookie LOCALLY (no network),
 * so it is included here to hand callers the org claim without a second hop, and
 * the client is returned so a caller can run its own follow-up query (profiles,
 * org_members) on the same authenticated client.
 *
 * Security is unchanged — still getUser() (server-validated), just not repeated.
 * Returns null when not signed in or Supabase isn't configured.
 */
import { cache } from "react";
import { getSupabaseServerClient } from "@/lib/supabase/server";

export const getValidatedAuth = cache(async () => {
  const supabase = await getSupabaseServerClient();
  if (!supabase) return null;

  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return null;

  // Local decode of the cookie's JWT — no network round-trip (see file doc).
  const { data: { session } } = await supabase.auth.getSession();
  return { supabase, user, session };
});
