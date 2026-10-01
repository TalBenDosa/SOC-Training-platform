/**
 * Did the AUTH SERVICE fail (as opposed to "there is no valid session")?
 * supabase.auth.getUser() does not throw on a Supabase Auth 5xx or a network
 * failure — it returns { user: null, error: AuthRetryableFetchError } — and that
 * was treated as "signed out": an auth incident looked like a mass logout (401 on
 * every API call, every page bounced to /login with no explanation). QA phase 7, E-05.
 */
export function isAuthOutage(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const e = error as { name?: unknown; status?: unknown };
  if (e.name === "AuthRetryableFetchError") return true;
  const status = typeof e.status === "number" ? e.status : 0;
  return status >= 500;
}
