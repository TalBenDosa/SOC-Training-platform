/**
 * Options for the Supabase session cookies, shared by every client (browser, server, middleware).
 *
 * @supabase/ssr defaults to path "/", SameSite=Lax, HttpOnly off and NO Secure flag. Secure is added
 * here so the session token can never travel over plain HTTP (HSTS already upgrades this host, this
 * is the belt to its braces). Off outside production so `next dev` on http://localhost keeps working.
 *
 * HttpOnly stays off on purpose: the browser client (auth forms, realtime, the storage backend) reads
 * the session from the cookie. XSS, the one way to read it, is closed by the nonce + strict-dynamic
 * CSP (src/lib/security/csp.ts).
 */
export const SESSION_COOKIE_OPTIONS = {
  path: "/",
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
};
