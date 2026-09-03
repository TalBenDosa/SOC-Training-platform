"use client";
import { useEffect } from "react";

/**
 * Salvages password-recovery links that land on the wrong page.
 *
 * Supabase only honours a reset email's `redirectTo` (/update-password) when
 * that URL is on the project's Redirect-URLs allowlist AND the Site URL is
 * current. When either is stale, Supabase silently discards the requested
 * redirect and falls back to the **Site URL root** — dumping the student on the
 * landing page with the recovery token still in the URL, where the only visible
 * action is "create account" (which then says "email already exists"). That is
 * exactly the dead-end a real student hit.
 *
 * This catcher runs only on "/", detects a recovery/auth token in the query or
 * hash, and forwards it to /update-password so the reset completes regardless of
 * the dashboard config. It renders nothing and ships as the page's only client
 * JS. The proper fix is still to correct the Supabase Site URL + allowlist; this
 * is defence-in-depth so a config slip never strands a user again.
 */
export function RecoveryRedirect() {
  useEffect(() => {
    if (typeof window === "undefined") return;
    const { pathname, search, hash } = window.location;
    if (pathname !== "/") return;

    const query = new URLSearchParams(search);
    const frag = new URLSearchParams(hash.startsWith("#") ? hash.slice(1) : hash);

    // PKCE fallback carries `?code=`; the implicit/hash fallback carries
    // `#type=recovery` (with an access_token). An auth error on a recovery link
    // (expired/already-used) is forwarded too, so the user reaches the
    // "request a new link" screen instead of the signup CTA.
    const looksLikeRecovery =
      query.has("code") ||
      query.has("token_hash") ||
      query.get("type") === "recovery" ||
      frag.get("type") === "recovery" ||
      (frag.has("access_token") && frag.get("type") === "recovery") ||
      query.get("error_code") === "otp_expired" ||
      (query.has("error") && (search + hash).includes("recovery"));

    if (!looksLikeRecovery) return;
    // Preserve BOTH query and hash — the Supabase client on /update-password
    // reads whichever half the flow used.
    window.location.replace(`/update-password${search}${hash}`);
  }, []);

  return null;
}
