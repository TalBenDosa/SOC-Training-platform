/**
 * Disposable / anonymous-alias email domains (pure, isomorphic, no network).
 *
 * Two uses, same list:
 *   - an INSTANT client-side check in signup (a Set lookup — no latency, no UX cost),
 *     so a throwaway address gets a clear message instead of a generic DB error;
 *   - mirrored in the DB trigger (migration 0091) as the non-bypassable backstop.
 *
 * This is NOT about typos (a typo like tSl@ vs tal@ is a valid, deliverable address —
 * only email CONFIRMATION catches that). It is about addresses a course can't rely on
 * reaching: temporary mailboxes and anonymous forwarders.
 *
 * Keep the SQL copy in 0091 in sync with this list.
 */
export function normalizeEmail(raw: unknown): string {
  return String(raw ?? "").trim().toLowerCase();
}
export function emailDomain(email: string): string {
  const at = email.lastIndexOf("@");
  return at >= 0 ? email.slice(at + 1).trim() : "";
}

export const DISPOSABLE_DOMAINS: ReadonlySet<string> = new Set([
  // classic throwaway / 10-minute mail
  "mailinator.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com",
  "10minutemail.com", "10minutemail.net", "temp-mail.org", "tempmail.com", "tempmailo.com",
  "tempmail.net", "tmpmail.org", "throwawaymail.com", "getnada.com", "nada.email",
  "dispostable.com", "trashmail.com", "trashmail.de", "maildrop.cc", "mohmal.com",
  "yopmail.com", "yopmail.net", "fakeinbox.com", "mailnesia.com", "mintemail.com",
  "spamgourmet.com", "mailcatch.com", "emailondeck.com", "moakt.com", "tempr.email",
  "mailtemp.net", "burnermail.io", "33mail.com", "spam4.me", "grr.la", "inboxbear.com",
  "tempinbox.com", "mail-temp.com", "disposablemail.com", "harakirimail.com",
  // anonymous forwarding / alias services (reachability + accountability risk)
  "passinbox.com", "passmail.com", "passmail.net",            // Proton Pass aliases
  "simplelogin.com", "simplelogin.io", "slmail.me", "aleeas.com",
  "anonaddy.com", "anonaddy.me", "addy.io",
  "duck.com",                                                  // DuckDuckGo Email Protection
  "relay.firefox.com", "mozmail.com",                         // Firefox Relay
  // NOTE: Apple "Hide My Email" (@icloud.com / @privaterelay.appleid.com) is NOT blocked —
  // that would block every real iCloud user. Add only if the client explicitly requires it.
]);

/** A reason the address is a disposable/alias mailbox, or null when it's acceptable. */
export function disposableIssue(email: string): string | null {
  const domain = emailDomain(normalizeEmail(email));
  if (domain && DISPOSABLE_DOMAINS.has(domain)) {
    return "Please use a permanent email address — temporary and anonymous-forwarding addresses aren't accepted, so your course can always reach you.";
  }
  return null;
}
