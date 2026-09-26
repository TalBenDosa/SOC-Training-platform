// ── Shared feed ──────────────────────────────────────────────────────────────
export function sevColor(s?: string) { return s === "critical" || s === "high" ? "bg-severity-high" : s === "medium" ? "bg-neon-amber" : "bg-slate-500"; }
/** Some vendor events carry `description`/`raw` as an OBJECT, not a string — React
 *  can't render an object child, so coerce everything we render to a safe string. */
export function asStr(v: unknown): string { return typeof v === "string" ? v : ""; }
/** Auto-detect an IOC's type for display + accuracy scoring (T1-5). */
export function detectIocType(v: string): string {
  const s = v.trim();
  if (/^[a-f0-9]{64}$/i.test(s)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(s)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(s)) return "md5";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (/@/.test(s)) return "email";
  if (/\.[a-z]{2,}$/i.test(s) && !/\s/.test(s)) return "domain";
  return "host";
}
// A4: a MANUAL IOC must be a real indicator shape — a strong type (hash/ip/email/domain)
// or a plausible hostname (has a hyphen/dot/digit, no spaces) — so junk free text like
// "asdf" can't satisfy the ≥1-indicator escalation gate. Picked-from-log IOCs are trusted.
export function isValidIoc(v: string): boolean {
  const s = v.trim();
  if (!s || /\s/.test(s)) return false;
  if (detectIocType(s) !== "host") return true;       // hash / ip / email / domain
  return /^[A-Za-z0-9][A-Za-z0-9._-]{2,62}$/.test(s) && /[-.\d]/.test(s); // plausible hostname
}
export const wordCount = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

/** Short stable hash (FNV-1a) — used to derive idempotency keys from an action payload. */
export function hashString(s: string): string {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return (h >>> 0).toString(36);
}

/**
 * Map a raw database error from apply_session_action to plain language (audit C6 —
 * the room used to show text like "action_not_allowed: disposition.set for role
 * t2 in status paused" in a banner that never cleared).
 */
export function friendlyActionError(raw: string): string {
  const m = raw.toLowerCase();
  if (m.includes("rate_limited")) return "Slow down — too many actions in a few seconds. Try again in a moment.";
  if (m.includes("action_not_allowed")) return m.includes("paused")
    ? "The shift is paused — actions resume when it does."
    : "That action isn't available to your role right now.";
  if (m.includes("not_a_member")) return "You're no longer on this session's roster.";
  if (m.includes("session_full")) return "This session has reached its activity limit.";
  if (m.includes("payload_too_large")) return "That's too much text or data for one action — shorten it and try again.";
  if (m.includes("seq_conflict")) return "Someone acted at the same moment — please try again.";
  if (m.includes("auth_required") || m.includes("jwt")) return "Your sign-in expired — reload the page to continue.";
  return "Couldn't complete that action. Check your connection and try again.";
}
