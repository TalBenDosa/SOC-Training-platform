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
 * Server rejection codes from apply_session_action (contract 2 of the 2026-09-27 fix
 * round). The RPC raises `<code>` or `<code>: <detail>`; callers that can RECOVER
 * from one (claim_held / case_owned → offer an explicit take-over) branch on the
 * code, everyone else just shows the friendly text.
 */
export const ACTION_ERROR_CODES = [
  "claim_held", "case_owned", "already_escalated", "unknown_event", "not_escalated",
  "invalid_payload", "ticket_answered", "no_pending_request", "not_approved",
  "rate_limited", "action_not_allowed", "not_a_member", "session_full", "payload_too_large",
  "seq_conflict", "auth_required",
] as const;
export type ActionErrorCode = (typeof ACTION_ERROR_CODES)[number];
/** The recognised rejection code inside a raw error message, or null. */
export function actionErrorCode(raw: string): ActionErrorCode | null {
  const m = (raw ?? "").toLowerCase();
  for (const c of ACTION_ERROR_CODES) if (m.includes(c)) return c;
  if (m.includes("jwt")) return "auth_required";
  return null;
}
/** What an action call resolved to — `code` is set when the server rejected it. */
export interface ActOutcome { ok: boolean; code: ActionErrorCode | null; message?: string }
/** The outcome-returning action helper; `handled` codes are left to the caller (no banner). */
export type ActR = (type: string, payload: Record<string, unknown>, opts?: { handled?: ActionErrorCode[] }) => Promise<ActOutcome>;

/**
 * Map a raw database error from apply_session_action to plain language (audit C6 —
 * the room used to show text like "action_not_allowed: disposition.set for role
 * t2 in status paused" in a banner that never cleared).
 */
export function friendlyActionError(raw: string): string {
  const m = (raw ?? "").toLowerCase();
  switch (actionErrorCode(raw)) {
    case "rate_limited": return "Slow down — too many actions in a few seconds. Try again in a moment.";
    case "action_not_allowed": return m.includes("paused")
      ? "The shift is paused — actions resume when it does."
      : "That action isn't available to your role right now.";
    case "not_a_member": return "You're no longer on this session's roster.";
    case "session_full": return "This session has reached its activity limit.";
    case "payload_too_large": return "That's too much text or data for one action — shorten it and try again.";
    case "seq_conflict": return "Someone acted at the same moment — please try again.";
    case "auth_required": return "Your sign-in expired — reload the page to continue.";
    // ── ownership (P0-3) — recoverable with an explicit take-over ──
    case "claim_held": return "A teammate is already working this alert. Pick another one — or use “Take over” if they've stalled and you've agreed to take it.";
    case "case_owned": return "Another analyst already took this case. Leave it with them — or use “Take over (backup)” if they asked for help or went quiet.";
    // ── validation (P0-2) ──
    case "already_escalated": return "This log is already escalated and still open — add to that case (note / evidence) instead of escalating it again.";
    case "unknown_event": return "That log isn't in this shift's feed — re-select it from the feed and try again.";
    case "not_escalated": return "Nobody has escalated that log yet — it needs an open escalation first (Tier-1 escalates, then Tier-2 takes the case).";
    case "invalid_payload": {
      // The server's detail is already plain English ("the escalation needs a summary",
      // "a request for WS-FIN-2847 is already pending") — surface it.
      const what = raw.split(/invalid_payload:?/i)[1]?.trim().replace(/\s+/g, " ");
      return what ? `Can't send that yet — ${what.slice(0, 120)}.` : "Something required is missing or invalid — fill it in and try again.";
    }
    case "ticket_answered": return "That help-desk ticket was already answered by a teammate.";
    case "no_pending_request": return "There's no open containment request to decide on — it was already approved or denied.";
    case "not_approved": return "This containment hasn't been approved yet — the SOC Manager must approve it before you execute.";
    default: return "Couldn't complete that action. Check your connection and try again.";
  }
}
