/**
 * How an email send went, in the terms the super-admin console explains:
 *   sent            → delivered to the provider;
 *   not_configured  → RESEND_API_KEY unset, nothing was sent;
 *   rejected        → the provider refused this recipient (e.g. unverified sender domain).
 */
export type EmailStatus = "sent" | "not_configured" | "rejected";

export function emailStatusOf(r: { ok: boolean; skipped?: boolean }): EmailStatus {
  return r.ok ? "sent" : r.skipped ? "not_configured" : "rejected";
}
