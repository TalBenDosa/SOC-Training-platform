import "server-only";
/**
 * Minimal transactional-email sender. Provider: Resend (simple REST, no SDK).
 *
 * GRACEFUL DEGRADATION, matching the rest of the platform (audit → stderr,
 * rate-limit → memory): when RESEND_API_KEY is not configured, sends are SKIPPED
 * and logged rather than throwing, so a deployment without email still works —
 * the invite links are always shown in the console regardless. Email is a
 * convenience layer on top, never a hard dependency.
 *
 * Env:
 *   RESEND_API_KEY  — enables real sending.
 *   EMAIL_FROM      — the From address, e.g. "HACK THE SOC <noreply@your-domain>".
 *                     Optional override. Defaults to noreply@hackthesoc.app — the
 *                     project's own VERIFIED Resend domain, which can deliver to
 *                     any recipient. (The old fallback, onboarding@resend.dev, is
 *                     Resend's shared sender and only delivers to the account
 *                     owner — so a missing/typo'd EMAIL_FROM used to silently 403
 *                     every real invite. Defaulting to the verified domain removes
 *                     that footgun; email works out of the box, env just overrides.)
 */
const DEFAULT_FROM = "HACK THE SOC <noreply@hackthesoc.app>";
const RESEND_ENDPOINT = "https://api.resend.com/emails";

export interface EmailInput {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(input: EmailInput): Promise<{ ok: boolean; skipped?: boolean; error?: string }> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM?.trim() || DEFAULT_FROM;
  const to = Array.isArray(input.to) ? input.to : [input.to];

  if (!key) {
    console.info(`[email] RESEND_API_KEY not set — skipping "${input.subject}" → ${to.join(", ")}`);
    return { ok: false, skipped: true };
  }

  try {
    const res = await fetch(RESEND_ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from, to, subject: input.subject, html: input.html, text: input.text }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      console.error(`[email] send failed (${res.status}): ${body}`);
      return { ok: false, error: `HTTP ${res.status}` };
    }
    return { ok: true };
  } catch (e) {
    console.error("[email] send threw:", e instanceof Error ? e.message : String(e));
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
