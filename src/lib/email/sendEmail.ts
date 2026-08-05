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
 *                     Falls back to Resend's shared onboarding sender for testing.
 */
const RESEND_ENDPOINT = "https://api.resend.com/emails";

export interface EmailInput {
  to: string | string[];
  subject: string;
  html: string;
  text?: string;
}

export async function sendEmail(input: EmailInput): Promise<{ ok: boolean; skipped?: boolean; error?: string }> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM || "HACK THE SOC <onboarding@resend.dev>";
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
