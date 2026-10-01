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

const RESEND_BATCH_ENDPOINT = "https://api.resend.com/emails/batch";
/** Resend accepts at most 100 messages per batch call. */
export const EMAIL_BATCH_MAX = 100;

/** True when a provider key is present (sends would actually go out). */
export function isEmailConfigured(): boolean {
  return Boolean(process.env.RESEND_API_KEY);
}

export interface BatchResult {
  /** No provider key — nothing was attempted (same posture as sendEmail). */
  skipped: boolean;
  /** Per input (same order): accepted by the provider. */
  sent: boolean[];
  /** One entry per failed API call. */
  errors: string[];
}

/**
 * Send many transactional emails with as few API calls as possible: Resend's
 * batch endpoint, ≤ 100 messages per call, each message addressed to exactly
 * the `to` given (callers send one message per recipient). Same key / From
 * conventions and the same skip-when-unconfigured behaviour as sendEmail().
 *
 * A failed call marks only ITS messages unsent and the next chunk is still
 * tried; calls are spaced ~0.6 s apart to respect the provider's default
 * 2 requests/second. Never throws.
 */
export async function sendEmailBatch(inputs: readonly EmailInput[], opts: { pauseMs?: number } = {}): Promise<BatchResult> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM?.trim() || DEFAULT_FROM;
  const sent = inputs.map(() => false);
  if (inputs.length === 0) return { skipped: false, sent, errors: [] };
  if (!key) {
    console.info(`[email] RESEND_API_KEY not set — skipping a batch of ${inputs.length} email(s)`);
    return { skipped: true, sent, errors: [] };
  }
  const errors: string[] = [];
  const pause = opts.pauseMs ?? 600;
  for (let start = 0; start < inputs.length; start += EMAIL_BATCH_MAX) {
    if (start > 0 && pause > 0) await new Promise(r => setTimeout(r, pause));
    const part = inputs.slice(start, start + EMAIL_BATCH_MAX);
    try {
      const res = await fetch(RESEND_BATCH_ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
        body: JSON.stringify(part.map(i => ({
          from, to: Array.isArray(i.to) ? i.to : [i.to], subject: i.subject, html: i.html, text: i.text,
        }))),
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        console.error(`[email] batch send failed (${res.status}): ${redactEmails(body).slice(0, 500)}`);
        errors.push(`HTTP ${res.status}`);
        continue;
      }
      for (let i = 0; i < part.length; i++) sent[start + i] = true;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[email] batch send threw:", msg);
      errors.push(msg);
    }
  }
  return { skipped: false, sent, errors };
}

/**
 * Server logs must not collect recipients' addresses (SEC-18): mask any email in
 * text we log (a provider error body can echo the recipient) — "j***@college.ac.il".
 */
export function redactEmails(text: string): string {
  return text.replace(/([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g, "$1***@$2");
}

export async function sendEmail(input: EmailInput): Promise<{ ok: boolean; skipped?: boolean; error?: string }> {
  const key = process.env.RESEND_API_KEY;
  const from = process.env.EMAIL_FROM?.trim() || DEFAULT_FROM;
  const to = Array.isArray(input.to) ? input.to : [input.to];

  if (!key) {
    console.info(`[email] RESEND_API_KEY not set — skipping "${input.subject}" → ${to.length} recipient(s)`);
    return { ok: false, skipped: true };
  }

  // QA phase 7, E-18: a hung provider call used to hold the request until the
  // function's own limit. Each attempt now has a 10 s budget, and a 429 / 5xx /
  // network failure gets ONE retry. The idempotency key makes that retry safe
  // even if the first attempt was delivered but its answer was lost.
  const idempotencyKey = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
  const body = JSON.stringify({ from, to, subject: input.subject, html: input.html, text: input.text });
  let last: { ok: boolean; error?: string } = { ok: false, error: "not sent" };
  for (let attempt = 0; attempt < 2; attempt++) {
    let retryable = false;
    let waitMs = 1000;
    try {
      const res = await fetch(RESEND_ENDPOINT, {
        method: "POST",
        headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", "Idempotency-Key": idempotencyKey },
        body,
        signal: AbortSignal.timeout(SEND_TIMEOUT_MS),
      });
      if (res.ok) return { ok: true };
      const text = await res.text().catch(() => "");
      console.error(`[email] send failed (${res.status}, attempt ${attempt + 1}): ${redactEmails(text).slice(0, 500)}`);
      last = { ok: false, error: `HTTP ${res.status}` };
      retryable = res.status === 429 || res.status >= 500;
      const ra = Number(res.headers.get("retry-after"));
      if (Number.isFinite(ra) && ra > 0) waitMs = Math.min(3000, ra * 1000);
    } catch (e) {
      const msg = e instanceof Error ? (e.name === "TimeoutError" ? `timed out after ${SEND_TIMEOUT_MS} ms` : e.message) : String(e);
      console.error(`[email] send threw (attempt ${attempt + 1}):`, msg);
      last = { ok: false, error: msg };
      retryable = true;
    }
    if (!retryable || attempt === 1) break;
    await new Promise(r => setTimeout(r, waitMs));
  }
  return last;
}

const SEND_TIMEOUT_MS = 10_000;
