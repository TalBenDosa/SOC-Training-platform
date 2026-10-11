/**
 * Classifying AI-provider SDK errors by their HTTP status (QA phase 7, E-18).
 * The routes used to substring-match the message — `msg.includes("rate")` is
 * true for "generate", "accurate", "moderate"… so unrelated failures were
 * retried with 8–46 s sleeps, and a raw provider message reached the screen.
 * Both the OpenAI and Anthropic SDKs put the HTTP status on `err.status`.
 */
export function aiErrorStatus(err: unknown): number | null {
  const s = (err as { status?: unknown } | null)?.status;
  return typeof s === "number" ? s : null;
}

/** A 429 worth waiting out — not an exhausted quota, which no retry fixes. */
export function isRateLimitError(err: unknown): boolean {
  if (aiErrorStatus(err) !== 429) return false;
  const code = (err as { code?: unknown; error?: { code?: unknown; type?: unknown } }) ?? {};
  const tag = String(code.code ?? code.error?.code ?? code.error?.type ?? "");
  return !/insufficient_quota|billing/.test(tag);
}

/** The line an admin sees when generation fails — never the provider's raw text. */
export function aiFailureMessage(err: unknown, what = "Generation"): string {
  const s = aiErrorStatus(err);
  const name = (err as { name?: unknown } | null)?.name;
  if (s === 401 || s === 403) return "AI generation is temporarily unavailable. Please try again later.";
  if (s === 429) return isRateLimitError(err)
    ? "The AI provider is busy right now — please try again in a minute."
    : "The AI provider's usage limit has been reached — ask the platform owner to check the billing.";
  if (name === "APIConnectionTimeoutError" || name === "TimeoutError" || name === "AiBudgetError") return `${what} took too long — please try again (fewer sections helps).`;
  if (s !== null && s >= 500) return "The AI provider had an error — please try again.";
  return `${what} failed — please try again.`;
}

export class AiBudgetError extends Error {
  constructor() { super("AI time budget exceeded"); this.name = "AiBudgetError"; }
}
