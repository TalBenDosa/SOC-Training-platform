import { NETWORK_ERROR } from "./safeFetch";

/**
 * One message a learner can act on, for a failed API call (QA phase 7, E-09).
 *
 * Student flows told every failure "check your connection" — including an
 * expired session (401), a lapsed college licence (403), "slow down" (429) and a
 * server-side save failure (503) that already came with a precise message. Map the
 * status first; keep the server's own message where it is written for people.
 */
export function apiErrorMessage(status: number, body?: unknown, retryAfterSec?: number | null): string {
  const serverMsg = typeof (body as { error?: unknown } | null)?.error === "string" ? (body as { error: string }).error : "";
  if (status === 401) return "Your session expired — sign in again (your work on this page is still here).";
  if (status === 403) return serverMsg || "You don't have access to this right now.";
  if (status === 429) {
    const wait = retryAfterSec && retryAfterSec > 0 ? ` in ${Math.ceil(retryAfterSec)} s` : " in a moment";
    return `Too many requests in a short time — try again${wait}.`;
  }
  if (status === 404) return serverMsg || "That item no longer exists.";
  if (status >= 500) return serverMsg && !/^\s*(TypeError|SyntaxError|Error:)/.test(serverMsg) ? serverMsg : "Something went wrong on our side — please try again.";
  return serverMsg || "That didn't work — please try again.";
}

/** Reads a failed Response into a learner-facing message (never throws). */
export async function messageFromResponse(res: Response): Promise<string> {
  const body = await res.json().catch(() => null);
  const ra = Number(res.headers.get("retry-after"));
  return apiErrorMessage(res.status, body, Number.isFinite(ra) ? ra : null);
}

/** An Error whose message is already safe to show a learner. */
export class ApiError extends Error {
  constructor(message: string, public status: number | null) { super(message); this.name = "ApiError"; }
}

/**
 * A thrown value → a message for the learner: ours as-is; a fetch rejection
 * (TypeError — offline, DNS, dropped connection) → the network line; anything
 * else (a bad response shape, a bug) → a plain "try again", never raw text.
 */
export function userMessageFor(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof TypeError) return NETWORK_ERROR;
  return "Something went wrong — please try again.";
}

/**
 * A caught error → text for the screen (QA phase 7, E-07). Our own thrown messages
 * (usually the server's {error}) pass through; a fetch rejection becomes the
 * network line and a non-JSON body (an HTML 500/504 page) a plain retry line —
 * never "Failed to fetch" or "Unexpected token '<'…".
 */
export function displayError(e: unknown, fallback: string): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof TypeError) return NETWORK_ERROR;
  if (e instanceof SyntaxError) return "The server sent an unexpected response — please try again.";
  if (e instanceof Error && e.message) return e.message;
  return fallback;
}

/**
 * A Supabase Auth error → plain text (QA phase 7, E-07). GoTrue's own strings
 * ("Failed to fetch", "Auth session missing!", "Request rate limit reached")
 * were shown as-is on the sign-in, sign-up and new-password screens.
 */
export function authErrorMessage(err: { message?: string; status?: number; name?: string; code?: string } | null | undefined): string {
  if (!err) return "Something went wrong — please try again.";
  const m = (err.message ?? "").toLowerCase();
  if (err.name === "AuthRetryableFetchError" || m.includes("failed to fetch") || m.includes("network")) return NETWORK_ERROR;
  if (err.status === 429 || m.includes("rate limit")) return "Too many attempts — wait a minute and try again.";
  if (m.includes("invalid login credentials")) return "Incorrect email or password.";
  if (m.includes("email not confirmed")) return "Confirm your email address first — check your inbox for the link.";
  if (m.includes("session missing") || m.includes("expired") || err.status === 401 || err.status === 403) return "This link or session has expired — request a new password-reset email.";
  if (m.includes("should be different") || err.code === "same_password") return "The new password must be different from your current one.";
  if (m.includes("password") && (m.includes("weak") || m.includes("at least") || m.includes("characters"))) return err.message!;   // a policy hint, written for people
  if (m.includes("already registered") || m.includes("already exists")) return "This email already has an account. Sign in instead.";
  return "Something went wrong — please try again.";
}
