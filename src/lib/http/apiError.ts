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

/** A thrown value → a message for the learner: ours as-is; a fetch rejection → the network line. */
export function userMessageFor(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  return NETWORK_ERROR;
}
