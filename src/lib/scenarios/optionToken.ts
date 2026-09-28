import "server-only";
import { createHmac } from "node:crypto";

/**
 * Opaque option values for scenario questions (review of finding #4).
 *
 * The scenario page ships its questions to the browser; authored option values
 * are descriptive ids ("wrong_folder", "benign_is_bad", "missed") that give the
 * answer away in the page payload even when the DOM shows random tokens. The
 * server page swaps every value for a keyed HMAC token, and the grade route maps
 * tokens back before grading. Deterministic (same slug/question/value → same
 * token), so no state is kept between the render and the grade call.
 */
const secret = () =>
  process.env.SCENARIO_OPTION_SECRET ?? process.env.SUPABASE_SERVICE_ROLE_KEY ?? "hackthesoc-dev-option-secret";

export function optionToken(slug: string, questionId: string, value: string): string {
  return "o" + createHmac("sha256", secret()).update(`${slug}\u0001${questionId}\u0001${value}`).digest("hex").slice(0, 16);
}

type Q = { id: string; options?: { value: string }[] };

/** Map a submitted answer (token, or a raw value from an older client) back to authored values. */
export function decodeAnswer(slug: string, q: Q, submitted: string | string[] | undefined): string | string[] | undefined {
  if (submitted === undefined) return undefined;
  const byToken = new Map((q.options ?? []).map(o => [optionToken(slug, q.id, o.value), o.value]));
  const one = (v: unknown) => (typeof v === "string" ? byToken.get(v) ?? v : v);
  return Array.isArray(submitted) ? (submitted.map(one) as string[]) : (one(submitted) as string);
}
