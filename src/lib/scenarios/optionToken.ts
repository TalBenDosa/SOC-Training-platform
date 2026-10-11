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

// ─── Opaque event ids ─────────────────────────────────────────────────────────
//
// Authored event ids name the answer ("evt_mhi_ws3_beacon", "s3exfil_07_getobject_burst",
// "evt_phish_dns_c2") and the page shows them in every row's Raw JSON. The page
// and the grade response swap each id for a keyed, stable token everywhere the
// learner can read it — events, question text, explanations, debrief — so a
// question that says "Look at ev-3f9a…" still points at the right row.

/** Original event id → opaque, stable id for this scenario. */
export function eventIdMap(slug: string, ids: readonly string[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const id of ids) {
    if (!id || m.has(id)) continue;
    m.set(id, "ev-" + createHmac("sha256", secret()).update(`${slug}\u0002${id}`).digest("hex").slice(0, 10));
  }
  // Question text often cites an event by its short form ("evt_ce_03" for
  // "evt_ce_03_nsenter"). Every "_"-prefix of an id that ends in a numbered
  // segment and belongs to exactly ONE event becomes an alias of that event.
  const owners = new Map<string, Set<string>>();
  for (const id of m.keys()) {
    const parts = id.split("_");
    for (let k = 2; k < parts.length; k++) {
      if (!/\d/.test(parts[k - 1])) continue;
      const alias = parts.slice(0, k).join("_");
      if (!owners.has(alias)) owners.set(alias, new Set());
      owners.get(alias)!.add(id);
    }
  }
  for (const [alias, set] of owners) {
    if (set.size === 1 && !m.has(alias)) m.set(alias, m.get([...set][0])!);
  }
  return m;
}

/** Replace every original id (as a whole token) in any JSON-serialisable value. */
export function maskEventIds<T>(value: T, map: Map<string, string>): T {
  if (map.size === 0) return value;
  const ids = [...map.keys()].sort((a, b) => b.length - a.length).map(id => id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`(?<![A-Za-z0-9_-])(?:${ids.join("|")})(?![A-Za-z0-9_-])`, "g");
  return JSON.parse(JSON.stringify(value).replace(re, id => map.get(id) ?? id)) as T;
}
