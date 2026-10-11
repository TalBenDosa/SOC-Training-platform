import type { Ev } from "@/lib/team/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildIocTruth, extractIocs, iocDigest, normalizeIoc, type IocTruth, type IocType } from "@/lib/edr/iocIntel";
import { mergeAnswers, publicAnswers } from "@/lib/team/report/serverReport";

/**
 * Threat-intel truth for a team session's FIRED logs: the public feed rows with the
 * staff-only answers joined back (by inject_id), through the same buildIocTruth the
 * scenario pages use. Server-side only by usage (the answers never leave it; the
 * result is digest-keyed verdicts).
 */
export function buildTeamIocTruth(feedEvents: Ev[], feedInjects: { id: string; channel: string | null; expected_action: unknown }[]): IocTruth {
  const merged = mergeAnswers(feedEvents.filter(e => e.type === "feed.event"), publicAnswers(feedInjects));
  // The team key says "benign" for a story's control / baseline step (a legitimate
  // login before the takeover); buildIocTruth knows that state as is_baseline — without
  // the mapping the step's IOCs inherited the incident's guilt (a clean home IP → malicious).
  return buildIocTruth({ events: merged.map(e => {
    const p = e.payload as unknown as TelemetryEvent;
    return p.expected_verdict === ("benign" as TelemetryEvent["expected_verdict"]) ? { ...p, is_baseline: true } : p;
  }) });
}

// ── QA M4: answer only what is asked, only for logs the asker has in hand ──────
// The endpoint used to return the verdict of EVERY IOC of every fired log in one GET —
// with the digest function in the client bundle that was a whole-feed oracle ("which
// of these values are malicious?"). Now the client names the IOCs it wants (≤ 20 per
// call, budgeted per player in the DB) and gets a verdict only for an IOC that appears
// in a log this player has OPENED (or one the team escalated — Tier-2/3 work those from
// the case, not the raw feed). Everything else falls back to what the log itself says.

export const IOC_QUERY_MAX = 20;
const IOC_TYPES = new Set<IocType>(["ip", "domain", "hash"]);
export interface IocQuery { type: IocType; value: string }

/** The request body's `iocs` → normalised, de-duplicated, capped list (invalid entries dropped). */
export function parseIocQuery(body: unknown): IocQuery[] {
  const raw = (body && typeof body === "object" ? (body as { iocs?: unknown }).iocs : null);
  if (!Array.isArray(raw)) return [];
  const out = new Map<string, IocQuery>();
  for (const x of raw) {
    if (out.size >= IOC_QUERY_MAX) break;
    const type = (x as { type?: unknown } | null)?.type, value = (x as { value?: unknown } | null)?.value;
    if (typeof type !== "string" || !IOC_TYPES.has(type as IocType) || typeof value !== "string") continue;
    const v = value.trim().slice(0, 300);
    if (!v) continue;
    const n = normalizeIoc(type as IocType, v);
    if (n) out.set(`${type}:${n}`, { type: type as IocType, value: n });
  }
  return [...out.values()];
}

/**
 * The truth entries for `query`, restricted to IOCs that occur in `allowedEvents`
 * (the logs the asker may look up). `refused` = asked-for digests not answered.
 */
export function answerIocQuery(truth: IocTruth, query: IocQuery[], allowedEvents: Ev[]): IocTruth & { refused: string[] } {
  const allowed = new Set<string>();
  for (const e of allowedEvents) for (const ioc of extractIocs(e.payload as unknown as TelemetryEvent)) allowed.add(iocDigest(ioc.type, ioc.value));
  const entries: IocTruth["entries"] = {};
  const refused: string[] = [];
  for (const q of query) {
    const d = iocDigest(q.type, q.value);
    if (!allowed.has(d)) { refused.push(d); continue; }
    const t = truth.entries[d];
    if (t) entries[d] = t;
  }
  return { version: 1, entries, refused };
}
