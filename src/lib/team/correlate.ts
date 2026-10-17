/**
 * Entity correlation on the team feed, as a SIEM groups events by host / user / address.
 *
 * 2026-10-18 review: 55% of the attack logs that reached four Team Training exercises were never
 * opened. The pattern: the low / medium logs of an attack (the email, the browse, the DNS lookup,
 * the follow-up connection) were skipped once the team had found ONE alert of it. Two uses:
 *  - relatedLogs(): the other logs about the same host, user or external address, beside the log
 *    an analyst is reading (Tier-1 "Related activity");
 *  - linkedToHot(): un-triaged logs of any severity that share an entity with a log the team has
 *    already escalated or called malicious join the Tier-1 "Needs triage" queue.
 * Built only from what every player sees (no answer key).
 */
import type { Ev } from "./types";

/** Same id the team page uses for a feed log (alertQueue.feedEventId); local to avoid an import cycle. */
const feedEventId = (e: Ev): string => String((e.payload as { id?: unknown }).id ?? e.seq);

const PRIVATE_IP = /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;
const str = (v: unknown) => (typeof v === "string" ? v.trim() : "");

/** The entities a log is about: host, user, and any non-private address. */
export function entityKeys(e: Ev): string[] {
  const p = e.payload as { hostname?: unknown; user_email?: unknown; user?: { email?: unknown }; src_ip?: unknown; dst_ip?: unknown };
  const keys: string[] = [];
  const host = str(p.hostname).toLowerCase(); if (host) keys.push(`host:${host}`);
  const user = (str(p.user_email) || str(p.user?.email)).toLowerCase(); if (user && !/^(system|-|n\/a)$/.test(user)) keys.push(`user:${user}`);
  for (const ip of [str(p.src_ip), str(p.dst_ip)]) if (ip && !PRIVATE_IP.test(ip)) keys.push(`ip:${ip}`);
  return keys;
}
export const entityLabel = (k: string) => k.replace(/^(host|user|ip):/, "");

const tsOf = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);

/** Other feed logs about the same entities within ±windowMin of the target, newest last. */
export function relatedLogs(feed: Ev[], target: Ev, windowMin = 20, max = 12): { e: Ev; eid: string; shared: string[] }[] {
  const keys = new Set(entityKeys(target));
  if (!keys.size) return [];
  const t0 = tsOf(target), tid = feedEventId(target);
  const out: { e: Ev; eid: string; shared: string[] }[] = [];
  for (const e of feed) {
    const eid = feedEventId(e);
    if (eid === tid) continue;
    const t = tsOf(e);
    if (Number.isFinite(t0) && Number.isFinite(t) && Math.abs(t - t0) > windowMin * 60000) continue;
    const shared = entityKeys(e).filter(k => keys.has(k));
    if (shared.length) out.push({ e, eid, shared });
  }
  return out.slice(-max);
}

const HOT_VERDICTS = new Set(["true_positive", "suspicious"]);

/**
 * Un-triaged logs that share an entity with a log the team escalated or called malicious,
 * arriving from 10 min before to 30 min after it. eid → the shared entity.
 */
export function linkedToHot(feed: Ev[], dispositions: Map<string, string>, escalated: Set<string>, max = 10): Map<string, string> {
  const hot: { keys: Set<string>; t: number }[] = [];
  for (const e of feed) {
    const eid = feedEventId(e);
    if (escalated.has(eid) || HOT_VERDICTS.has(dispositions.get(eid) ?? "")) hot.push({ keys: new Set(entityKeys(e)), t: tsOf(e) });
  }
  const out = new Map<string, string>();
  if (!hot.length) return out;
  for (const e of feed) {
    const eid = feedEventId(e);
    if (dispositions.has(eid) || escalated.has(eid)) continue;
    const t = tsOf(e);
    for (const h of hot) {
      if (Number.isFinite(t) && Number.isFinite(h.t) && (t < h.t - 10 * 60000 || t > h.t + 30 * 60000)) continue;
      const k = entityKeys(e).find(x => h.keys.has(x));
      if (k) { out.set(eid, k); break; }
    }
  }
  return new Map([...out].slice(-max));
}
