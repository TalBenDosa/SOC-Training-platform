/**
 * Tier-3 "open lead" (T3 interface spec, stage C): the previous shift left a host nobody explained.
 * The Tier-3 has work from the first minutes: collect, decide, and record the host in the scope
 * register. Sometimes the host is the planted attack's first host; sometimes it is quiet, ordinary
 * activity and "cleared, with evidence" is the right answer.
 *
 * Built on the server at start, after the timeline is fitted, as one more `inject` entry. The text is
 * the SAME whichever way the truth goes; the truth sits in the staff-only answer (`lead_truth`) and
 * reaches the report only after the session ended (serverReport INJECT_ANSWER_KEYS).
 * Pure and deterministic: the session seed decides.
 */
import type { TimelineEntry } from "./buildTimeline";
import { hashSeed } from "./variety";

export const LEAD_KIND = "t3_lead";
export type LeadTruth = "compromised" | "clean";

const ATTACK = new Set(["tp", "escalate"]);
const str = (v: unknown) => (typeof v === "string" ? v : "");
const hk = (h: string) => h.trim().toLowerCase().split(".")[0];
const verdictOf = (e: TimelineEntry) => str(e.answer?.expected_verdict) || str(e.body.expected_verdict);

export function leadText(host: string): string {
  return `Open lead from the previous shift: ${host} showed activity nobody explained before handover. Tier-3: collect evidence on it, decide, and record the host in your scope register (confirmed or cleared, with evidence).`;
}

/**
 * The lead to add, or null (no Tier-3 seat, or no usable host). Easy sessions always point at the
 * attack (it teaches the loop); otherwise the seed picks the attack's first host or a quiet host
 * that never takes part in the attack, about half the time each.
 */
export function pickShiftLead(timeline: TimelineEntry[], opts: { seed: string | number; difficulty: string; hasTier3: boolean }): TimelineEntry | null {
  if (!opts.hasTier3) return null;
  const feed = timeline.filter(e => e.channel === "feed" && str(e.body.hostname)).sort((a, b) => a.due_offset_ms - b.due_offset_ms);
  const attackRows = feed.filter(e => ATTACK.has(verdictOf(e)));
  const attackHosts = new Set(attackRows.map(e => hk(str(e.body.hostname))));
  const first = attackRows[0];

  // Quiet hosts: seen at least twice, never in the attack, first seen before the attack starts.
  const quiet = new Map<string, { host: string; n: number; firstAt: number }>();
  for (const e of feed) {
    const h = str(e.body.hostname); const k = hk(h);
    if (!k || attackHosts.has(k)) continue;
    const cur = quiet.get(k) ?? { host: h, n: 0, firstAt: e.due_offset_ms };
    cur.n++; quiet.set(k, cur);
  }
  const limit = first ? first.due_offset_ms : Infinity;
  const clean = [...quiet.values()].filter(q => q.n >= 2 && q.firstAt < limit).sort((a, b) => b.n - a.n || a.host.localeCompare(b.host));

  const coin = hashSeed(`${opts.seed}:t3-lead`) % 2 === 0;
  const useAttack = !!first && (opts.difficulty === "easy" || !clean.length || coin);
  const host = useAttack ? str(first!.body.hostname) : clean[0]?.host;
  if (!host) return null;
  const truth: LeadTruth = useAttack ? "compromised" : "clean";
  // Arrives once the host already has logs to collect: a little after its first row.
  const hostFirst = feed.find(e => hk(str(e.body.hostname)) === hk(host))?.due_offset_ms ?? 0;
  return {
    due_offset_ms: hostFirst + 20_000,
    channel: "inject",
    body: { id: "t3_lead", kind: LEAD_KIND, host, text: leadText(host) },
    answer: { kind: LEAD_KIND, lead_truth: truth },
  };
}
