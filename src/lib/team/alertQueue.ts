/**
 * Tier-1 alert queue — the "needs triage" worklist of the team SIEM.
 *
 * It is a PROJECTION over the same shared feed the SIEM table shows, never a
 * second alert source: every item is one of the feed's own logs. It used to be
 * rendered as a separate orange card beside the SIEM, which read as a second
 * system with alerts "missing" from the SIEM (the table only rendered the last
 * 120 logs, used its own row text and ignored the SIEM filters). The team page
 * now shows it as a VIEW of the SIEM table ("Needs triage") and puts the SLA age
 * on the SIEM rows themselves.
 *
 * Rules (unchanged from the card):
 *  - un-triaged = no disposition yet, and not already escalated;
 *  - high/critical by default, medium optionally (early signs of a story);
 *  - ordered by orphans first (past SLA, unclaimed, not escalated — nobody is
 *    working it), then severity × age;
 *  - 2026-10-18: a log of ANY severity that shares a host / user / external address with a log
 *    the team escalated or called malicious joins the queue as "linked" (correlate.ts), so the
 *    quiet steps of an attack already found are not walked past.
 */
import type { Ev } from "./types";
import { activeMs, type PauseSpan } from "./pauses";
import { linkedToHot, entityLabel } from "./correlate";

/** Minutes until an un-triaged alert breaches its triage SLA, by severity. */
export const slaMinFor = (sev: string) => (sev === "critical" ? 1 : sev === "high" ? 3 : sev === "medium" ? 10 : 30);

export interface QueueItem {
  e: Ev;
  eid: string;
  severity: string;
  mins: number;
  breached: boolean;
  orphan: boolean;
  /** Pulled in by correlation: the entity it shares with an escalated / malicious log. */
  linked?: string;
}

/** The id the team page uses for a feed log (payload id, else its seq). */
export const feedEventId = (e: Ev): string => String((e.payload as { id?: unknown }).id ?? e.seq);

const RANK: Record<string, number> = { critical: 4, high: 3, medium: 2 };

export function buildAlertQueue(opts: {
  feed: Ev[];
  dispositions: Map<string, string>;
  escalated: Set<string>;
  /** eid → current claim (activeClaims). */
  claims: Map<string, { by: string }>;
  nowMs: number;
  withMedium: boolean;
  /** Paused spans (pausedSpans) — a pause never ages an alert toward its SLA (QA M3). */
  pauses?: PauseSpan[];
}): QueueItem[] {
  const { feed, dispositions, escalated, claims, nowMs, withMedium, pauses = [] } = opts;
  const linked = linkedToHot(feed, dispositions, escalated);
  const items: (QueueItem & { score: number })[] = [];
  for (const e of feed) {
    const eid = feedEventId(e);
    const severity = String((e.payload as { severity?: unknown }).severity ?? "");
    const link = linked.get(eid);
    const inScope = severity === "high" || severity === "critical" || (withMedium && severity === "medium") || !!link;
    if (!inScope || dispositions.has(eid) || escalated.has(eid)) continue;
    const t = e.occurred_at ? Date.parse(e.occurred_at) : NaN;
    const mins = Number.isFinite(t) ? Math.max(0, Math.floor(activeMs(t, nowMs, pauses) / 60000)) : 0;
    // A linked log ages against the medium SLA and ranks at least as a medium.
    const slaSev = link && !RANK[severity] ? "medium" : severity;
    const breached = mins >= slaMinFor(slaSev);
    const rank = Math.max(RANK[severity] ?? 0, link ? 2.5 : 0);
    items.push({ e, eid, severity, mins, breached, orphan: breached && !claims.has(eid), score: rank * (1 + mins / 5), ...(link ? { linked: entityLabel(link) } : {}) });
  }
  items.sort((a, b) => (a.orphan === b.orphan ? b.score - a.score : a.orphan ? -1 : 1));
  return items.map(({ score: _s, ...rest }) => { void _s; return rest; });
}

/** The alert "Take next" should hand this analyst: the most urgent one nobody else holds. */
export function nextAlertFor(queue: QueueItem[], claims: Map<string, { by: string }>, meId: string): QueueItem | null {
  return queue.find(q => { const c = claims.get(q.eid); return !c || c.by === meId; }) ?? null;
}
