import type { Ev } from "@/lib/team/types";

export interface SentinelActivity {
  queries: number; queriesOk: number; bookmarks: number; comments: number; closed: number;
  /** Closed incidents whose classification could be judged, and how many of those were right. */
  judged: number; judgedRight: number;
}

/** A closed incident's verdict is right when "True Positive" meets attack logs, and anything else except Undetermined meets none. */
export function classificationRight(classification: string, attack: boolean): boolean | null {
  if (!classification || classification === "Undetermined") return null;
  return classification.startsWith("True Positive") === attack;
}

/** What one analyst did in Sentinel during the shift, read from the session log. Null if nothing. */
export function sentinelActivity(events: Ev[], userId: string, attackEvents?: Set<string>): SentinelActivity | null {
  const out: SentinelActivity = { queries: 0, queriesOk: 0, bookmarks: 0, comments: 0, closed: 0, judged: 0, judgedRight: 0 };
  for (const e of events) {
    if (e.actor_id !== userId) continue;
    const p = e.payload as { ok?: unknown; patch?: { status?: unknown; classification?: unknown }; event_ids?: unknown };
    if (e.type === "sentinel.query_run") { out.queries++; if (p.ok === true) out.queriesOk++; }
    else if (e.type === "sentinel.bookmark_added") out.bookmarks++;
    else if (e.type === "sentinel.comment_added") out.comments++;
    else if (e.type === "sentinel.incident_updated" && p.patch?.status === "Closed") {
      out.closed++;
      const ids = Array.isArray(p.event_ids) ? p.event_ids.map(String) : [];
      const right = attackEvents && ids.length ? classificationRight(String(p.patch.classification ?? ""), ids.some(i => attackEvents.has(i))) : null;
      if (right !== null) { out.judged++; if (right) out.judgedRight++; }
    }
  }
  return out.queries + out.bookmarks + out.comments + out.closed > 0 ? out : null;
}
