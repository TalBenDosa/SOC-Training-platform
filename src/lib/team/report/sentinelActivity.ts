import type { Ev } from "@/lib/team/types";

export interface SentinelActivity { queries: number; queriesOk: number; bookmarks: number; comments: number; closed: number }

/** What one analyst did in Sentinel during the shift, read from the session log. Null if nothing. */
export function sentinelActivity(events: Ev[], userId: string): SentinelActivity | null {
  const out: SentinelActivity = { queries: 0, queriesOk: 0, bookmarks: 0, comments: 0, closed: 0 };
  for (const e of events) {
    if (e.actor_id !== userId) continue;
    const p = e.payload as { ok?: unknown; patch?: { status?: unknown } };
    if (e.type === "sentinel.query_run") { out.queries++; if (p.ok === true) out.queriesOk++; }
    else if (e.type === "sentinel.bookmark_added") out.bookmarks++;
    else if (e.type === "sentinel.comment_added") out.comments++;
    else if (e.type === "sentinel.incident_updated" && p.patch?.status === "Closed") out.closed++;
  }
  return out.queries + out.bookmarks + out.comments + out.closed > 0 ? out : null;
}
