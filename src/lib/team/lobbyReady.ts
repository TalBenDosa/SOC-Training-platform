/**
 * Lobby readiness — derived ONLY from the server's event log (plus the roster status read at
 * load). Realtime presence is for "who is online" and must never decide who is ready: each
 * client's tracked presence flag can be stale or not yet updated, and letting it overwrite the
 * log made a fresh "ready" vanish whenever anyone joined or clicked (prod 2026-10: players had to
 * press Ready two or three times, and marks dropped again as the last player readied up).
 */
export interface ReadyRosterRow { user_id: string; status?: string | null }
export interface ReadyEvent { seq: number; type: string; actor_id?: string | null }

export function deriveReadyMap(
  roster: ReadyRosterRow[],
  events: ReadyEvent[],
  me: { id: string } | null = null,
  pendingReady: boolean | null = null,
): Record<string, boolean> {
  const m: Record<string, boolean> = {};
  for (const r of roster) m[r.user_id] = r.status === "ready" || r.status === "active";
  for (const e of [...events].sort((a, b) => a.seq - b.seq)) {
    if (!e.actor_id) continue;
    if (e.type === "member.ready") m[e.actor_id] = true;
    else if (e.type === "member.unready") m[e.actor_id] = false;
  }
  // The local click is shown at once; the server row replaces it the moment it is merged.
  if (me && pendingReady !== null) m[me.id] = pendingReady;
  return m;
}
