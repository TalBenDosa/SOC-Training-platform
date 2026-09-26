import type { Ev } from "@/lib/team/types";

/**
 * ONE claims / open-work projection for the whole room (audit A3). It used to be
 * reconstructed four times with different rules — the feed badges, the Tier-1
 * console and the Situation Board expired a claim after 5 minutes, while the
 * after-action replay never did — so the AAR could penalise a Manager for "not
 * nudging" an overload the Situation Board had correctly stopped showing.
 * Pure: pass the reference time explicitly (serverNow() live, event time in a replay).
 */
export const CLAIM_TTL_MS = 5 * 60 * 1000;

export interface Claim { by: string; at: number }

const eidOf = (e: Ev) => String((e.payload as { event_id?: unknown } | null)?.event_id ?? "");
const tsOf = (e: Ev, fallback: number) => (e.occurred_at ? Date.parse(e.occurred_at) : fallback);

/**
 * Active Tier-1 soft-claims at time `now`: latest alert.claimed per alert, cleared
 * by alert.released or a disposition, and expired after `ttlMs`.
 */
export function activeClaims(events: Ev[], now: number, ttlMs = CLAIM_TTL_MS): Map<string, Claim> {
  const m = new Map<string, Claim>();
  for (const e of events) {
    if (e.type !== "alert.claimed" && e.type !== "alert.released" && e.type !== "disposition.set") continue;
    const eid = eidOf(e); if (!eid) continue;
    if (e.type === "alert.claimed") m.set(eid, { by: e.actor_id ?? "", at: tsOf(e, now) });
    else m.delete(eid);
  }
  for (const [eid, c] of m) if (now - c.at > ttlMs) m.delete(eid);
  return m;
}

/**
 * Open work per analyst at time `now`: active T1 claims + T2/T3 escalations they
 * first acknowledged that aren't resolved yet.
 */
export function openLoadByUser(events: Ev[], now: number, ttlMs = CLAIM_TTL_MS): Map<string, number> {
  const load = new Map<string, number>();
  const bump = (u: string) => { if (u) load.set(u, (load.get(u) ?? 0) + 1); };
  for (const c of activeClaims(events, now, ttlMs).values()) bump(c.by);
  const owner = new Map<string, string>();
  const resolved = new Set<string>();
  for (const e of events) {
    if (e.type === "escalation.acknowledged") { const id = eidOf(e); if (id && !owner.has(id)) owner.set(id, e.actor_id ?? ""); }
    else if (e.type === "escalation.resolved") resolved.add(eidOf(e));
  }
  for (const [id, u] of owner) if (!resolved.has(id)) bump(u);
  return load;
}
