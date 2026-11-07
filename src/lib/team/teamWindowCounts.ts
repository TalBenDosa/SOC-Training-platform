import type { Ev } from "./types";
import { containmentRequests, escalationStates } from "./projections";
import { canApproveIsolation, isolationRequests, type ApproverMember } from "./isolationApproval";

/**
 * What waits for one player, counted the same way in both of their windows: the team room (the
 * SIEM window) and Sentinel (2026-11 review: in Sentinel the analyst saw no escalation, chat or
 * approval). Pure; the tab title and the Sentinel strip both read it.
 */

/** localStorage key of the last chat message a player has seen (the team room writes it, Sentinel reads it). */
export const chatReadKey = (sessionId: string, userId: string) => `team-chat-read-${sessionId}-${userId}`;

/** A coach message is shown only to its addressee and to staff (it is NOT private in the database). */
export function visibleMessages(events: Ev[], meId: string, isStaff: boolean): Ev[] {
  return events.filter(e => {
    if (e.type !== "message.sent") return false;
    const p = e.payload as { kind?: unknown; to?: unknown };
    if (p.kind === "coach") return isStaff || p.to === meId || e.actor_id === meId;
    return true;
  });
}

export interface WaitingCounts {
  /** Escalations nobody has taken (Tier-2 / Tier-3), or all waiting ones (Manager). */
  escalations: number;
  /** Containments approved and waiting for this analyst to carry out. */
  approved: number;
  /** Isolation or containment requests waiting for THIS viewer's answer. */
  approvals: number;
  /** Chat messages from others since the last one this player saw. */
  unreadChat: number;
}

export function waitingCounts(events: Ev[], o: { meId: string; role: string | null; isStaff: boolean; members: ApproverMember[]; chatReadSeq: number }): WaitingCounts {
  const { meId, role } = o;
  const st = escalationStates(events);
  let escalations = 0;
  for (const s of st.values()) {
    if (s.rounds === 0 || s.resolved || s.bounced) continue;
    if (role === "t2" || role === "t3" || role === "mgr" || role === "lead") { if (!s.acked) escalations++; }
  }
  const conts = containmentRequests(events);
  const myCaseEids = new Set([...st.entries()].filter(([, s]) => s.owner === meId).map(([eid]) => eid));
  const approved = conts.filter(c => c.status === "approved" && (myCaseEids.has(c.eid) || c.request.actor_id === meId)).length;
  const iso = isolationRequests(events);
  let approvals = iso.filter(r => r.state === "pending" && canApproveIsolation(o.members, r.requestedBy, meId)).length;
  if (role === "mgr" || role === "lead") approvals += conts.filter(c => c.status === "pending").length;
  const unreadChat = visibleMessages(events, meId, o.isStaff).filter(e => e.actor_id !== meId && e.seq > o.chatReadSeq).length;
  return { escalations, approved, approvals, unreadChat };
}

/** The tab title with a count in front: "(3) Team exercise". */
export function titleWithCount(base: string, n: number): string {
  const clean = base.replace(/^\(\d+\)\s*/, "");
  return n > 0 ? `(${n}) ${clean}` : clean;
}
