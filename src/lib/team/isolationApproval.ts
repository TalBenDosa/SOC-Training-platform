import type { Ev } from "./types";

/**
 * Isolation needs the shift senior's approval (owner, 2026-11-07).
 *
 * An analyst no longer isolates a host directly. Tier-2 or Tier-3 sends
 * `isolation.requested`; the senior on shift answers with `isolation.approved` or
 * `isolation.denied`; on approval the SERVER records `edr.host_isolated` itself
 * (migration 0104 trigger), so the EDR console, Sentinel and the report keep
 * reading the same event they always did. Release stays direct (`edr.host_released`):
 * lifting a containment restores the business and needs no second pair of eyes.
 *
 * The approver rule lives here and nowhere else in TypeScript; the database gate
 * (`team_isolation_can_approve`, 0104) is the same rule in SQL. Keep them in step.
 *
 *   1. A seated, active SOC Manager or Lead.
 *   2. Otherwise a seated, active Tier-3 who is not the requester.
 *   3. Otherwise the exercise admin (the session's instructor seat, held only by a team admin).
 *   Staff may always approve or deny as an override, so a request can never wedge.
 *   Nobody approves their own request.
 *
 * "Active" on the server = heartbeat in the last ISOLATION_ACTIVE_WINDOW_MS (the roster
 * from GET /api/team/sessions/[id] carries it as `active`); the person approving counts
 * as active. The server is the authority.
 */

export const ISOLATION_REQUEST_TYPES = ["isolation.requested", "isolation.approved", "isolation.denied"] as const;
/** Roles that may ask for an isolation (the old direct-isolate roles). */
export const ISOLATION_REQUESTER_ROLES = ["t2", "t3"] as const;
/** Roles that may release a host directly. */
export const ISOLATION_RELEASE_ROLES = ["t2", "t3", "mgr", "lead", "instructor"] as const;
/** Same window the server lifecycle uses for "online". */
export const ISOLATION_ACTIVE_WINDOW_MS = 120_000;
export const ISOLATION_REASON_MAX = 500;

export interface ApproverMember {
  user_id: string;
  role: string;
  /** Seat status; `left` is never an approver. */
  status?: string | null;
  /** Online now (client: presence; server: last_seen_at in the window). */
  active: boolean;
}

export type ApproverTier = "mgr" | "t3" | "staff";

export interface IsolationApprovers {
  /** Which rung of the rule applies right now. */
  tier: ApproverTier;
  /** Who that rung names (may be empty only when no instructor seat exists). */
  userIds: string[];
  /** Staff seats, who may always approve as an override. */
  staffIds: string[];
}

const seated = (m: ApproverMember) => (m.status ?? "") !== "left";

export function isolationApprovers(members: ApproverMember[], requesterId: string | null): IsolationApprovers {
  const staffIds = members.filter(m => m.role === "instructor" && seated(m) && m.user_id !== requesterId).map(m => m.user_id);
  const mgr = members.filter(m => (m.role === "mgr" || m.role === "lead") && seated(m) && m.active && m.user_id !== requesterId);
  if (mgr.length) return { tier: "mgr", userIds: mgr.map(m => m.user_id), staffIds };
  const t3 = members.filter(m => m.role === "t3" && seated(m) && m.active && m.user_id !== requesterId);
  if (t3.length) return { tier: "t3", userIds: t3.map(m => m.user_id), staffIds };
  return { tier: "staff", userIds: staffIds, staffIds };
}

/** May `userId` approve or deny a request by `requesterId` right now? */
export function canApproveIsolation(members: ApproverMember[], requesterId: string | null, userId: string): boolean {
  if (!userId || userId === requesterId) return false;
  // The person acting is plainly online, whatever their last heartbeat says (same as the DB gate).
  const a = isolationApprovers(members.map(m => (m.user_id === userId ? { ...m, active: true } : m)), requesterId);
  return a.userIds.includes(userId) || a.staffIds.includes(userId);
}

/**
 * Nobody seated can approve: the only possible approver is the requester (an exercise admin playing
 * Tier-2 with no Manager, Lead, other Tier-3 or admin in the instructor seat). The request waits for
 * an exercise admin, and the requester is told so rather than "waiting for approval from" themselves.
 * Nobody approves their own request, here or in the database (team_isolation_can_approve).
 */
export const NO_APPROVER = "No approver on shift: an exercise admin must approve";
/** What the requester can do about it. */
export const NO_APPROVER_HELP = "Nobody seated in this session can approve your request, and you cannot approve your own. Ask an exercise admin to take the instructor seat, or to seat a SOC Manager, Lead or Tier-3.";
export const isNoApprover = (approver: string | null | undefined) => (approver ?? "").startsWith(NO_APPROVER);

/** "Waiting for approval from X", or the no-approver line when nobody but the requester could approve. */
export function waitingForApproval(approver: string, opts: { requester?: boolean } = {}): string {
  if (isNoApprover(approver)) return `${NO_APPROVER}.${opts.requester ? ` ${NO_APPROVER_HELP}` : ""}`;
  return `Waiting for approval from ${approver}`;
}

/** A short label for the approver's rung, for the requester's "waiting for ..." line. */
export function approverLabel(tier: ApproverTier): string {
  return tier === "mgr" ? "the SOC Manager" : tier === "t3" ? "Tier-3" : "the exercise admin";
}

export interface IsolationRequest {
  seq: number;
  host: string;
  requestedBy: string | null;
  requesterRole: string | null;
  reason: string;
  incident: string | null;
  at: string | null;
  /** pending until answered; approved/denied carry the answer's seq. */
  state: "pending" | "approved" | "denied";
  answeredBy: string | null;
  answeredAt: string | null;
  answerSeq: number | null;
  denyReason: string | null;
}

/** Every isolation request in the log with its answer, in request order. */
export function isolationRequests(events: Ev[]): IsolationRequest[] {
  const out = new Map<number, IsolationRequest>();
  const sorted = [...events].sort((a, b) => a.seq - b.seq);
  for (const e of sorted) {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    if (e.type === "isolation.requested") {
      const host = String(p.host ?? "").trim();
      if (!host) continue;
      out.set(e.seq, {
        seq: e.seq, host, requestedBy: e.actor_id, requesterRole: e.role,
        reason: String(p.reason ?? ""), incident: p.incident != null ? String(p.incident) : null,
        at: e.occurred_at ?? null, state: "pending", answeredBy: null, answeredAt: null, answerSeq: null, denyReason: null,
      });
    } else if (e.type === "isolation.approved" || e.type === "isolation.denied") {
      const r = out.get(Number(p.request_seq));
      if (!r || r.state !== "pending") continue;
      r.state = e.type === "isolation.approved" ? "approved" : "denied";
      r.answeredBy = e.actor_id; r.answeredAt = e.occurred_at ?? null; r.answerSeq = e.seq;
      if (e.type === "isolation.denied" && p.reason != null) r.denyReason = String(p.reason);
    }
  }
  return [...out.values()];
}

/** Open requests only, keyed by lower-cased host (the DB allows one open request per host). */
export function pendingIsolationRequests(events: Ev[]): Map<string, IsolationRequest> {
  const m = new Map<string, IsolationRequest>();
  for (const r of isolationRequests(events)) if (r.state === "pending") m.set(r.host.toLowerCase(), r);
  return m;
}
