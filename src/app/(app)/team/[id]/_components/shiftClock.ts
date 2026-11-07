import type { Ev, RosterMember } from "@/lib/team/types";
import { activeMs, pausedSpans } from "@/lib/team/pauses";
import { scheduledEnd } from "@/lib/team/projections";

/**
 * Shift time for every player (2026-11 review: no player saw a clock, and End threw everyone into
 * the review mid-sentence). All of it comes from the session log the room already holds, on the
 * server clock: running time since session.started with paused spans removed, the planned length,
 * and a scheduled end (session.end_scheduled, two minutes ahead) until it fires or is cancelled.
 * Pure: pass `now` (serverNow()).
 */
export interface ShiftClock {
  started: boolean;
  /** Running (un-paused) milliseconds since the shift started. */
  activeMs: number;
  plannedMs: number;
  /** Planned minus running, never below 0. */
  remainingMs: number;
  /** Running time has passed the planned length. */
  overtime: boolean;
  paused: boolean;
  /** A scheduled end that has not fired or been cancelled: when (server ms) and by whom. */
  endsAt: number | null;
  endBy: string | null;
}

const ts = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);

export function shiftClock(events: Ev[], o: { startedAt?: string | null; plannedMs: number; now: number }): ShiftClock {
  let start = o.startedAt ? Date.parse(o.startedAt) : NaN;
  let endsAt: number | null = null, endBy: string | null = null, paused = false, ended = NaN;
  for (const e of events) {
    if (e.type === "session.started" && !Number.isFinite(start)) start = ts(e);
    else if (e.type === "session.end_scheduled") {
      const at = Date.parse(String((e.payload as { ends_at?: unknown }).ends_at ?? ""));
      endsAt = Number.isFinite(at) ? at : null;
      endBy = e.actor_id ?? (typeof (e.payload as { by?: unknown }).by === "string" ? String((e.payload as { by?: unknown }).by) : null);
    } else if (e.type === "session.end_cancelled") { endsAt = null; endBy = null; }
    else if (e.type === "session.paused") paused = true;
    else if (e.type === "session.resumed") paused = false;
    else if (e.type === "session.ended") { ended = ts(e); endsAt = null; paused = false; }
  }
  // The scheduled end, read with the server's own projection so both sides agree.
  const sched = scheduledEnd(events);
  if (sched) { const t = Date.parse(sched.endsAt); endsAt = Number.isFinite(t) ? t : endsAt; endBy = sched.by ?? endBy; } else if (endsAt != null && !events.some(e => e.type === "session.end_scheduled")) endsAt = null;
  if (!Number.isFinite(start)) return { started: false, activeMs: 0, plannedMs: o.plannedMs, remainingMs: o.plannedMs, overtime: false, paused, endsAt, endBy };
  const until = Number.isFinite(ended) ? ended : o.now;
  const run = Math.max(0, activeMs(start, until, pausedSpans(events, until)));
  return { started: true, activeMs: run, plannedMs: o.plannedMs, remainingMs: Math.max(0, o.plannedMs - run), overtime: o.plannedMs > 0 && run >= o.plannedMs, paused, endsAt, endBy };
}

/** mm:ss, or h:mm:ss past an hour. */
export function fmtClock(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h ? `${h}:${pad(m)}:${pad(sec)}` : `${pad(m)}:${pad(sec)}`;
}

/** The server's presence notices (they replaced the automatic pauses): the QA side's projection, shared. */
export { openPresenceNotices } from "@/lib/team/projections";

/** The SOC Manager's open request to end the shift (a chat message of kind end_request), if any. */
export function openEndRequest(events: Ev[]): Ev | null {
  let req: Ev | null = null;
  for (const e of events) {
    if (e.type === "message.sent" && (e.payload as { kind?: unknown }).kind === "end_request") req = e;
    else if (req && (e.type === "session.end_scheduled" || e.type === "session.ended" || (e.type === "message.sent" && (e.payload as { kind?: unknown }).kind === "end_request_declined"))) req = null;
  }
  return req;
}

/**
 * Who looks stuck (2026-11 review: the Manager was silent for 20 minutes and the instructor's screen
 * showed only "online"). Per seat: the last real action (not a log open), the last activity of any
 * kind including reading a log, idle minutes since that, and the open load. Players only.
 */
export interface SeatActivity { userId: string; name: string; role: string; lastActionMs: number | null; lastSeenMs: number | null; idleMin: number | null; idle: boolean }
export const IDLE_MIN = 5;
export function seatActivity(events: Ev[], roster: RosterMember[], now: number, startedAt?: number | null): SeatActivity[] {
  const lastAct = new Map<string, number>(), lastSeen = new Map<string, number>();
  for (const e of events) {
    if (!e.actor_id) continue;
    const t = ts(e);
    if (!Number.isFinite(t)) continue;
    if (e.type !== "event.opened" && e.type !== "member.ready" && e.type !== "member.unready") lastAct.set(e.actor_id, Math.max(lastAct.get(e.actor_id) ?? 0, t));
    lastSeen.set(e.actor_id, Math.max(lastSeen.get(e.actor_id) ?? 0, t));
  }
  const spans = pausedSpans(events, now);
  return roster.filter(m => m.status !== "left" && m.role !== "instructor" && m.role !== "observer").map(m => {
    const a = lastAct.get(m.user_id) ?? null, s = lastSeen.get(m.user_id) ?? null;
    const from = s ?? (startedAt ?? null);
    const idleMin = from != null && now > from ? Math.floor(activeMs(from, now, spans) / 60000) : null;
    return { userId: m.user_id, name: m.name, role: m.role, lastActionMs: a, lastSeenMs: s, idleMin, idle: idleMin != null && idleMin >= IDLE_MIN };
  });
}
