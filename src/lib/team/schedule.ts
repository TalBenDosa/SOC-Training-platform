/**
 * The attacks of a running team exercise that have not reached the feed yet, and how to bring
 * the next one forward (2026-10-18 review: in two of four Team Training exercises the primary
 * incident was still due when the instructor ended the session, and nothing on screen said so).
 *
 * Pure: the route reads the pending session_injects rows and the session clock, and writes back
 * the new due offsets this module computes. Staff only (the rows carry the answer key).
 */

export interface PendingRow {
  id: string;
  channel: "feed" | "inject" | "bonus";
  due_offset_ms: number;
  expected_action: Record<string, unknown> | null;
}

export interface PendingAttack {
  incident: string;
  /** "planned" = a storyline of the attack plan, "standalone" = a pool attack, "bonus" = the held bonus. */
  kind: "planned" | "standalone" | "bonus";
  firstDueMs: number | null;
  rows: number;
}

const ATTACK = new Set(["tp", "escalate"]);
const ea = (r: PendingRow) => r.expected_action ?? {};
const incidentOf = (r: PendingRow) => (typeof ea(r).incident_id === "string" ? (ea(r).incident_id as string) : null);

/** The session clock (ms of live shift), the same arithmetic promote_due_injects uses. */
export function shiftElapsedMs(s: { started_at: string | null; paused_ms?: number | null; paused_at?: string | null; status: string }, nowMs: number): number {
  if (!s.started_at) return 0;
  const end = s.status === "paused" && s.paused_at ? Date.parse(s.paused_at) : nowMs;
  return Math.max(0, end - Date.parse(s.started_at) - (s.paused_ms ?? 0));
}

/** Pending attacks, soonest first (the held bonus last). */
export function pendingAttacks(rows: PendingRow[]): PendingAttack[] {
  const by = new Map<string, PendingAttack>();
  for (const r of rows) {
    const inc = incidentOf(r);
    if (!inc || !ATTACK.has(String(ea(r).expected_verdict))) continue;
    const kind: PendingAttack["kind"] = r.channel === "bonus" ? "bonus" : ea(r).origin === "story" ? "planned" : "standalone";
    const cur = by.get(inc) ?? { incident: inc, kind, firstDueMs: null, rows: 0 };
    cur.rows++;
    if (r.channel !== "bonus") cur.firstDueMs = cur.firstDueMs == null ? r.due_offset_ms : Math.min(cur.firstDueMs, r.due_offset_ms);
    by.set(inc, cur);
  }
  return [...by.values()].sort((a, b) => (a.firstDueMs ?? Infinity) - (b.firstDueMs ?? Infinity));
}

/**
 * New due offsets that bring `incident` (default: the next planned attack, else the next one,
 * else the held bonus) forward so its first log arrives `leadMs` from now, its own spacing kept.
 * Every pending row of that incident moves (its control steps too); nothing else does.
 */
export function releasePlan(rows: PendingRow[], elapsedMs: number, incident?: string, leadMs = 5000): { incident: string; updates: { id: string; due_offset_ms: number; channel?: "feed" }[] } | null {
  const pending = pendingAttacks(rows);
  const target = incident
    ? pending.find(p => p.incident === incident)
    : pending.find(p => p.kind === "planned" && p.firstDueMs != null) ?? pending.find(p => p.firstDueMs != null) ?? pending.find(p => p.kind === "bonus");
  if (!target) return null;
  const mine = rows.filter(r => incidentOf(r) === target.incident && r.channel !== "inject");
  if (!mine.length) return null;
  const at = elapsedMs + leadMs;
  if (target.kind === "bonus") {
    // Held rows sit at BONUS_HOLD + their relative offset: release them at their own pace.
    const base = Math.min(...mine.map(r => r.due_offset_ms));
    return { incident: target.incident, updates: mine.map(r => ({ id: r.id, due_offset_ms: at + (r.due_offset_ms - base), channel: "feed" as const })) };
  }
  const first = Math.min(...mine.map(r => r.due_offset_ms));
  if (first <= at) return { incident: target.incident, updates: [] };   // already about to arrive
  const delta = at - first;
  return { incident: target.incident, updates: mine.map(r => ({ id: r.id, due_offset_ms: r.due_offset_ms + delta })) };
}
