/**
 * Platform health for the super-admin console (QA phase 7, E-06) — internal
 * only, no external monitoring account. Reads the service-only team_ops_health
 * view (0071) and the recent team_ops_events rows, and turns them into one
 * level the console can show at a glance.
 */
export interface OpsHealthRow {
  running_sessions: number; paused_sessions: number;
  max_promote_lag_s: number; ops_errors_1h: number; broadcast_failures_1h: number;
}
export interface OpsEvent { at: string; kind: string; session_id: string | null; detail: string | null }
export type OpsLevel = "ok" | "warning" | "critical";

export function opsLevel(h: OpsHealthRow | null): { level: OpsLevel; reasons: string[] } {
  if (!h) return { level: "warning", reasons: ["Health data couldn't be read."] };
  const reasons: string[] = [];
  let level: OpsLevel = "ok";
  const bump = (to: OpsLevel, why: string) => {
    reasons.push(why);
    if (to === "critical" || level === "ok") level = to;
  };
  // PostgREST returns bigint/numeric columns as numbers or numeric strings.
  const n = (v: unknown) => Number(v) || 0;
  const broadcast = n(h.broadcast_failures_1h), lag = n(h.max_promote_lag_s), errors = n(h.ops_errors_1h);
  if (broadcast > 0) bump(broadcast >= 20 ? "critical" : "warning", `${broadcast} realtime broadcast failure(s) in the last hour — team rooms may miss live events.`);
  if (lag > 60) bump(lag > 300 ? "critical" : "warning", `Team injects are ${Math.round(lag)} s late — the cron jobs may be stalled.`);
  const other = errors - broadcast;
  if (other > 0) bump(other >= 50 ? "critical" : "warning", `${other} background job error(s) in the last hour.`);
  return { level, reasons };
}
