"use client";
import { Gauge, AlertTriangle } from "lucide-react";
import type { WorkloadPreview, WorkloadLevel, TierLoad } from "@/lib/team/workloadPreview";

export interface WorkloadAlternative { kind: string; label: string; preview: WorkloadPreview }

const TONE: Record<WorkloadLevel, string> = {
  ok: "border-neon-green/40 bg-neon-green/[0.06] text-neon-green",
  busy: "border-neon-amber/40 bg-neon-amber/[0.08] text-neon-amber",
  over: "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
};
const LABEL: Record<WorkloadLevel, string> = { ok: "Fits the team", busy: "Busy but workable", over: "More than the team can do" };
const pctText = (t: TierLoad) => (t.pct == null ? "nobody in this role" : `${Math.round(t.pct * 100)}%`);

/**
 * Staff-only lobby check: the exercise is built ahead of time and its real work is measured per
 * tier (load-preview). Above 100% the instructor sees what would fix it and confirms before starting.
 */
export function WorkloadCheck({ preview, alternatives, loading, confirmed, onConfirm }: {
  preview: WorkloadPreview | null; alternatives: WorkloadAlternative[]; loading: boolean;
  confirmed: boolean; onConfirm: (v: boolean) => void;
}) {
  if (!preview) return <p className="mt-2 text-[11px] text-slate-500">{loading ? "Measuring the team's workload…" : ""}</p>;
  return (
    <div className={`mt-2 rounded-lg border px-2.5 py-2 text-[11px] ${TONE[preview.level]}`} role="status">
      <p className="flex items-center gap-1.5 font-semibold"><Gauge className="h-3.5 w-3.5" aria-hidden /> Workload check: {LABEL[preview.level]}</p>
      <p className="mt-1 text-slate-300">
        Built ahead of time: {preview.feedRows} logs over {preview.shiftMin} min ({preview.logsPerMin} per minute), {preview.alertRows} high or critical alerts, {preview.incidents} incident{preview.incidents === 1 ? "" : "s"} to escalate, attacks {preview.attackShare}% of the feed.
      </p>
      <p className="mt-0.5 text-slate-300">
        Tier-1 ({preview.tier1.people}): <b>{pctText(preview.tier1)}</b> of their time · Tier-2/3 ({preview.tier2.people}): <b>{pctText(preview.tier2)}</b>
        <span className="text-slate-500"> (reading a log ~25 s, an alert ~1 min, a good escalation ~5 min, a case ~10 min; 100% = the whole shift with some breathing room)</span>
      </p>
      {preview.level === "over" && (
        <div className="mt-1.5 space-y-1">
          {alternatives.length > 0 && (
            <ul className="space-y-0.5 text-slate-300">
              {alternatives.map(a => (
                <li key={a.kind}>With {a.label}: Tier-1 {pctText(a.preview.tier1)}, Tier-2/3 {pctText(a.preview.tier2)}, {a.preview.logsPerMin} logs/min</li>
              ))}
            </ul>
          )}
          <label className="flex items-center gap-1.5 text-slate-200">
            <input type="checkbox" checked={confirmed} onChange={e => onConfirm(e.target.checked)} />
            <AlertTriangle className="h-3.5 w-3.5 text-severity-critical" aria-hidden /> Start anyway: I know the team will not keep up with everything.
          </label>
        </div>
      )}
    </div>
  );
}
