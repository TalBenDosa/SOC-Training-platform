"use client";
import { cn } from "@/lib/utils";
import type { DashboardSessionRecord } from "./useLiveEvents";
import { CheckCircle2, Shield, X, Zap, FileText, XCircle } from "lucide-react";

interface Objective {
  label: string;
  met: boolean;
}

interface Props {
  record: DashboardSessionRecord;
  reportPassed: boolean;
  onClose: () => void;
  objectives?: Objective[];
  canClearCompany?: boolean;
  nextCompanyName?: string;
  onClearCompany?: () => void;
}

export function SessionSummaryModal({ record, reportPassed, onClose, objectives, canClearCompany, nextCompanyName, onClearCompany }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
      <div className="relative w-full max-w-lg rounded-xl border border-border bg-bg-elevated shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">

        {/* Top accent */}
        <div className="h-1 w-full shrink-0 bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-green" />

        {/* Header */}
        <div className="flex items-center justify-between px-6 pt-5 pb-4 border-b border-border shrink-0">
          <div className="flex items-center gap-3">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyber-500/15 border border-cyber-500/30">
              <Zap className="h-5 w-5 text-cyber-300" />
            </span>
            <div>
              <h2 className="text-base font-bold text-white">Session Complete</h2>
              <p className="text-[10px] text-slate-400 uppercase tracking-widest">Performance Breakdown</p>
            </div>
          </div>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white transition">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="overflow-y-auto px-6 py-5 space-y-5 flex-1">

          {/* XP + report status */}
          <div className="grid grid-cols-2 gap-3">
            <MetricTile
              label="XP Earned"
              value={`+${record.xpEarned}`}
              color="cyber"
              icon={<Zap className="h-4 w-4" />}
            />
            <MetricTile
              label="Incident Report"
              value={reportPassed ? "Passed" : "Not yet"}
              color={reportPassed ? "green" : "amber"}
              icon={<FileText className="h-4 w-4" />}
            />
          </div>

          {/* Company objectives checklist */}
          {objectives && objectives.length > 0 && (
            <div className="rounded-lg border border-border/60 bg-bg/50 p-4">
              <p className="mb-3 text-[10px] font-bold uppercase tracking-widest text-slate-500">Company Objectives</p>
              <div className="space-y-2">
                {objectives.map((obj, i) => (
                  <div key={i} className="flex items-center gap-2.5">
                    {obj.met ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-neon-green" />
                    ) : (
                      <XCircle className="h-4 w-4 shrink-0 text-severity-critical" />
                    )}
                    <span className={cn("text-xs", obj.met ? "text-slate-200" : "text-slate-400")}>
                      {obj.label}
                    </span>
                    <span className={cn(
                      "ml-auto text-[10px] font-bold uppercase tracking-wider",
                      obj.met ? "text-neon-green" : "text-severity-critical"
                    )}>
                      {obj.met ? "Done" : "Not met"}
                    </span>
                  </div>
                ))}
              </div>
              {!canClearCompany && objectives.some(o => !o.met) && (
                <p className="mt-3 text-[10px] text-slate-500 leading-relaxed">
                  Complete all objectives to secure this company and unlock the next one.
                </p>
              )}
            </div>
          )}

          {/* Coaching tip */}
          <div className="rounded-lg border border-neon-amber/20 bg-neon-amber/5 px-4 py-3">
            <p className="text-[10px] font-bold uppercase tracking-wider text-neon-amber mb-1">Analyst Tip</p>
            {reportPassed ? (
              <p className="text-xs text-slate-300 leading-relaxed">
                Strong session — your report identified the attack and held up against the evidence in the logs.
                Keep practicing to build speed reading unfamiliar log sources.
              </p>
            ) : (
              <p className="text-xs text-slate-300 leading-relaxed">
                Not there yet. Before you resubmit: re-read the logs for the exact attack technique, quote real
                IP/user/host values you actually saw (never invent one), and state a concrete response action
                and business impact.
              </p>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex flex-col gap-3 border-t border-border px-6 py-4 shrink-0">
          {canClearCompany && onClearCompany && (
            <button
              onClick={onClearCompany}
              className="flex w-full items-center justify-center gap-2 rounded-lg border border-neon-green/40 bg-neon-green/10 px-5 py-2.5 text-sm font-bold text-neon-green hover:bg-neon-green/20 transition"
            >
              <Shield className="h-4 w-4" />
              Secure This Company{nextCompanyName ? ` — Unlock ${nextCompanyName}` : ""}
            </button>
          )}
          <button
            onClick={onClose}
            className="rounded-lg bg-cyber-500 px-5 py-2 text-sm font-bold text-bg hover:bg-cyber-400 transition"
          >
            Continue Training
          </button>
        </div>
      </div>
    </div>
  );
}

function MetricTile({ label, value, color, icon }: {
  label: string; value: string;
  color: "cyber" | "green" | "amber" | "purple" | "critical";
  icon: React.ReactNode;
}) {
  const colorMap: Record<string, string> = {
    cyber:    "border-cyber-500/30 bg-cyber-500/8 text-cyber-300",
    green:    "border-neon-green/30 bg-neon-green/8 text-neon-green",
    amber:    "border-severity-medium/30 bg-severity-medium/8 text-severity-medium",
    purple:   "border-neon-purple/30 bg-neon-purple/8 text-neon-purple",
    critical: "border-severity-critical/30 bg-severity-critical/8 text-severity-critical",
  };
  return (
    <div className={cn("rounded-lg border p-3 flex flex-col gap-1", colorMap[color])}>
      <div className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
        {icon}
        {label}
      </div>
      <p className="font-mono text-xl font-bold">{value}</p>
    </div>
  );
}
