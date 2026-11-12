"use client";
import { useRef } from "react";
import { CheckCircle2, ClipboardList, Clock, Printer, RefreshCw, Target, TrendingUp, X } from "lucide-react";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { formatDuration, SESSION_LIMIT_MS, type Metric, type SessionReport } from "@/lib/dashboard/sessionReport";

interface Props {
  report: SessionReport;
  companyName: string;
  onClose: () => void;
  /** Start another 30-minute training on the same company and level. */
  onNewTraining?: () => void;
}

const BAND: Record<SessionReport["band"], { label: string; tone: string }> = {
  excellent: { label: "Excellent", tone: "text-neon-green border-neon-green/40 bg-neon-green/10" },
  good: { label: "Good", tone: "text-cyber-300 border-cyber-500/40 bg-cyber-500/10" },
  developing: { label: "Developing", tone: "text-neon-amber border-neon-amber/40 bg-neon-amber/10" },
  needs_work: { label: "Needs work", tone: "text-severity-critical border-severity-critical/40 bg-severity-critical/10" },
  not_enough_data: { label: "Not enough to grade", tone: "text-slate-300 border-border bg-white/5" },
};
const STATUS: Record<Metric["status"], { label: string; tone: string; bar: string }> = {
  met: { label: "Target met", tone: "text-neon-green", bar: "bg-neon-green" },
  close: { label: "Close", tone: "text-cyber-300", bar: "bg-cyber-500" },
  below: { label: "Below target", tone: "text-neon-amber", bar: "bg-neon-amber" },
  na: { label: "Not measured", tone: "text-slate-400", bar: "bg-slate-600" },
};
const ENDED: Record<SessionReport["facts"]["endedBy"], string> = {
  time: "The 30-minute training time ended.",
  secured: "You secured the company.",
  manual: "You ended the training.",
};

/** The end-of-training report: success metrics against their targets and where to improve. */
export function SessionReportModal({ report, companyName, onClose, onNewTraining }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, dialogRef);
  const band = BAND[report.band];
  const f = report.facts;
  const date = new Date(f.endedAt).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-black/85 p-4 backdrop-blur-md print:static print:bg-white print:p-0">
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-labelledby="session-report-title" tabIndex={-1}
        className="my-6 w-full max-w-3xl rounded-2xl border border-border bg-bg-elevated shadow-2xl print:my-0 print:border-0 print:shadow-none">
        <div className="flex items-start justify-between gap-4 border-b border-border p-6">
          <div className="min-w-0">
            <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.2em] text-cyber-300">
              <ClipboardList className="h-3.5 w-3.5" /> Training report
            </p>
            <h2 id="session-report-title" className="mt-1 text-xl font-bold text-white">{companyName} · {f.difficulty ?? "training"} shift</h2>
            <p className="mt-1 text-xs text-slate-400">
              {date} · {formatDuration(report.durationMs)} of {formatDuration(SESSION_LIMIT_MS)} · {ENDED[f.endedBy]}
            </p>
          </div>
          <button type="button" onClick={onClose} aria-label="Close the training report" className="rounded-md p-1.5 text-slate-400 hover:bg-white/5 hover:text-white print:hidden">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="space-y-6 p-6">
          {/* Overall */}
          <section className="flex flex-wrap items-center gap-4">
            <div className={`flex items-baseline gap-2 rounded-xl border px-5 py-3 ${band.tone}`}>
              <span className="font-mono text-4xl font-bold leading-none">{report.overall ?? "-"}</span>
              {report.overall !== null && <span className="text-sm font-semibold opacity-80">/100</span>}
            </div>
            <div className="min-w-0 flex-1">
              <p className={`text-sm font-bold ${band.tone.split(" ")[0]}`}>{band.label}</p>
              <p className="mt-0.5 text-xs leading-relaxed text-slate-400">
                {report.overall === null
                  ? "No attack reached your feed and no report was graded, so there is nothing to score yet. Start a new training and investigate the first alert you see."
                  : "Your score combines how many attacks you caught, how good your reports were, and how fast you found and closed them, each against the target for a Tier-1 analyst."}
              </p>
              <p className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
                <span>Attacks in the feed: <b className="text-slate-200">{f.presented}</b></span>
                <span>Caught: <b className="text-slate-200">{f.caught}</b></span>
                <span>Rows opened: <b className="text-slate-200">{f.eventsOpened}</b></span>
                <span>EDR investigations: <b className="text-slate-200">{f.edrInvestigations}</b></span>
                <span>Session XP: <b className="text-slate-200">{f.xp}</b></span>
              </p>
            </div>
          </section>

          {/* Where to improve */}
          <section aria-labelledby="improve-title">
            <h3 id="improve-title" className="flex items-center gap-1.5 text-sm font-bold text-white"><TrendingUp className="h-4 w-4 text-neon-amber" /> Where to improve</h3>
            {report.improvements.length === 0 ? (
              <p className="mt-2 rounded-lg border border-neon-green/30 bg-neon-green/5 px-4 py-3 text-xs text-slate-300">
                {report.overall === null ? "Nothing measured this time." : "Every measured target was met. Next time, try a harder level or the next company."}
              </p>
            ) : (
              <ol className="mt-2 space-y-3">
                {report.improvements.map((imp, i) => (
                  <li key={`${imp.metric}-${i}`} className="rounded-lg border border-neon-amber/30 bg-neon-amber/5 px-4 py-3">
                    <p className="text-sm font-semibold text-white">{i + 1}. {imp.title}</p>
                    <p className="mt-0.5 text-xs text-slate-400">{imp.why}</p>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-relaxed text-slate-300">
                      {imp.how.map(h => <li key={h}>{h}</li>)}
                    </ul>
                  </li>
                ))}
              </ol>
            )}
          </section>

          {/* Metrics */}
          <section aria-labelledby="metrics-title">
            <h3 id="metrics-title" className="flex items-center gap-1.5 text-sm font-bold text-white"><Target className="h-4 w-4 text-cyber-300" /> Success metrics</h3>
            <div className="mt-2 grid gap-2 sm:grid-cols-2">
              {report.metrics.map(m => {
                const st = STATUS[m.status];
                return (
                  <div key={m.id} className="rounded-lg border border-border bg-bg/60 px-3.5 py-3">
                    <div className="flex items-baseline justify-between gap-2">
                      <p className="text-xs font-semibold text-slate-200">{m.label}</p>
                      <p className={`text-[10px] font-bold uppercase tracking-wider ${st.tone}`}>{st.label}</p>
                    </div>
                    <p className="mt-1 font-mono text-lg font-bold tabular-nums text-white">{m.value}</p>
                    <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/10" aria-hidden="true">
                      <div className={`h-full ${st.bar}`} style={{ width: `${Math.round((m.progress ?? 0) * 100)}%` }} />
                    </div>
                    <p className="mt-1.5 text-[11px] text-slate-400">Target: {m.target}. {m.explain}</p>
                  </div>
                );
              })}
            </div>
          </section>

          {/* Strengths */}
          {report.strengths.length > 0 && (
            <section aria-labelledby="strengths-title">
              <h3 id="strengths-title" className="flex items-center gap-1.5 text-sm font-bold text-white"><CheckCircle2 className="h-4 w-4 text-neon-green" /> What went well</h3>
              <ul className="mt-2 space-y-1 text-xs text-slate-300">
                {report.strengths.map(s => <li key={s} className="flex gap-2"><span className="text-neon-green" aria-hidden="true">+</span>{s}</li>)}
              </ul>
            </section>
          )}

          {/* Incidents */}
          {(f.reports.length > 0 || f.missed.length > 0) && (
            <section aria-labelledby="incidents-title">
              <h3 id="incidents-title" className="flex items-center gap-1.5 text-sm font-bold text-white"><Clock className="h-4 w-4 text-slate-300" /> Incidents this shift</h3>
              <div className="mt-2 overflow-x-auto rounded-lg border border-border">
                <table className="w-full text-left text-xs">
                  <thead className="bg-white/5 text-[10px] uppercase tracking-wider text-slate-400">
                    <tr><th className="px-3 py-2 font-semibold">Incident</th><th className="px-3 py-2 font-semibold">Result</th><th className="px-3 py-2 font-semibold">Report</th><th className="px-3 py-2 font-semibold">Evidence</th></tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {f.reports.map((r, i) => (
                      <tr key={`${r.incidentId}-${i}`}>
                        <td className="px-3 py-2 text-slate-200">{r.title}</td>
                        <td className={`px-3 py-2 font-semibold ${r.passed ? "text-neon-green" : "text-neon-amber"}`}>{r.passed ? "Passed" : "Not passed"}</td>
                        <td className="px-3 py-2 font-mono tabular-nums text-slate-200">{r.score}/100</td>
                        <td className="px-3 py-2 font-mono tabular-nums text-slate-300">{r.subScores ? `${r.subScores.ioc}/30` : "-"}</td>
                      </tr>
                    ))}
                    {f.missed.map((m, i) => (
                      <tr key={`missed-${i}`}>
                        <td className="px-3 py-2 text-slate-200">{m.title}</td>
                        <td className="px-3 py-2 font-semibold text-severity-critical">Missed</td>
                        <td className="px-3 py-2 text-slate-400" colSpan={2}>{m.tell}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>

        <div className="flex flex-wrap justify-end gap-2 border-t border-border p-4 print:hidden">
          <button type="button" onClick={() => window.print()} className="flex items-center gap-1.5 rounded-md border border-border px-3 py-2 text-xs font-semibold text-slate-300 transition hover:bg-white/5">
            <Printer className="h-3.5 w-3.5" /> Print or save as PDF
          </button>
          {onNewTraining && (
            <button type="button" onClick={onNewTraining} className="flex items-center gap-1.5 rounded-md border border-cyber-500/40 px-3 py-2 text-xs font-semibold text-cyber-300 transition hover:bg-cyber-500/10">
              <RefreshCw className="h-3.5 w-3.5" /> New 30-minute training
            </button>
          )}
          <button type="button" onClick={onClose} className="rounded-md bg-neon-green px-4 py-2 text-xs font-bold text-bg transition hover:bg-neon-green/90">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
