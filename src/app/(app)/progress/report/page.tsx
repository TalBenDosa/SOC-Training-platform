"use client";
/**
 * Printable personal progress report for a period (7 / 30 / 90 days): output, mastery per
 * topic, missed attacks, response times against target, report quality and next steps.
 * The learner prints it or saves it as PDF from the browser and shares it themselves.
 * Same data as /progress (the learner's own rows in their current organisation), never
 * any right answers.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { Printer, ArrowLeft, Loader2 } from "lucide-react";
import type { ProgressPayload } from "@/lib/progress/selfView";
import { fmtDate, fmtMinutes, fmtMs, LEVEL_STYLE } from "@/components/progress/format";
import { cn } from "@/lib/utils";

const PERIODS = [7, 30, 90] as const;

export default function ProgressReportPage() {
  const [days, setDays] = useState<(typeof PERIODS)[number]>(30);
  const [data, setData] = useState<ProgressPayload | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null); setErr(null);
    fetch(`/api/me/progress?days=${days}`, { cache: "no-store" })
      .then(async r => { const b = await r.json().catch(() => ({})); if (!r.ok) throw new Error(b.error ?? "Couldn't load your progress."); return b; })
      .then(b => { if (alive) setData(b as ProgressPayload); })
      .catch(e => { if (alive) setErr(e instanceof Error ? e.message : "Couldn't load your progress."); });
    return () => { alive = false; };
  }, [days]);

  const from = Date.now() - days * 86_400_000;
  const inPeriod = (iso: string | null) => !!iso && Date.parse(iso) >= from;

  return (
    <div className="progress-report min-h-screen bg-bg px-4 pb-16 pt-6 text-slate-200 sm:px-8 print:bg-white print:p-0 print:text-black">
      <style>{`@media print { .no-print { display: none !important; } .progress-report * { color: #111 !important; border-color: #bbb !important; background: transparent !important; box-shadow: none !important; } @page { margin: 14mm; } }`}</style>
      <div className="mx-auto max-w-3xl">
        <div className="no-print mb-6 flex flex-wrap items-center gap-3">
          <Link href="/progress?tab=reports" className="inline-flex items-center gap-1.5 text-xs font-semibold text-cyber-300"><ArrowLeft aria-hidden="true" className="h-3.5 w-3.5" /> Back to My Progress</Link>
          <div role="group" aria-label="Period" className="ml-auto flex gap-1">
            {PERIODS.map(p => (
              <button key={p} type="button" aria-pressed={days === p} onClick={() => setDays(p)}
                className={cn("rounded-md border px-2.5 py-1 text-xs font-semibold", days === p ? "border-cyber-500/60 bg-cyber-500/15 text-cyber-300" : "border-border text-slate-300")}>
                {p} days
              </button>
            ))}
          </div>
          <button type="button" onClick={() => window.print()} disabled={!data}
            className="inline-flex items-center gap-1.5 rounded-md border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-xs font-semibold text-cyber-300 disabled:opacity-50">
            <Printer aria-hidden="true" className="h-3.5 w-3.5" /> Print or save as PDF
          </button>
        </div>

        <header className="border-b border-border pb-3">
          <h1 className="text-xl font-bold text-white">Personal progress report</h1>
          <p className="text-sm text-slate-400">The last {days} days, up to {fmtDate(new Date().toISOString())}</p>
        </header>

        {err && <p role="alert" className="mt-4 text-sm text-severity-high">{err}</p>}
        {!data && !err && <p className="mt-6 flex items-center gap-2 text-sm text-slate-400"><Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" /> Building your report…</p>}

        {data && (
          <div className="mt-5 space-y-6 text-sm">
            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Summary</h2>
              <ul className="mt-2 space-y-1">{data.overview.sentences.map(s => <li key={s}>{s}</li>)}</ul>
              <dl className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Fact label="Completed" value={String(data.overview.tiles.done.now)} />
                <Fact label="Right first try" value={data.overview.tiles.firstTry.now === null ? "–" : `${data.overview.tiles.firstTry.now}%`} />
                <Fact label="Missed attacks" value={String(data.overview.tiles.missed.now)} />
                <Fact label="Active time" value={fmtMinutes(Math.round(data.activity.weeks.filter(w => Date.parse(w.start) + 7 * 86_400_000 >= from).reduce((s, w) => s + w.minutes, 0)))} />
              </dl>
            </section>

            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Mastery by topic (all time, right first try)</h2>
              <table className="mt-2 w-full text-[13px]">
                <tbody>
                  {data.skills.areas.filter(a => a.items > 0).map(a => (
                    <tr key={a.area} className="border-t border-border/60">
                      <td className="py-1.5 pr-2">{a.label}</td>
                      <td className="py-1.5 pr-2 font-mono tabular-nums">{a.accuracy ?? "–"}%</td>
                      <td className="py-1.5 pr-2 text-slate-400">{a.items} questions</td>
                      <td className="py-1.5">{LEVEL_STYLE[a.level].label}{a.trend ? ` (${a.trend.prev}% → ${a.trend.now}%)` : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>

            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Missed attacks in this period</h2>
              {data.criticalMisses.filter(m => inPeriod(m.at)).length === 0 ? <p className="mt-2 text-slate-400">None.</p> : (
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {data.criticalMisses.filter(m => inPeriod(m.at)).map((m, i) => <li key={m.title + i}>{m.title} ({m.source === "live" ? "live feed" : "team exercise"}, {fmtDate(m.at)}){m.practice ? `. Practice: ${m.practice.title}` : ""}</li>)}
                </ul>
              )}
            </section>

            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Response times (all time)</h2>
              <ul className="mt-2 space-y-1">
                {data.response.live.source !== "none" && <li>Live feed, total response: median {fmtMs(data.response.live.total.median)}, {data.response.live.total.withinTarget ?? "–"}% within the 15-minute target.</li>}
                {data.response.rooms.count > 0 && <li>Room questions: median decision {fmtMs(data.response.rooms.median)}, {data.response.rooms.accuracy ?? "–"}% right first try.</li>}
                {data.response.scenarios.count > 0 && <li>Scenarios: median {fmtMs(data.response.scenarios.median)} to finish.</li>}
                {data.response.team.slaTotal > 0 && <li>Team exercises: SLA met on {data.response.team.slaMet} of {data.response.team.slaTotal} logs.</li>}
              </ul>
            </section>

            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Report quality</h2>
              {data.reports.quality.points.length === 0 ? <p className="mt-2 text-slate-400">No graded reports yet.</p> : (
                <>
                  <p className="mt-2">Average over the last {Math.min(10, data.reports.quality.points.length)} reports: identification {avgOf(data, "identification")}%, evidence {avgOf(data, "evidence")}%, depth and reasoning {avgOf(data, "depth")}%.</p>
                  {data.reports.quality.weakest && <p className="mt-1">Focus: {data.reports.quality.weakest.advice}</p>}
                </>
              )}
            </section>

            <section>
              <h2 className="text-xs font-bold uppercase tracking-widest text-slate-400">Next steps</h2>
              <ol className="mt-2 list-decimal space-y-1 pl-5">{data.overview.next.map(n => <li key={n.label}>{n.label}: {n.detail}</li>)}</ol>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border px-3 py-2">
      <dt className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{label}</dt>
      <dd className="font-mono text-lg tabular-nums">{value}</dd>
    </div>
  );
}

function avgOf(d: ProgressPayload, k: "identification" | "evidence" | "depth"): number {
  const pts = d.reports.quality.points.slice(-10);
  return pts.length ? Math.round(pts.reduce((s, p) => s + p[k], 0) / pts.length) : 0;
}
