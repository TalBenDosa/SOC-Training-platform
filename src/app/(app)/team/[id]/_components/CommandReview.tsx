"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Gavel, AlertOctagon } from "lucide-react";
import type { ManagerReview, CommandPillar, DecisionRow, TimelineMark } from "@/lib/team/report/managerReview";

/**
 * Command Review: the SOC Manager's end-of-shift report (PLAN §10א). The manager and staff
 * see it whole; the rest of the team gets the command timeline and what was decided, no grades.
 */

const RANK_STYLE: Record<string, string> = {
  great: "border-neon-green/50 bg-neon-green/10 text-neon-green",
  good: "border-cyber-500/50 bg-cyber-500/10 text-cyber-200",
  okay: "border-neon-amber/50 bg-neon-amber/10 text-neon-amber",
  weak: "border-severity-critical/50 bg-severity-critical/10 text-severity-critical",
};
const RANK_LABEL: Record<string, string> = { great: "Best", good: "Good", okay: "Acceptable", weak: "Weak" };
const LEVEL_TONE: Record<string, string> = { command_ready: "text-neon-green", proficient: "text-cyber-200", developing: "text-neon-amber", needs_coaching: "text-severity-critical" };
const LANE_LABEL: Record<TimelineMark["lane"], string> = { attacker: "Attacker", manager: "You", pressure: "Pressure" };
const IND_LABEL = { continuity: "Business continuity", trust: "Stakeholder trust", capacity: "Team capacity", regulatory: "Regulatory exposure" } as const;
const fmt = (s: number | null) => (s == null ? "-" : `${Math.floor(s / 60)}:${String(Math.round(s) % 60).padStart(2, "0")}`);

export function CommandReview({ review, xp }: { review: ManagerReview; xp?: number }) {
  const r = review;
  return (
    <Card className="border-neon-purple/40">
      <div className="flex flex-wrap items-baseline gap-2">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Gavel className="h-4 w-4 text-neon-purple" aria-hidden /> Command Review</h3>
        <span className="text-[11px] text-slate-400"><bdi>{r.managerName}</bdi> · SOC Manager</span>
        {typeof xp === "number" && <span className="ml-auto rounded border border-neon-green/40 bg-neon-green/10 px-1.5 py-0.5 font-mono text-[10px] font-bold text-neon-green" title="XP added to the account for this shift">+{xp} XP</span>}
      </div>
      {r.redacted ? (
        <p className="mt-1 text-[11px] text-slate-400">How the incident was commanded: what the attacker did, what the manager decided, and the pressure from outside. The manager&apos;s grades are theirs to share.</p>
      ) : (
        <Headline r={r} />
      )}
      {r.criticalErrors.length > 0 && (
        <div className="mt-3 space-y-1.5 rounded-lg border border-severity-critical/50 bg-severity-critical/10 p-2.5">
          {r.criticalErrors.map((c, i) => (
            <p key={i} className="flex gap-2 text-xs text-slate-200"><AlertOctagon className="mt-0.5 h-3.5 w-3.5 shrink-0 text-severity-critical" aria-hidden />
              <span><b className="text-severity-critical">{c.label}</b>{c.atS != null && <span className="font-mono text-[10px] text-slate-400"> at {fmt(c.atS)}</span>}. {c.detail}</span></p>
          ))}
          <p className="text-[10px] text-slate-400">A critical error caps the score at 69: in a real organisation it alone would do serious damage.</p>
        </div>
      )}
      <Timeline marks={r.timeline} endS={r.endS} gaps={r.gaps} />
      {r.decisions.length > 0 && <Decisions rows={r.decisions} redacted={!!r.redacted} />}
      {!r.redacted && <Calibration r={r} />}
      {!r.redacted && (r.profile.length > 0 || r.keep.length > 0 || r.improve.length > 0) && (
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          {r.profile.length > 0 && (
            <div className="sm:col-span-2">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Leadership profile</p>
              <div className="mt-1 flex flex-wrap gap-1.5">
                {r.profile.map(p => <span key={p.style} title={p.evidence} className="rounded border border-neon-purple/40 bg-neon-purple/10 px-2 py-0.5 text-[11px] text-slate-100">{p.style} <span className="text-slate-400">· {p.evidence}</span></span>)}
              </div>
            </div>
          )}
          {r.keep.length > 0 && <List title="Keep doing" items={r.keep} tone="text-neon-green" />}
          {r.improve.length > 0 && <List title="Work on" items={r.improve} tone="text-neon-amber" />}
        </div>
      )}
      {r.debrief.length > 0 && (
        <div className="mt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Questions for the team debrief</p>
          <ol className="mt-1 list-decimal space-y-0.5 pl-4 text-xs text-slate-300">{r.debrief.map((q, i) => <li key={i}>{q}</li>)}</ol>
        </div>
      )}
    </Card>
  );
}

function Headline({ r }: { r: ManagerReview }) {
  return (
    <>
      <div className="mt-2 flex flex-wrap items-end gap-3">
        <span className={`font-mono text-3xl font-bold ${LEVEL_TONE[r.level ?? ""] ?? "text-slate-300"}`}>{r.score ?? "-"}</span>
        <span className={`pb-1 text-sm font-semibold ${LEVEL_TONE[r.level ?? ""] ?? "text-slate-400"}`}>{r.levelLabel}</span>
        {r.uncappedScore != null && r.score != null && r.uncappedScore > r.score && <span className="pb-1 text-[11px] text-slate-400">({r.uncappedScore} before the critical-error cap)</span>}
        {r.declared && <span className="ml-auto pb-1 text-[11px] text-slate-400">Declared Sev-{r.declared.severity} at {fmt(r.declared.atS)}{r.truthSeverity && <> · the incident was Sev-{r.truthSeverity}</>}</span>}
      </div>
      <p className="mt-1 text-[10px] text-slate-500">85% how you commanded (team &amp; incident 35, stakeholders 25, reporting 25) + 15% the team&apos;s outcome. Decisions are judged on what was visible when they were made.</p>
      <div className="mt-3 grid gap-2 sm:grid-cols-2">{r.pillars.map(p => <Pillar key={p.key} p={p} />)}</div>
    </>
  );
}

function Pillar({ p }: { p: CommandPillar }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-border bg-bg px-2.5 py-2">
      <button type="button" onClick={() => setOpen(o => !o)} aria-expanded={open} className="flex w-full items-center gap-2 text-left">
        <span className="flex-1 text-xs font-semibold text-slate-200">{p.label} <span className="font-normal text-slate-500">{Math.round(p.weight * 100)}%</span></span>
        <span className="font-mono text-sm font-bold text-slate-100">{p.score ?? "-"}</span>
      </button>
      <div className="mt-1 h-1.5 w-full rounded bg-slate-700" aria-hidden><div className="h-1.5 rounded bg-neon-purple" style={{ width: `${p.score ?? 0}%` }} /></div>
      {p.score == null && <p className="mt-1 text-[10px] text-slate-500">Not enough evidence to score this part.</p>}
      {open && (
        <ul className="mt-2 space-y-1">
          {p.cells.map(c => (
            <li key={c.label} className="flex items-start gap-2 text-[11px]">
              <span className={`w-6 shrink-0 text-right font-mono ${c.score == null ? "text-slate-600" : c.score >= 8 ? "text-neon-green" : c.score >= 4 ? "text-neon-amber" : "text-severity-critical"}`}>{c.score ?? "-"}</span>
              <span className="text-slate-300">{c.label}{c.note && <span className="text-slate-500"> · {c.note}</span>}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Timeline({ marks, endS, gaps }: { marks: TimelineMark[]; endS: number; gaps: string[] }) {
  if (!marks.length) return null;
  const span = Math.max(endS, ...marks.map(m => m.t), 60);
  const lanes: TimelineMark["lane"][] = ["attacker", "manager", "pressure"];
  return (
    <div className="mt-4">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Command timeline</p>
      <div className="mt-1.5 space-y-1.5">
        {lanes.map(l => (
          <div key={l} className="flex items-center gap-2">
            <span className="w-16 shrink-0 text-[10px] text-slate-400">{LANE_LABEL[l]}</span>
            <div className="relative h-5 flex-1 rounded bg-bg-elevated">
              {marks.filter(m => m.lane === l).map((m, i) => (
                <span key={i} title={`${fmt(m.t)} · ${m.label}`} style={{ left: `calc(${(m.t / span) * 100}% - 4px)` }}
                  className={`absolute top-1.5 h-2 w-2 rounded-full ${m.tone === "good" ? "bg-neon-green" : m.tone === "bad" ? "bg-severity-critical" : l === "attacker" ? "bg-severity-high" : l === "pressure" ? "bg-neon-purple" : "bg-cyber-300"}`} />
              ))}
            </div>
          </div>
        ))}
        <div className="flex justify-between pl-[4.5rem] font-mono text-[9px] text-slate-500"><span>0:00</span><span>{fmt(span)}</span></div>
      </div>
      <details className="mt-1">
        <summary className="cursor-pointer text-[10px] text-cyber-300">Every moment ({marks.length})</summary>
        <ul className="mt-1 max-h-48 space-y-0.5 overflow-y-auto text-[11px]">
          {marks.map((m, i) => <li key={i} className="text-slate-300"><span className="font-mono text-slate-500">{fmt(m.t)}</span> <span className="text-slate-400">{LANE_LABEL[m.lane]}:</span> {m.label}</li>)}
        </ul>
      </details>
      {gaps.length > 0 && <ul className="mt-1.5 space-y-0.5">{gaps.map((g, i) => <li key={i} className="text-[11px] text-neon-amber">Gap: {g}</li>)}</ul>}
    </div>
  );
}

function Decisions({ rows, redacted }: { rows: DecisionRow[]; redacted: boolean }) {
  return (
    <div className="mt-4">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Decisions ({rows.length})</p>
      <div className="mt-1.5 space-y-1.5">
        {rows.map(d => (
          <details key={d.injectId} className="rounded-lg border border-border bg-bg px-2.5 py-1.5 text-xs">
            <summary className="flex cursor-pointer flex-wrap items-center gap-2">
              <span className="font-mono text-[10px] text-slate-500">{fmt(d.firedS)}</span>
              <span className="font-semibold text-slate-200"><bdi>{d.from.name}</bdi> <span className="font-normal text-slate-500">{d.from.role}</span></span>
              <span className="min-w-0 flex-1 truncate text-slate-400"><bdi>{d.text}</bdi></span>
              {d.state === "expired" ? <span className="rounded border border-severity-critical/40 px-1.5 text-[10px] text-severity-critical">no decision</span>
                : !redacted && d.rank ? <span className={`rounded border px-1.5 text-[10px] ${RANK_STYLE[d.rank]}`}>{RANK_LABEL[d.rank]} · {d.score}/12</span> : null}
              {d.state === "late" && <span className="text-[10px] text-neon-amber">late</span>}
            </summary>
            <div className="mt-1.5 space-y-1 border-t border-border/60 pt-1.5">
              <p className="text-slate-300"><bdi>{d.text}</bdi></p>
              {d.optionLabel ? <p className="text-slate-300">Chosen{!redacted && d.confidence ? ` (${d.confidence} confidence)` : ""}{d.decidedInS != null ? ` in ${fmt(d.decidedInS)}` : ""}: <b className="text-slate-100">{d.optionLabel}</b></p>
                : <p className="text-severity-critical">Nobody decided before the deadline.</p>}
              {d.rationale && <p className="text-[11px] text-slate-400">Why: {d.rationale}</p>}
              <ul className="space-y-0.5">
                {d.options.map(o => (
                  <li key={o.id} className={`rounded px-1.5 py-1 text-[11px] ${o.id === d.option ? "bg-bg-elevated" : ""}`}>
                    {!redacted && o.rank && <span className={`mr-1 rounded border px-1 text-[9px] ${RANK_STYLE[o.rank]}`}>{RANK_LABEL[o.rank]}</span>}
                    <span className="text-slate-200">{o.label}</span>
                    {o.note && <span className="text-slate-500"> {o.note}</span>}
                  </li>
                ))}
              </ul>
              {d.objective && <p className="text-[10px] text-slate-500">What this tests: {d.objective}</p>}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

function Calibration({ r }: { r: ManagerReview }) {
  const { grid, highTotal, highGreat, calibrated } = r.calibration;
  const any = Object.values(grid).some(row => row.low + row.medium + row.high > 0);
  return (
    <div className="mt-4 grid gap-3 sm:grid-cols-2">
      {any && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Confidence calibration</p>
          <table className="mt-1 w-full text-center text-[11px]">
            <thead><tr className="text-slate-500"><th className="text-left font-normal">Call</th><th className="font-normal">Low</th><th className="font-normal">Medium</th><th className="font-normal">High</th></tr></thead>
            <tbody>
              {(["great", "good", "okay", "weak"] as const).map(k => (
                <tr key={k}>
                  <td className="text-left text-slate-300">{RANK_LABEL[k]}</td>
                  {(["low", "medium", "high"] as const).map(c => (
                    <td key={c} className={`font-mono ${grid[k][c] && k === "weak" && c === "high" ? "font-bold text-severity-critical" : grid[k][c] ? "text-slate-100" : "text-slate-600"}`}>{grid[k][c]}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          {highTotal > 0 && <p className="mt-1 text-[11px] text-slate-400">{highGreat} of {highTotal} high-confidence calls were the best option{calibrated === true ? ": well calibrated." : calibrated === false ? ": overconfident." : "."}</p>}
        </div>
      )}
      {r.decisions.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Impact at the end</p>
          <div className="mt-1 space-y-1">
            {(Object.keys(IND_LABEL) as (keyof typeof IND_LABEL)[]).map(k => (
              <div key={k} className="flex items-center gap-2 text-[11px]">
                <span className="w-32 shrink-0 text-slate-400">{IND_LABEL[k]}</span>
                <span className="flex gap-0.5" aria-label={`${r.indicators[k]} of 5`}>{[0, 1, 2, 3, 4].map(i => <span key={i} className={`h-2 w-4 rounded-sm ${i < r.indicators[k] ? (r.indicators[k] <= 1 ? "bg-severity-critical" : r.indicators[k] <= 2 ? "bg-neon-amber" : "bg-neon-green") : "bg-slate-700"}`} />)}</span>
                <span className="font-mono text-slate-300">{r.indicators[k]}/5</span>
              </div>
            ))}
          </div>
          <p className="mt-1 text-[10px] text-slate-500">Each starts at 3; every decision (or silence) moved them.</p>
        </div>
      )}
    </div>
  );
}

function List({ title, items, tone }: { title: string; items: string[]; tone: string }) {
  return (
    <div>
      <p className={`text-[11px] font-semibold uppercase tracking-wider ${tone}`}>{title}</p>
      <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-slate-300">{items.map((x, i) => <li key={i}>{x}</li>)}</ul>
    </div>
  );
}
