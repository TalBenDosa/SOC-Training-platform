"use client";
import React, { useMemo, useState } from "react";
import { Check, Lightbulb, Search, FileText } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";

// Field read (SPEC-field-labs.md): a raw artifact in its native format, and objectives answered
// from it the way an analyst works a log. Filter, tap the line, copy a value, count. No timer and
// no lives: a wrong line says what that line actually is, so the miss teaches. Teaches, awards nothing.

type ReaderLabDef = Extract<BriefingLab, { kind: "reader" }>;

const normValue = (s: string) => {
  const t = s.trim().toLowerCase().replace(/\s+/g, " ");
  const n = t.replace(/,/g, "");
  return /^-?\d+(\.\d+)?$/.test(n) ? String(Number(n)) : t;
};

export function ReaderLab({ lab, onDone }: { lab: ReaderLabDef; onDone: () => void }) {
  const [current, setCurrent] = useState(0);
  const [solved, setSolved] = useState<string[]>([]);
  const [filter, setFilter] = useState("");
  const [picked, setPicked] = useState<number | null>(null);
  const [typed, setTyped] = useState("");
  const [miss, setMiss] = useState<string | null>(null);
  const [hint, setHint] = useState(false);
  const [fired, setFired] = useState(false);

  const obj = lab.objectives[current];
  const done = solved.length === lab.objectives.length;
  // Lines already proven by a solved "line" objective stay marked, the analyst's highlights.
  const marked = useMemo(() => new Set(lab.objectives.filter(o => solved.includes(o.id) && o.type === "line").flatMap(o => (o.type === "line" ? o.answer : []))), [lab.objectives, solved]);
  const shown = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return lab.lines.map((text, i) => ({ text, i })).filter(l => !f || l.text.toLowerCase().includes(f));
  }, [lab.lines, filter]);

  function solve() {
    const next = [...solved, obj.id];
    setSolved(next);
    setMiss(null); setHint(false); setPicked(null); setTyped("");
    if (current + 1 < lab.objectives.length) setCurrent(current + 1);
    if (next.length === lab.objectives.length && !fired) { setFired(true); onDone(); }
  }

  function check() {
    if (!obj || done) return;
    if (obj.type === "line") {
      if (picked === null) { setMiss("Tap a line in the log first."); return; }
      if (obj.answer.includes(picked)) return solve();
      setMiss(lab.notes?.[picked] ?? `Line ${picked + 1} does not answer this. Read its fields again against the task.`);
      return;
    }
    const v = normValue(typed);
    if (!v) { setMiss("Type your answer first."); return; }
    if (obj.type === "value") {
      if (obj.answer.some(a => normValue(a) === v)) return solve();
      const inArtifact = [...(lab.header ?? []), ...lab.lines].some(l => l.toLowerCase().includes(typed.trim().toLowerCase()));
      setMiss(inArtifact ? "That text is in the log, but it is not the value this task asks for." : "That text does not appear in the log. Copy the value from the line itself.");
      return;
    }
    if (Number(v) === obj.answer) return solve();
    setMiss(`Not ${typed.trim()}. Filter the log on what the task describes and count the lines again.`);
  }

  return (
    <div className="space-y-4">
      {/* The artifact */}
      <div className="overflow-hidden rounded-xl border border-white/10 bg-[#05080e]">
        <div className="flex flex-wrap items-center gap-2 border-b border-white/10 bg-[#0e1524] px-3 py-2">
          <FileText className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden />
          <p className="min-w-0 flex-1 truncate font-mono text-[11px] font-semibold text-slate-300">{lab.source}</p>
          <label className="relative flex items-center">
            <Search className="pointer-events-none absolute left-2 h-3.5 w-3.5 text-slate-500" aria-hidden />
            <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter lines"
              aria-label="Filter the log lines"
              className="w-40 rounded-md border border-white/15 bg-black/40 py-1 pl-7 pr-2 font-mono text-[12px] text-white outline-none focus:border-sky-400 sm:w-56" />
          </label>
        </div>
        <div className="max-h-[22rem] overflow-auto">
          {/* Lines wrap rather than scroll sideways: the outcome fields (status, bytes, time) sit at the
              END of a log line, and in the briefing column they would otherwise be off-screen. */}
          <div className="py-1 font-mono text-[12px] leading-relaxed">
            {(lab.header ?? []).map(h => <p key={h} className="whitespace-pre-wrap px-3 pl-12 text-slate-500 [overflow-wrap:anywhere]">{h}</p>)}
            {shown.map(({ text, i }) => {
              const isPicked = picked === i;
              const isMarked = marked.has(i);
              const selectable = !done && obj?.type === "line";
              return (
                <button key={i} type="button" disabled={!selectable}
                  aria-pressed={isPicked}
                  onClick={() => { setPicked(i); setMiss(null); }}
                  className={cn(
                    "flex w-full items-start gap-3 border-b border-white/[0.04] px-3 py-0.5 text-left transition",
                    isPicked ? "bg-sky-500/20 text-white" : isMarked ? "bg-emerald-500/10 text-emerald-100" : "text-slate-200",
                    selectable && !isPicked ? "hover:bg-white/[0.05]" : "",
                  )}>
                  <span className="w-6 shrink-0 select-none text-right text-slate-500">{i + 1}</span>
                  <span className="min-w-0 whitespace-pre-wrap [overflow-wrap:anywhere]">{text}</span>
                </button>
              );
            })}
            {shown.length === 0 && <p className="px-3 py-2 text-slate-500">No line contains &quot;{filter}&quot;.</p>}
          </div>
        </div>
        <p className="border-t border-white/10 px-3 py-1.5 text-[11px] text-slate-500">{shown.length} of {lab.lines.length} lines{filter ? ` match "${filter}"` : ""}</p>
      </div>

      {/* Objectives */}
      <ol className="space-y-2">
        {lab.objectives.map((o, idx) => {
          const isDone = solved.includes(o.id);
          const isCurrent = !done && idx === current;
          return (
            <li key={o.id} className={cn("rounded-xl border p-3", isCurrent ? "border-sky-400/40 bg-[#081120]" : "border-white/10 bg-white/[0.02]")}>
              <p className={cn("text-sm font-semibold", isDone ? "text-emerald-200" : isCurrent ? "text-white" : "text-slate-500")}>
                <span className="mr-2 text-sky-300">{idx + 1}.</span>{o.task}
              </p>
              {isDone && <p className="mt-1.5 text-sm leading-relaxed text-emerald-200"><Check className="mr-1 inline h-4 w-4" />{o.why}</p>}
              {isCurrent && (
                <div className="mt-2 space-y-2">
                  {o.type === "line" ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs text-slate-400">{picked === null ? "Tap the line in the log." : `Selected: line ${picked + 1}`}</span>
                      <button onClick={check} className="rounded-lg border border-sky-300/60 px-3 py-1.5 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Check</button>
                    </div>
                  ) : (
                    <div className="flex gap-2">
                      <input value={typed} onChange={e => { setTyped(e.target.value); setMiss(null); }} onKeyDown={e => e.key === "Enter" && check()}
                        inputMode={o.type === "count" ? "numeric" : undefined}
                        aria-label={`Answer ${idx + 1}`} placeholder={o.type === "count" ? "How many lines" : "Copy the value from the log"}
                        className={cn("min-w-0 flex-1 rounded-lg border bg-black/30 px-3 py-2 font-mono text-sm text-white outline-none", miss ? "border-rose-500" : "border-white/15 focus:border-sky-400")} />
                      <button onClick={check} className="rounded-lg border border-sky-300/60 px-3 text-sm font-bold text-sky-100 hover:bg-sky-500/10">Check</button>
                    </div>
                  )}
                  {miss && <p role="status" className="text-xs leading-relaxed text-rose-300">{miss}</p>}
                  {hint ? <p className="text-xs leading-relaxed text-amber-200">{o.hint}</p>
                    : <button onClick={() => setHint(true)} className="inline-flex items-center gap-1 text-xs text-amber-300 hover:underline"><Lightbulb className="h-3.5 w-3.5" />Where do I look?</button>}
                </div>
              )}
            </li>
          );
        })}
      </ol>
      {done && <p role="status" className="rounded-xl border border-emerald-400/30 bg-emerald-500/10 p-3 text-sm leading-relaxed text-emerald-100">{lab.lesson}</p>}
    </div>
  );
}
