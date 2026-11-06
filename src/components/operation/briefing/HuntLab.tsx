"use client";
import React, { useMemo, useState } from "react";
import { Heart, Lightbulb, Play, Table2, Trophy } from "lucide-react";
import { cn } from "@/lib/utils";
import type { BriefingLab } from "@/lib/rooms/experience";
import { runHunt, type HuntStep } from "@/lib/rooms/experience/hunt";

// Build a hunting query one line at a time, in a console laid out like the real thing:
// schema on the left, editor on top, results below. Every result is really computed from
// the rows, so a wrong line shows what it actually returns, and that is the lesson.

type Lab = Extract<BriefingLab, { kind: "hunt" }>;
const LIVES = 3;

export function HuntLab({ lab, onDone }: { lab: Lab; onDone: () => void }) {
  const [run, setRun] = useState(0);
  return <HuntRun key={run} lab={lab} onDone={onDone} onRetry={() => setRun(r => r + 1)} />;
}

function HuntRun({ lab, onDone, onRetry }: { lab: Lab; onDone: () => void; onRetry: () => void }) {
  const [locked, setLocked] = useState<{ text: string; step: HuntStep }[]>([]);
  const [trial, setTrial] = useState<{ text: string; step: HuntStep } | null>(null);
  const [lives, setLives] = useState(LIVES);
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [open, setOpen] = useState(lab.start);

  const rung = lab.rungs[locked.length];
  const won = locked.length >= lab.rungs.length;
  const lost = lives <= 0;
  const steps = useMemo(() => [...locked, ...(trial ? [trial] : [])].map(l => l.step), [locked, trial]);
  const result = useMemo(() => runHunt(lab.tables, lab.start, steps, { emptyColumns: lab.language === "SPL" }), [lab, steps]);

  function pick(c: Lab["rungs"][number]["choices"][number]) {
    if (won || lost) return;
    if (c.right) {
      const next = [...locked, { text: c.text, step: c.apply }];
      setLocked(next);
      setTrial(null);
      setNote({ ok: true, text: c.why });
      if (next.length >= lab.rungs.length) onDone();
    } else {
      setTrial({ text: c.text, step: c.apply });
      setLives(l => l - 1);
      setNote({ ok: false, text: c.why });
    }
  }

  const lines = [lab.start, ...locked.map(l => l.text)];
  const table = lab.tables.find(t => t.name === open);

  return (
    <div>
      <div className="mb-3 rounded-xl border border-white/10 bg-black/30 p-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-300">
          <span className="inline-flex items-center gap-0.5" aria-label={`${lives} of ${LIVES} lives left`}>
            {Array.from({ length: LIVES }, (_, i) => <Heart key={i} className={cn("h-4 w-4", i < lives ? "fill-rose-400 text-rose-400" : "text-slate-600")} />)}
          </span>
          <span className="font-semibold text-slate-200">{won ? "Query done" : `Step ${locked.length + 1} of ${lab.rungs.length}`}</span>
          <span className="ml-auto">Goal: {lab.goal}</span>
        </div>
        {!won && !lost && <p className="mt-2 text-base font-bold leading-snug text-white">{rung.ask}</p>}
      </div>

      {note && !lost && (
        <div role="status" className={cn("mb-3 rounded-xl border p-3 text-sm leading-relaxed", note.ok ? "border-emerald-400/40 bg-emerald-500/10 text-emerald-100" : "border-amber-400/40 bg-amber-500/10 text-amber-100")}>{note.text}</div>
      )}

      {lost ? (
        <div role="status" className="rounded-2xl border border-rose-400/40 bg-rose-500/10 p-6 text-center">
          <p className="text-lg font-extrabold text-white">The hunt went cold</p>
          <p className="mx-auto mt-1 max-w-lg text-sm leading-relaxed text-slate-100">{note?.text}</p>
          <div className="mx-auto mt-3 max-w-lg rounded-xl border border-white/10 bg-black/30 p-3 text-left">
            <p className="flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-amber-300"><Lightbulb className="h-3.5 w-3.5" />What to take from this</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-100">{lab.lesson}</p>
          </div>
          <button autoFocus onClick={onRetry} className="mt-4 rounded-xl bg-white px-5 py-2.5 text-sm font-bold text-[#04121a]">Run it again</button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-white/10 bg-white text-[#323130]" style={{ fontFamily: '"Segoe UI", system-ui, sans-serif' }}>
          <div className="flex items-center gap-2 border-b border-[#edebe9] bg-[#faf9f8] px-3 py-1.5 text-[13px] font-semibold">
            <span>{lab.console ?? "Advanced hunting"}</span>
            <span className="ml-auto rounded-sm bg-[#deecf9] px-2 py-0.5 text-[11px] font-normal text-[#201f1e]">{lab.language}</span>
          </div>
          <div className="grid md:grid-cols-[11.5rem_1fr]">
            <nav aria-label="Schema" className="border-b border-[#edebe9] p-2 text-[12.5px] md:border-b-0 md:border-r">
              <p className="px-1 pb-1 text-[11px] font-semibold text-[#605e5c]">Schema</p>
              {lab.tables.map(t => (
                <div key={t.name}>
                  <button onClick={() => setOpen(t.name)} aria-expanded={open === t.name} className={cn("flex w-full items-center gap-1.5 rounded-sm px-1 py-1 text-left hover:bg-[#f3f2f1]", open === t.name && "bg-[#edebe9] font-semibold")}>
                    <Table2 className="h-3.5 w-3.5 shrink-0 text-[#0078d4]" /><span className="min-w-0 [overflow-wrap:anywhere]">{t.name}</span>
                  </button>
                  {open === t.name && table && (
                    <div className="px-1 pb-1 pl-6 text-[11px] text-[#605e5c]">
                      <p className="mb-0.5">{table.note}</p>
                      {table.columns.map(c => <p key={c} className="font-mono [overflow-wrap:anywhere]">{c}</p>)}
                    </div>
                  )}
                </div>
              ))}
            </nav>
            <div className="min-w-0">
              <div className="border-b border-[#edebe9] p-2">
                <ol className="overflow-x-auto font-mono text-[12.5px] leading-6" aria-label="Query">
                  {lines.map((l, i) => <li key={i} className="flex gap-3 whitespace-pre"><span className="w-4 shrink-0 select-none text-right text-[#a19f9d]">{i + 1}</span><span>{l}</span></li>)}
                  {trial && <li className="flex gap-3 whitespace-pre text-[#a4262c]"><span className="w-4 shrink-0 select-none text-right">{lines.length + 1}</span><span>{trial.text}</span></li>}
                </ol>
              </div>
              {!won && (
                <div className="border-b border-[#edebe9] bg-[#faf9f8] p-2">
                  <p className="mb-1 text-[11.5px] font-semibold text-[#605e5c]">Add the next line and run it</p>
                  <div className="grid gap-1">
                    {rung.choices.map(c => (
                      <button key={c.id} onClick={() => pick(c)} className="flex items-start gap-2 rounded-sm border border-[#c8c6c4] bg-white px-2 py-1.5 text-left font-mono text-[12px] text-[#201f1e] hover:border-[#0078d4] hover:bg-[#f3f9fd]">
                        <Play className="mt-0.5 h-3 w-3 shrink-0 text-[#0078d4]" /><span className="min-w-0 [overflow-wrap:anywhere]">{c.text}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
              <div className="p-2">
                <p className="mb-1 text-[12px] font-semibold text-[#201f1e]">Results <span className="font-normal text-[#605e5c]">{result.error ? "" : `${result.rows.length} item${result.rows.length === 1 ? "" : "s"}`}</span></p>
                {result.error ? <p className="rounded-sm border-l-4 border-[#a4262c] bg-[#fdf3f4] px-2 py-1 text-[12.5px] text-[#201f1e]">{result.error}</p>
                  : result.rows.length === 0 ? <p className="text-[12.5px] text-[#605e5c]">No results found.</p> : (
                    <div className="max-h-64 overflow-auto">
                      <table className="w-full text-left text-[12px]">
                        <thead className="sticky top-0 bg-white text-[#605e5c]"><tr className="border-b border-[#edebe9]">{result.columns.map(c => <th key={c} className="whitespace-nowrap px-2 py-1 font-semibold">{c}</th>)}</tr></thead>
                        <tbody>{result.rows.map((r, i) => <tr key={i} className="border-b border-[#f3f2f1]">{r.map((c, j) => <td key={j} className="whitespace-nowrap px-2 py-1 font-mono text-[11.5px]">{c}</td>)}</tr>)}</tbody>
                      </table>
                    </div>
                  )}
              </div>
            </div>
          </div>
        </div>
      )}

      {won && (
        <div role="status" className="mt-3 rounded-xl border border-emerald-400/40 bg-emerald-500/10 p-4">
          <p className="flex items-center gap-2 text-sm font-bold text-emerald-200"><Trophy className="h-4 w-4" />Query ran clean</p>
          <p className="mt-1 text-sm leading-relaxed text-slate-200">{lab.lesson}</p>
        </div>
      )}
    </div>
  );
}
