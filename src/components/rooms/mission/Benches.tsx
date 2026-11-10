"use client";
/**
 * The non-query workbenches of a mission. Each one only collects the learner's
 * work; the player sends it to the server to be checked.
 */
import { useId, useMemo, useState } from "react";
import { Play, TextSelect } from "lucide-react";
import type { MissionArtifact, MissionEvent, MissionSample } from "@/lib/missions/types";
import type { SanitizedField, StringRow } from "@/lib/missions/sanitize";
import { buildSample } from "@/lib/missions/yara/samples";
import { compileYara, scanYara } from "@/lib/missions/yara";
import { matchSigma, parseSigma } from "@/lib/missions/sigma";
import { cn } from "@/lib/utils";
import { CodeEditor } from "./CodeEditor";
import { useAddIoc } from "./Notebook";

// ─── Evidence ─────────────────────────────────────────────────────────────────

export function ArtifactView({ roomId, artifact, collect }: { roomId: string; artifact: MissionArtifact; collect?: boolean }) {
  const addIoc = useAddIoc(roomId);
  const [msg, setMsg] = useState<string | null>(null);
  function addSelection() {
    const sel = typeof window !== "undefined" ? window.getSelection()?.toString() ?? "" : "";
    const v = sel.trim().replace(/^[<("'\s]+|[>)"',;\s]+$/g, "");
    if (!v) { setMsg("Select the indicator's text in the evidence first."); return; }
    setMsg(addIoc(v, artifact.title) ? `Added ${v.length > 48 ? v.slice(0, 48) + "..." : v}` : "Can't tell what that is. Type it into the notebook with its type.");
  }
  return (
    <figure className="rounded-lg border border-border bg-bg-panel/60">
      <figcaption className="flex flex-wrap items-center gap-2 border-b border-border/60 px-3 py-1.5 text-xs">
        <span className="font-semibold text-slate-200">{artifact.title}</span>
        {collect && (
          <button type="button" onMouseDown={e => e.preventDefault()} onClick={addSelection}
            className="ml-auto inline-flex items-center gap-1 rounded border border-cyber-500/40 px-2 py-0.5 text-[11px] text-cyber-200 hover:bg-cyber-500/15">
            <TextSelect className="h-3 w-3" aria-hidden /> Add selection to notebook
          </button>
        )}
      </figcaption>
      {artifact.format === "mono"
        ? <pre tabIndex={0} className="max-h-96 overflow-auto whitespace-pre-wrap break-all px-3 py-2 font-mono text-[12px] leading-5 text-slate-200">{artifact.body}</pre>
        : <div className="whitespace-pre-wrap px-3 py-2 text-sm leading-relaxed text-slate-200">{artifact.body}</div>}
      {msg && <p role="status" className="border-t border-border/60 px-3 py-1 text-[11px] text-slate-400">{msg}</p>}
    </figure>
  );
}

// ─── Typed fields ─────────────────────────────────────────────────────────────

export function FieldsBench({ fields, values, onChange, verdicts, disabled }: {
  fields: SanitizedField[];
  values: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  verdicts?: { id: string; ok: boolean; say?: string }[];
  disabled?: boolean;
}) {
  const ids = useId();
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {fields.map(f => {
        const v = verdicts?.find(x => x.id === f.id);
        const cls = cn("w-full rounded-md border bg-bg-elevated px-2.5 py-1.5 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30",
          v ? (v.ok ? "border-neon-green/60" : "border-severity-high/60") : "border-border");
        const set = (x: string) => onChange({ ...values, [f.id]: x });
        return (
          <div key={f.id} className={cn("space-y-1", f.format === "set" && "sm:col-span-2")}>
            <label htmlFor={`${ids}-${f.id}`} className="flex items-center gap-2 text-xs font-medium text-slate-300">
              {f.label}
              <span className="rounded bg-bg-elevated px-1.5 py-0.5 font-mono text-[10px] uppercase text-slate-500">{f.format === "set" ? `list of ${f.item ?? "text"}` : f.format}</span>
            </label>
            {f.format === "choice" ? (
              <select id={`${ids}-${f.id}`} value={values[f.id] ?? ""} disabled={disabled || v?.ok} onChange={e => set(e.target.value)} className={cls}>
                <option value="">Choose...</option>
                {(f.options ?? []).map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            ) : f.format === "set" ? (
              <textarea id={`${ids}-${f.id}`} rows={2} value={values[f.id] ?? ""} disabled={disabled || v?.ok} onChange={e => set(e.target.value)} placeholder={f.placeholder ?? "One per line, or comma separated"} className={cn(cls, "font-mono")} />
            ) : (
              <input id={`${ids}-${f.id}`} value={values[f.id] ?? ""} disabled={disabled || v?.ok} onChange={e => set(e.target.value)} placeholder={f.placeholder} className={cn(cls, f.format !== "text" && "font-mono")} />
            )}
            {v && !v.ok && v.say && <p className="text-xs text-neon-amber">{v.say}</p>}
          </div>
        );
      })}
    </div>
  );
}

// ─── Strings view ─────────────────────────────────────────────────────────────

export function StringsBench({ view, totals, picks, onPicks, verdicts, disabled }: {
  view: StringRow[];
  totals: { bad: number; good: number };
  picks: string[];
  onPicks: (p: string[]) => void;
  verdicts?: { value: string; ok: boolean }[];
  disabled?: boolean;
}) {
  const [filter, setFilter] = useState("");
  const rows = useMemo(() => view.filter(r => !filter || r.value.toLowerCase().includes(filter.toLowerCase())), [view, filter]);
  const toggle = (v: string) => onPicks(picks.includes(v) ? picks.filter(x => x !== v) : [...picks, v]);
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
        <label className="sr-only" htmlFor="strings-filter">Filter strings</label>
        <input id="strings-filter" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter strings"
          className="rounded-md border border-border bg-bg-elevated px-2 py-1 font-mono text-xs text-slate-200 placeholder:text-slate-500" />
        <span>{view.length} strings. Corpus: {totals.bad} known-bad builds, {totals.good} goodware files.</span>
      </div>
      <div className="max-h-96 overflow-auto rounded-lg border border-border">
        <table className="min-w-full border-collapse font-mono text-[12px]">
          <thead className="sticky top-0 bg-bg-elevated text-slate-300">
            <tr>
              <th scope="col" className="w-8 px-2 py-1.5"><span className="sr-only">Pick</span></th>
              <th scope="col" className="px-2 py-1.5 text-left">Offset</th>
              <th scope="col" className="px-2 py-1.5 text-left">Enc</th>
              <th scope="col" className="px-2 py-1.5 text-left">String</th>
              <th scope="col" className="px-2 py-1.5 text-right">In bad</th>
              <th scope="col" className="px-2 py-1.5 text-right">In goodware</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => {
              const picked = picks.includes(r.value);
              const v = verdicts?.find(x => x.value === r.value);
              return (
                <tr key={`${r.offset}-${r.enc}`} className={cn("border-t border-border/50", picked && "bg-cyber-500/10")}>
                  <td className="px-2 text-center">
                    <input type="checkbox" checked={picked} disabled={disabled} onChange={() => toggle(r.value)} aria-label={`Pick ${r.value}`} />
                  </td>
                  <td className="whitespace-nowrap px-2 py-1 text-slate-500">0x{r.offset.toString(16).padStart(5, "0")}</td>
                  <td className="px-2 py-1 text-slate-400">{r.enc === "wide" ? "utf16le" : "ascii"}</td>
                  <td className={cn("break-all px-2 py-1", v ? (v.ok ? "text-neon-green" : "text-severity-high") : "text-slate-100")}>{r.value}</td>
                  <td className="px-2 py-1 text-right text-slate-300">{r.bad} / {totals.bad}</td>
                  <td className={cn("px-2 py-1 text-right", r.good > 0 ? "text-neon-amber" : "text-slate-300")}>{r.good} / {totals.good}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-xs text-slate-500">{picks.length} picked.</p>
    </div>
  );
}

// ─── Rule bench (YARA / Sigma) ────────────────────────────────────────────────

type RunRow = { name: string; label: "bad" | "good"; matched: boolean; detail: string; note?: string };

export function RuleBench({ language, source, onSource, samples, events, hiddenCount, disabled }: {
  language: "yara" | "sigma";
  source: string;
  onSource: (s: string) => void;
  samples?: MissionSample[];
  events?: MissionEvent[];
  hiddenCount: number;
  disabled?: boolean;
}) {
  const [rows, setRows] = useState<RunRow[] | null>(null);
  const [error, setError] = useState<{ line: number; message: string } | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  function run() {
    setError(null); setWarnings([]);
    if (language === "yara") {
      const c = compileYara(source);
      if (!c.ok) { setError(c.error); setRows(null); return; }
      setRows((samples ?? []).map(s => {
        const built = buildSample(s.spec);
        const r = scanYara(c.rules, built.bytes, built.filesize);
        const hits = r.rules.flatMap(x => x.strings.filter(h => h.count > 0).map(h => `${h.id} x${h.count}`));
        return { name: s.name, label: s.label, note: s.note, matched: r.matched, detail: `${(built.filesize / 1024).toFixed(0)} KB. ${hits.length ? hits.join(", ") : "no string hits"}` };
      }));
    } else {
      const p = parseSigma(source);
      if (!p.ok) { setError(p.error); setRows(null); return; }
      setWarnings(p.warnings);
      setRows((events ?? []).map(e => {
        const m = matchSigma(p.rule, e.fields);
        const sel = Object.entries(m.selections).map(([k, v]) => `${k}: ${v ? "yes" : "no"}`).join(", ");
        return { name: e.id, label: e.label, note: e.note, matched: m.matched, detail: sel };
      }));
    }
  }

  const caught = rows?.filter(r => r.label === "bad" && r.matched).length ?? 0;
  const bad = rows?.filter(r => r.label === "bad").length ?? 0;
  const falseHits = rows?.filter(r => r.label === "good" && r.matched).length ?? 0;

  return (
    <div className="space-y-3">
      {/* The test set: what the rule must catch and what it must leave alone. Evidence, not answers. */}
      <details className="rounded-lg border border-border bg-bg-panel/60" open>
        <summary className="cursor-pointer px-3 py-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          Test set: {language === "yara" ? `${samples?.length ?? 0} files` : `${events?.length ?? 0} events`}
        </summary>
        <div className="max-h-80 space-y-1.5 overflow-auto border-t border-border/60 px-3 py-2">
          {language === "yara"
            ? (samples ?? []).map(s => (
              <div key={s.name} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", s.label === "bad" ? "bg-severity-high/15 text-severity-high" : "bg-neon-green/10 text-neon-green")}>{s.label === "bad" ? "malicious" : "clean"}</span>
                <span className="font-mono text-slate-200">{s.name}</span>
                <span className="text-slate-500">{(s.spec.size / 1024).toLocaleString(undefined, { maximumFractionDigits: 0 })} KB</span>
                {s.note && <span className="text-slate-400">{s.note}</span>}
              </div>
            ))
            : (events ?? []).map(e => (
              <div key={e.id} className="rounded-md bg-bg-elevated/60 px-2 py-1.5 text-xs">
                <div className="mb-1 flex flex-wrap items-baseline gap-2">
                  <span className="font-mono font-semibold text-slate-200">{e.id}</span>
                  <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase", e.label === "bad" ? "bg-severity-high/15 text-severity-high" : "bg-neon-green/10 text-neon-green")}>{e.label === "bad" ? "malicious" : "clean"}</span>
                  {e.note && <span className="text-slate-400">{e.note}</span>}
                </div>
                <dl className="grid grid-cols-[max-content_minmax(0,1fr)] gap-x-3 font-mono text-[11px]">
                  {Object.entries(e.fields).filter(([, v]) => v !== null && v !== "").map(([k, v]) => (
                    <div key={k} className="contents"><dt className="text-slate-500">{k}</dt><dd className="break-all text-slate-200">{String(v)}</dd></div>
                  ))}
                </dl>
              </div>
            ))}
        </div>
      </details>
      <CodeEditor language={language} label={`${language === "yara" ? "YARA" : "Sigma"} rule`} value={source} onChange={onSource} onRun={run} rows={12} errorLine={error?.line ?? null} />
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={run} disabled={disabled || !source.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-sm font-semibold text-cyber-200 hover:bg-cyber-500/25 disabled:opacity-50">
          <Play className="h-3.5 w-3.5" aria-hidden /> Run on the test set
        </button>
        <span className="text-xs text-slate-500">The check also runs your rule on {hiddenCount} {language === "yara" ? "files" : "events"} you cannot see.</span>
      </div>
      {error && <p className="rounded-md border border-severity-high/40 bg-severity-high/10 px-3 py-2 font-mono text-xs text-severity-high">line {error.line}: {error.message}</p>}
      {warnings.length > 0 && <ul className="text-xs text-neon-amber">{warnings.map((w, i) => <li key={i}>Warning: {w}</li>)}</ul>}
      {rows && (
        <div className="space-y-1.5">
          <p className="text-xs text-slate-300">Caught {caught} of {bad} malicious. {falseHits === 0 ? "No false hits." : <span className="text-severity-high">{falseHits} false hit{falseHits === 1 ? "" : "s"} on clean files.</span>}</p>
          <div className="overflow-auto rounded-lg border border-border">
            <table className="min-w-full border-collapse text-[12px]">
              <thead className="bg-bg-elevated text-slate-300">
                <tr><th scope="col" className="px-2 py-1.5 text-left">{language === "yara" ? "File" : "Event"}</th><th scope="col" className="px-2 py-1.5 text-left">Set</th><th scope="col" className="px-2 py-1.5 text-left">Result</th><th scope="col" className="px-2 py-1.5 text-left">Why</th></tr>
              </thead>
              <tbody>
                {rows.map(r => {
                  const right = (r.label === "bad") === r.matched;
                  return (
                    <tr key={r.name} className="border-t border-border/50">
                      <td className="px-2 py-1 font-mono text-slate-200">{r.name}{r.note && <span className="block font-sans text-[11px] text-slate-500">{r.note}</span>}</td>
                      <td className="px-2 py-1 text-slate-400">{r.label === "bad" ? "malicious" : "clean"}</td>
                      <td className={cn("px-2 py-1 font-semibold", right ? "text-neon-green" : "text-severity-high")}>{r.matched ? "match" : "no match"}</td>
                      <td className="px-2 py-1 font-mono text-[11px] text-slate-400">{r.detail}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Report ───────────────────────────────────────────────────────────────────

export function ReportBench({ slots, values, onChange, verdicts, disabled }: {
  slots: { id: string; label: string; placeholder?: string; maxWords: number }[];
  values: Record<string, string>;
  onChange: (v: Record<string, string>) => void;
  verdicts?: { id: string; ok: boolean; missing: string[]; flagged: string[]; tooLong: boolean; words: number }[];
  disabled?: boolean;
}) {
  const ids = useId();
  return (
    <div className="space-y-3">
      {slots.map(s => {
        const text = values[s.id] ?? "";
        const words = text.trim().split(/\s+/).filter(Boolean).length;
        const v = verdicts?.find(x => x.id === s.id);
        return (
          <div key={s.id} className="space-y-1">
            <label htmlFor={`${ids}-${s.id}`} className="flex items-center justify-between text-xs font-medium text-slate-300">
              <span>{s.label}</span>
              <span className={cn("font-mono", words > s.maxWords ? "text-severity-high" : "text-slate-500")}>{words}/{s.maxWords} words</span>
            </label>
            <textarea id={`${ids}-${s.id}`} rows={3} value={text} disabled={disabled || v?.ok} onChange={e => onChange({ ...values, [s.id]: e.target.value })} placeholder={s.placeholder}
              className={cn("w-full rounded-md border bg-bg-elevated p-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyber-500/30",
                v ? (v.ok ? "border-neon-green/60" : "border-severity-high/60") : "border-border")} />
            {v && !v.ok && (
              <ul className="space-y-0.5 text-xs text-neon-amber">
                {v.missing.map(m => <li key={m}>Missing: {m}</li>)}
                {v.flagged.map(f => <li key={f} className="text-severity-high">{f}</li>)}
                {v.tooLong && <li>Too long: cut it to {s.maxWords} words. A reader needs the facts, not the effort.</li>}
              </ul>
            )}
          </div>
        );
      })}
    </div>
  );
}
