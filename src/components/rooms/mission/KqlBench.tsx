"use client";
/**
 * Query Workspace: the learner writes KQL, runs it on the mission's tables (in
 * the browser, instantly, as often as they like) and pins rows to the case
 * notebook. "Check" is the player's job and goes to the server.
 */
import { useMemo, useRef, useState } from "react";
import { Play, Pin, Table2, ChevronDown } from "lucide-react";
import { formatKqlValue } from "@/lib/kql";
import type { KqlResult } from "@/lib/kql/types";
import { hydrate, pipelineCounts, runMissionQuery } from "@/lib/missions/kqlCompare";
import type { MissionDataset } from "@/lib/missions/types";
import { cn } from "@/lib/utils";
import { CodeEditor, type CodeEditorHandle } from "./CodeEditor";

const SHOW_ROWS = 50;

export function KqlBench({ data, focusTables, query, onQuery, onPin, disabled }: {
  data: MissionDataset;
  focusTables?: string[];
  query: string;
  onQuery: (q: string) => void;
  onPin: (source: string, text: string, time?: string) => void;
  disabled?: boolean;
}) {
  const tables = useMemo(() => hydrate(data), [data]);
  const editor = useRef<CodeEditorHandle>(null);
  const [result, setResult] = useState<KqlResult | null>(null);
  const [stages, setStages] = useState<ReturnType<typeof pipelineCounts>>(null);
  const [schemaOpen, setSchemaOpen] = useState(true);
  const [ranAt, setRanAt] = useState(0);
  const [ranQuery, setRanQuery] = useState("");

  const ordered = useMemo(() => {
    const names = data.tables.map(t => t.name);
    const first = (focusTables ?? []).filter(n => names.includes(n));
    return [...first, ...names.filter(n => !first.includes(n))];
  }, [data, focusTables]);

  function run() {
    if (!query.trim()) return;
    const r = runMissionQuery(data, query);
    setResult(r);
    setStages(r.ok ? pipelineCounts(data, query) : null);
    setRanAt(n => n + 1);
    setRanQuery(query);
  }

  const timeCol = result && result.ok ? result.columns.find(c => c.type === "datetime")?.name : undefined;

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-border bg-bg-panel/60">
        <button type="button" onClick={() => setSchemaOpen(o => !o)} aria-expanded={schemaOpen}
          className="flex w-full items-center gap-2 px-3 py-2 text-left text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200">
          <Table2 className="h-3.5 w-3.5" aria-hidden /> Tables in this workspace
          <ChevronDown className={cn("ml-auto h-3.5 w-3.5 transition-transform", schemaOpen && "rotate-180")} aria-hidden />
        </button>
        {schemaOpen && (
          <div className="space-y-2 border-t border-border/60 px-3 py-2">
            {ordered.map(name => {
              const t = tables[name];
              return (
                <div key={name} className="text-xs">
                  <button type="button" className="font-mono font-semibold text-cyan-300 hover:underline" onClick={() => editor.current?.insert(name)}>
                    {name}
                  </button>
                  <span className="ml-2 text-slate-500">{t.rows.length.toLocaleString()} rows</span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {t.columns.map(c => (
                      <button key={c.name} type="button" title={`${c.name} (${c.type}): insert`}
                        onClick={() => editor.current?.insert(c.name)}
                        className="rounded border border-border/70 bg-bg-elevated px-1.5 py-0.5 font-mono text-[11px] text-slate-300 hover:border-cyber-500/50 hover:text-white">
                        {c.name}<span className="ml-1 text-slate-500">{c.type}</span>
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <CodeEditor ref={editor} language="kql" label="KQL query" value={query} onChange={onQuery} onRun={run} tables={tables}
        errorLine={result && !result.ok ? result.error.line : null} />
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" onClick={run} disabled={disabled || !query.trim()}
          className="inline-flex items-center gap-1.5 rounded-md border border-cyber-500/50 bg-cyber-500/15 px-3 py-1.5 text-sm font-semibold text-cyber-200 hover:bg-cyber-500/25 disabled:opacity-50">
          <Play className="h-3.5 w-3.5" aria-hidden /> Run
        </button>
        <span className="text-xs text-slate-500">Shift+Enter runs. Running is free; only Check counts.</span>
      </div>

      {result && ranQuery !== query && (
        <p className="text-xs text-neon-amber">You changed the query since this run. Run it again to see what it returns now.</p>
      )}
      <div aria-live="polite" key={ranAt} className={cn(result && ranQuery !== query && "opacity-50")}>
        {result && !result.ok && (
          <p className="rounded-md border border-severity-high/40 bg-severity-high/10 px-3 py-2 font-mono text-xs text-severity-high">
            Line {result.error.line}, column {result.error.column}: {result.error.message}
          </p>
        )}
        {result && result.ok && (
          <div className="space-y-2">
            {stages && (
              <p className="flex flex-wrap items-center gap-1 text-xs text-slate-400" aria-label="Rows after each line">
                {stages.map((s, i) => (
                  <span key={i} className="inline-flex items-center gap-1">
                    {i > 0 && <span aria-hidden className="text-slate-600">&rarr;</span>}
                    <span className={cn("rounded px-1.5 py-0.5 font-mono", s.rows === 0 ? "bg-severity-high/15 text-severity-high" : "bg-bg-elevated text-slate-300")}>
                      {s.label} {s.rows === null ? "?" : s.rows.toLocaleString()}
                    </span>
                  </span>
                ))}
              </p>
            )}
            <p className="text-xs text-slate-400">
              {result.rows.length.toLocaleString()} row{result.rows.length === 1 ? "" : "s"}
              {result.rows.length > SHOW_ROWS && ` (first ${SHOW_ROWS} shown)`}
              {result.warnings.length > 0 && <span className="ml-2 text-neon-amber">{result.warnings[0]}</span>}
            </p>
            {result.rows.length > 0 && (
              <div className="max-h-80 overflow-auto rounded-lg border border-border">
                <table className="min-w-full border-collapse font-mono text-[12px]">
                  <thead className="sticky top-0 bg-bg-elevated">
                    <tr>
                      <th className="w-8 px-1" aria-label="Pin" />
                      {result.columns.map(c => <th key={c.name} scope="col" className="whitespace-nowrap px-2 py-1.5 text-left font-semibold text-slate-300">{c.name}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {result.rows.slice(0, SHOW_ROWS).map((r, i) => {
                      const cells = result.columns.map(c => formatKqlValue(r[c.name], c.type));
                      const text = result.columns.map((c, j) => `${c.name}=${cells[j]}`).join("  ");
                      const time = timeCol ? formatKqlValue(r[timeCol], "datetime") : undefined;
                      return (
                        <tr key={i} className="border-t border-border/50 odd:bg-white/[0.02]">
                          <td className="px-1 text-center">
                            <button type="button" title="Pin this row to the case notebook" aria-label={`Pin row ${i + 1}`}
                              onClick={() => onPin("KQL result", text, time)} className="rounded p-1 text-slate-500 hover:bg-cyber-500/15 hover:text-cyber-200">
                              <Pin className="h-3 w-3" aria-hidden />
                            </button>
                          </td>
                          {cells.map((v, j) => <td key={j} className="max-w-[28rem] truncate whitespace-nowrap px-2 py-1 text-slate-200" title={v}>{v}</td>)}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
