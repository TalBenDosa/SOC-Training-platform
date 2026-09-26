"use client";
import { Filter, X } from "lucide-react";

// ── G-04: surfaced feed filters + active pivot chips ─────────────────────────
type PivotTuple = ["user" | "host" | "ip", string, (v: string) => void];
export function FeedFilterBar({
  severity, setSeverity, source, setSource, sources, search, setSearch, pivots,
}: {
  severity: "all" | "low" | "medium" | "high"; setSeverity: (v: "all" | "low" | "medium" | "high") => void;
  source: string; setSource: (v: string) => void; sources: string[];
  search: string; setSearch: (v: string) => void;
  pivots: PivotTuple[];
}) {
  const activePivots = pivots.filter(([, v]) => v !== "all");
  const SEV: Array<{ k: "all" | "low" | "medium" | "high"; label: string }> = [
    { k: "all", label: "All" }, { k: "high", label: "High" }, { k: "medium", label: "Med" }, { k: "low", label: "Low" },
  ];
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-elevated/60 px-3 py-2">
      <Filter className="h-3.5 w-3.5 shrink-0 text-slate-400" />
      <div className="flex items-center gap-1">
        {SEV.map(s => (
          <button key={s.k} onClick={() => setSeverity(s.k)}
            className={`rounded px-2 py-0.5 text-[10px] font-semibold transition ${severity === s.k ? "border border-cyber-500/40 bg-cyber-500/20 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>{s.label}</button>
        ))}
      </div>
      <select value={source} onChange={e => setSource(e.target.value)}
        className="rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">
        <option value="all">All sources</option>
        {sources.map(s => <option key={s} value={s}>{s}</option>)}
      </select>
      <div className="relative min-w-[120px] flex-1">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search feed… (host:… user:…)"
          className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
      </div>
      {activePivots.map(([field, value, setter]) => (
        <button key={field} onClick={() => setter("all")} title="Clear this filter"
          className="flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 text-[10px] font-mono text-cyber-300 hover:bg-cyber-500/20">
          {field}:{value} <X className="h-3 w-3" />
        </button>
      ))}
    </div>
  );
}
