"use client";
/**
 * The left-hand module tree of the learning-plan editors: Learning Path → path →
 * module → lesson, Rooms → category → room, Quizzes, Scenarios, and the org's
 * own Custom content. Collapsible, searchable, and a tick (V) at ANY level
 * selects every item under it — tick "SOC Foundations" and all its lessons are
 * in; tick it again (when fully selected) and they are all out. Branch boxes
 * show a partial state when only some children are chosen.
 *
 * Pure presentation over a server-built tree (/api/org/catalog): it never
 * imports the content corpus.
 */
import { useMemo, useState } from "react";
import { ChevronRight, Check, Minus, Search, X } from "lucide-react";
import type { CatalogNode } from "@/lib/plans/types";

/** Every leaf key under `n`, in tree order. */
export function leafKeys(n: CatalogNode): string[] {
  if (n.item) return [n.key];
  return (n.children ?? []).flatMap(leafKeys);
}

/** key → leaf node, for resolving selected keys back to titles/items. */
export function indexLeaves(tree: CatalogNode[]): Map<string, CatalogNode> {
  const m = new Map<string, CatalogNode>();
  const walk = (n: CatalogNode) => { if (n.item) m.set(n.key, n); n.children?.forEach(walk); };
  tree.forEach(walk);
  return m;
}

/** Prune the tree to nodes matching `q` (a matching branch keeps all its children). */
function filterTree(nodes: CatalogNode[], q: string): CatalogNode[] {
  const out: CatalogNode[] = [];
  for (const n of nodes) {
    if (n.label.toLowerCase().includes(q)) { out.push(n); continue; }
    if (n.children) {
      const kids = filterTree(n.children, q);
      if (kids.length) out.push({ ...n, children: kids });
    }
  }
  return out;
}

function TickBox({ state }: { state: "all" | "some" | "none" }) {
  return (
    <span className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-[3px] border transition ${
      state === "none" ? "border-slate-600 bg-bg" : "border-cyber-400 bg-cyber-500/80 text-bg"
    }`}>
      {state === "all" && <Check className="h-3 w-3" strokeWidth={3} />}
      {state === "some" && <Minus className="h-3 w-3" strokeWidth={3} />}
    </span>
  );
}

export function ModuleTree({
  tree, selected, onToggle, className = "",
}: {
  tree: CatalogNode[];
  selected: ReadonlySet<string>;
  /** Select (true) or deselect (false) these leaf keys, in tree order. */
  onToggle: (keys: string[], select: boolean) => void;
  className?: string;
}) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const query = q.trim().toLowerCase();
  const shown = useMemo(() => (query ? filterTree(tree, query) : tree), [tree, query]);

  function toggleOpen(key: string) {
    setOpen(s => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n; });
  }

  function render(n: CatalogNode, depth: number): React.ReactNode {
    const keys = leafKeys(n);
    const picked = keys.filter(k => selected.has(k)).length;
    const state = picked === 0 ? "none" : picked === keys.length ? "all" : "some";
    const isLeaf = Boolean(n.item);
    // While searching, every surviving branch is expanded.
    const expanded = !isLeaf && (query ? true : open.has(n.key));

    return (
      <li key={n.key}>
        <div className="group flex items-center gap-1 rounded pr-1 hover:bg-white/5" style={{ paddingLeft: depth * 12 }}>
          {isLeaf ? (
            <span className="w-4 shrink-0" />
          ) : (
            <button type="button" onClick={() => toggleOpen(n.key)} aria-label={expanded ? `Collapse ${n.label}` : `Expand ${n.label}`}
              className="flex h-5 w-4 shrink-0 items-center justify-center text-slate-500 hover:text-slate-200">
              <ChevronRight className={`h-3.5 w-3.5 transition-transform ${expanded ? "rotate-90" : ""}`} />
            </button>
          )}
          <button
            type="button"
            role="checkbox"
            aria-checked={state === "all" ? true : state === "some" ? "mixed" : false}
            onClick={() => onToggle(keys, state !== "all")}
            className="flex min-w-0 flex-1 items-center gap-2 py-1 text-left"
          >
            <TickBox state={state} />
            <span className={`min-w-0 flex-1 truncate text-[12px] ${isLeaf ? (state === "all" ? "text-cyber-200" : "text-slate-300") : "font-semibold text-slate-100"}`}>
              {n.label}
            </span>
            {isLeaf
              ? n.hint && <span className="shrink-0 text-[10px] uppercase tracking-wider text-slate-500">{n.hint}</span>
              : <span className="shrink-0 font-mono text-[10px] text-slate-500">{picked > 0 ? `${picked}/` : ""}{keys.length}</span>}
          </button>
        </div>
        {expanded && n.children && <ul>{n.children.map(c => render(c, depth + 1))}</ul>}
      </li>
    );
  }

  return (
    <div className={`flex min-h-0 flex-col rounded-lg border border-border bg-bg ${className}`}>
      <div className="flex items-center gap-2 border-b border-border px-2.5 py-1.5">
        <Search className="h-3.5 w-3.5 shrink-0 text-slate-500" />
        <input
          value={q} onChange={e => setQ(e.target.value)} placeholder="Search modules…"
          className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
        />
        {q && <button type="button" onClick={() => setQ("")} aria-label="Clear search" className="text-slate-500 hover:text-slate-200"><X className="h-3.5 w-3.5" /></button>}
      </div>
      <ul className="min-h-0 flex-1 overflow-y-auto p-1.5">
        {shown.length === 0
          ? <li className="px-2 py-3 text-xs text-slate-500">Nothing matches “{q}”.</li>
          : shown.map(n => render(n, 0))}
      </ul>
    </div>
  );
}
