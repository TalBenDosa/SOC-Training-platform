"use client";
import { forwardRef, memo, useCallback, useId, useImperativeHandle, useMemo, useRef, useState, type KeyboardEvent as RKeyboardEvent } from "react";
import {
  BookmarkPlus, ChevronDown, ChevronFirst, ChevronLast, ChevronLeft, ChevronRight, ChevronUp, Clock, Columns3, Copy, Filter, MoreHorizontal, Search, Timer,
} from "lucide-react";
import type { KqlColumn, KqlResult, KqlRow } from "@/lib/kql/types";
import { ChartView, kindFromResult } from "./ChartView";
import { BookmarkDialog } from "./BookmarkDialog";
import { useSentinel } from "./context";
import { fmtValue } from "./engine";
import { fmtCount, fmtDuration, fmtElapsed, toCsv } from "./helpers";
import { ColumnsButton, Popover, Tabs } from "./ui";

export interface Outcome {
  id: number;
  /** The text that ran. */
  query: string;
  /** Where that text starts in the editor. */
  blockStart: number;
  firstLine: number;
  result: KqlResult;
  ms: number;
  /** "the last 24 hours" or "the custom time range". */
  phrase: string;
}

type Op = "contains" | "notcontains" | "equals" | "notequals" | "startswith" | "gt" | "lt" | "empty";
interface ColFilter { op: Op; value: string }
const OPS: { value: Op; label: string }[] = [
  { value: "contains", label: "Contains" }, { value: "notcontains", label: "Does not contain" }, { value: "equals", label: "Equals" },
  { value: "notequals", label: "Not equal to" }, { value: "startswith", label: "Starts with" }, { value: "gt", label: "Greater than" },
  { value: "lt", label: "Less than" }, { value: "empty", label: "Is empty" },
];

type Ok = Extract<KqlResult, { ok: true }>;

function compareValues(a: unknown, b: unknown, col: KqlColumn): number {
  if (a === b) return 0;
  if (a === null || a === undefined) return -1;
  if (b === null || b === undefined) return 1;
  if (col.type === "int" || col.type === "long" || col.type === "real") return Number(a) - Number(b);
  if (col.type === "datetime") return Date.parse(String(a)) - Date.parse(String(b));
  return String(a).localeCompare(String(b));
}

function matches(raw: unknown, text: string, col: KqlColumn, f: ColFilter): boolean {
  const t = text.toLowerCase(); const v = f.value.toLowerCase();
  switch (f.op) {
    case "contains": return t.includes(v);
    case "notcontains": return !t.includes(v);
    case "equals": return t === v;
    case "notequals": return t !== v;
    case "startswith": return t.startsWith(v);
    case "empty": return text === "";
    case "gt": case "lt": {
      const numeric = col.type === "int" || col.type === "long" || col.type === "real";
      const left = numeric ? Number(raw) : col.type === "datetime" ? Date.parse(String(raw)) : NaN;
      const right = numeric ? Number(f.value) : col.type === "datetime" ? Date.parse(f.value) : NaN;
      if (Number.isNaN(left) || Number.isNaN(right)) return f.op === "gt" ? t > v : t < v;
      return f.op === "gt" ? left > right : left < right;
    }
  }
}

function pretty(v: unknown, text: string): string {
  if (v && typeof v === "object" && !(v instanceof Date) && !("ticks" in v)) return JSON.stringify(v, null, 2);
  if (typeof v === "string" && /^\s*[[{]/.test(v)) {
    try { return JSON.stringify(JSON.parse(v), null, 2); } catch { return text; }
  }
  return text;
}

async function copyText(s: string) {
  try { await navigator.clipboard.writeText(s); }
  catch {
    const t = document.createElement("textarea");
    t.value = s; document.body.appendChild(t); t.select();
    try { document.execCommand("copy"); } finally { t.remove(); }
  }
}

function FilterPopover({ col, anchor, value, onApply, onClose }: { col: KqlColumn; anchor: HTMLElement; value?: ColFilter; onApply: (f: ColFilter | null) => void; onClose: () => void }) {
  const [op, setOp] = useState<Op>(value?.op ?? "contains");
  const [text, setText] = useState(value?.value ?? "");
  return (
    <Popover anchor={anchor} onClose={onClose} width={230} role="dialog" label={`Filter ${col.name}`}>
      <form className="st-pop-pad" onSubmit={e => { e.preventDefault(); onApply({ op, value: text }); onClose(); }}>
        <strong className="st-small">Show items with value that:</strong>
        <label><span className="st-sr">Operator</span>
          <select className="st-input" value={op} onChange={e => setOp(e.target.value as Op)}>
            {OPS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        {op !== "empty" && <label><span className="st-sr">Value</span><input className="st-input" value={text} onChange={e => setText(e.target.value)} placeholder="Value" /></label>}
        <div className="st-row">
          <button type="submit" className="st-btn primary">Filter</button>
          <button type="button" className="st-btn" onClick={() => { onApply(null); onClose(); }}>Clear</button>
        </div>
      </form>
    </Popover>
  );
}

const Row = memo(function Row({ row, index, cols, selected, expanded, activeCol, checkFirst, onToggleSelect, onToggleExpand, onFocusCell, onCopy, fmt }: {
  row: KqlRow; index: number; cols: KqlColumn[]; selected: boolean; expanded: boolean; activeCol: number | null; checkFirst: boolean;
  onToggleSelect: (i: number) => void; onToggleExpand: (i: number) => void; onFocusCell: (i: number, c: number) => void;
  onCopy: (s: string) => void; fmt: (v: unknown, c: KqlColumn) => string;
}) {
  const expandCell = (
    <td className="narrow" role="gridcell">
      <button type="button" tabIndex={-1} className="st-icon-btn" style={{ width: 20, height: 20 }} aria-label={expanded ? "Collapse row" : "Expand row"} onClick={() => onToggleExpand(index)}>
        {expanded ? <ChevronDown size={13} aria-hidden /> : <ChevronRight size={13} aria-hidden />}
      </button>
    </td>
  );
  const checkCell = (
    <td className="narrow" role="gridcell">
      <input type="checkbox" tabIndex={-1} aria-label="Select row" checked={selected} onChange={() => onToggleSelect(index)} style={{ margin: 0, accentColor: "var(--st-accent)" }} />
    </td>
  );
  return (
    <tr className={selected ? "selected" : undefined} aria-expanded={expanded} aria-selected={selected} data-row={index}>
      {checkFirst ? <>{checkCell}{expandCell}</> : <>{expandCell}{checkCell}</>}
      {cols.map((c, i) => {
        const text = fmt(row[c.name], c);
        return (
          <td key={c.name} role="gridcell" tabIndex={activeCol === i ? 0 : -1} data-col={i} title={text} onFocus={() => onFocusCell(index, i)}>
            {text}
            {text !== "" && (
              <button type="button" tabIndex={-1} className="st-copy" aria-label={`Copy ${c.name}`} onClick={e => { e.stopPropagation(); onCopy(text); }}>
                <Copy size={12} aria-hidden />
              </button>
            )}
          </td>
        );
      })}
    </tr>
  );
});

function ExpandedRow({ row, span, columns, onFilter, onCopy, fmt }: {
  row: KqlRow; span: number; columns: KqlColumn[]; onFilter: (c: KqlColumn, v: unknown, exclude: boolean) => void;
  onCopy: (s: string) => void; fmt: (v: unknown, c: KqlColumn) => string;
}) {
  return (
    <tr>
      <td colSpan={span} className="st-expand">
        <div className="st-kv">
          {columns.map(c => {
            const text = fmt(row[c.name], c);
            return [
              <div key={`${c.name}-k`} className="k">{c.name}</div>,
              <div key={`${c.name}-v`} className="v">{pretty(row[c.name], text)}</div>,
              <div key={`${c.name}-a`} className="a">
                <button type="button" className="st-link" aria-label={`Include ${c.name}`} onClick={() => onFilter(c, row[c.name], false)}>Include</button>
                <button type="button" className="st-link" aria-label={`Exclude ${c.name}`} onClick={() => onFilter(c, row[c.name], true)}>Exclude</button>
                <button type="button" className="st-link" aria-label={`Copy ${c.name} value`} onClick={() => onCopy(text)}>Copy</button>
              </div>,
            ];
          })}
        </div>
      </td>
    </tr>
  );
}

export interface ResultsHandle { exportCsv: (all: boolean) => void }

export const ResultsArea = forwardRef<ResultsHandle, { outcome: Outcome; incidentId?: string; panel?: boolean; onFilter: (c: KqlColumn, v: unknown, exclude: boolean) => void }>(
function ResultsArea({ outcome, incidentId, panel = false, onFilter }, ref) {
  const { ended } = useSentinel();
  const result = outcome.result as Ok;
  const { rows } = result;
  // A query that shapes its columns keeps its order. Otherwise TimeGenerated leads, as in the portal.
  const columns = useMemo(() => {
    const shaped = /\b(project|summarize|distinct|make-series|evaluate)\b/.test(outcome.query);
    if (shaped) return result.columns;
    return [...result.columns.filter(c => c.name === "TimeGenerated"), ...result.columns.filter(c => c.name !== "TimeGenerated")];
  }, [result.columns, outcome.query]);
  const [view, setView] = useState<"results" | "chart">(result.chart && result.chart.kind !== "table" ? "chart" : "results");
  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const [filters, setFilters] = useState<Record<string, ColFilter>>({});
  const [filterAt, setFilterAt] = useState<{ col: KqlColumn; anchor: HTMLElement } | null>(null);
  const [sort, setSort] = useState<{ col: string; dir: 1 | -1 } | null>(null);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<number>>(() => new Set());
  const [expanded, setExpanded] = useState<Set<number>>(() => new Set());
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(50);
  const [active, setActive] = useState({ row: 0, col: 0 });
  const [note, setNote] = useState("");
  const [bookmarking, setBookmarking] = useState(false);
  const [searching, setSearching] = useState(false);
  const body = useRef<HTMLTableSectionElement>(null);
  const helpId = useId();

  const fmt = useCallback((v: unknown, c: KqlColumn) => fmtValue(v, c.type), []);
  const visible = useMemo(() => columns.filter(c => !hidden.has(c.name)), [columns, hidden]);

  const order = useMemo(() => {
    let idx = rows.map((_, i) => i);
    for (const [name, f] of Object.entries(filters)) {
      const col = columns.find(c => c.name === name);
      if (col) idx = idx.filter(i => matches(rows[i][name], fmt(rows[i][name], col), col, f));
    }
    const s = search.trim().toLowerCase();
    if (s) idx = idx.filter(i => visible.some(c => fmt(rows[i][c.name], c).toLowerCase().includes(s)));
    if (sort) {
      const col = columns.find(c => c.name === sort.col);
      if (col) idx = [...idx].sort((a, b) => sort.dir * compareValues(rows[a][col.name], rows[b][col.name], col));
    }
    return idx;
  }, [rows, columns, filters, search, sort, visible, fmt]);

  const pages = Math.max(1, Math.ceil(order.length / pageSize));
  const safePage = Math.min(page, pages - 1);
  const pageIdx = useMemo(() => order.slice(safePage * pageSize, safePage * pageSize + pageSize), [order, safePage, pageSize]);

  const flash = useCallback((s: string) => {
    setNote(s);
    window.setTimeout(() => setNote(n => (n === s ? "" : n)), 2500);
  }, []);
  const onCopy = useCallback((s: string) => { void copyText(s); flash("Copied"); }, [flash]);

  useImperativeHandle(ref, () => ({
    exportCsv(all) {
      const cols = all ? columns : visible;
      const csv = toCsv(cols.map(c => c.name), order.map(i => cols.map(c => fmt(rows[i][c.name], c))));
      const url = URL.createObjectURL(new Blob([`﻿${csv}`], { type: "text/csv;charset=utf-8" }));
      const a = document.createElement("a");
      a.href = url; a.download = "query_data.csv"; a.click();
      URL.revokeObjectURL(url);
    },
  }), [columns, visible, order, rows, fmt]);

  const toggleSelect = useCallback((i: number) => setSelected(s => { const n = new Set(s); if (n.has(i)) n.delete(i); else n.add(i); return n; }), []);
  const toggleExpand = useCallback((i: number) => setExpanded(s => { const n = new Set(s); if (n.has(i)) n.delete(i); else n.add(i); return n; }), []);
  const onFocusCell = useCallback((r: number, c: number) => setActive({ row: r, col: c }), []);

  const allShownSelected = order.length > 0 && order.every(i => selected.has(i));
  const toggleAll = () => setSelected(allShownSelected ? new Set() : new Set(order));

  const focusCell = (rowIdx: number, col: number) => {
    setActive({ row: rowIdx, col });
    requestAnimationFrame(() => body.current?.querySelector<HTMLElement>(`tr[data-row="${rowIdx}"] td[data-col="${col}"]`)?.focus());
  };
  const onGridKey = (e: RKeyboardEvent) => {
    const at = pageIdx.indexOf(active.row);
    const go = (pos: number, col = active.col) => { const r = pageIdx[Math.max(0, Math.min(pageIdx.length - 1, pos))]; if (r !== undefined) { e.preventDefault(); focusCell(r, Math.max(0, Math.min(visible.length - 1, col))); } };
    switch (e.key) {
      case "ArrowDown": go(at + 1); break;
      case "ArrowUp": go(at - 1); break;
      case "ArrowRight": go(at, active.col + 1); break;
      case "ArrowLeft": go(at, active.col - 1); break;
      case "Home": go(e.ctrlKey ? 0 : at, 0); break;
      case "End": go(e.ctrlKey ? pageIdx.length - 1 : at, visible.length - 1); break;
      case "PageDown": e.preventDefault(); setPage(p => Math.min(p + 1, pages - 1)); break;
      case "PageUp": e.preventDefault(); setPage(p => Math.max(p - 1, 0)); break;
      case "Enter": e.preventDefault(); toggleExpand(active.row); break;
      case " ": e.preventDefault(); toggleSelect(active.row); break;
      case "c": case "C":
        if ((e.ctrlKey || e.metaKey) && !window.getSelection()?.toString()) {
          const col = visible[active.col];
          if (col) { e.preventDefault(); onCopy(fmt(rows[active.row]?.[col.name], col)); }
        }
        break;
    }
  };

  const span = visible.length + 2;
  const from = order.length ? safePage * pageSize + 1 : 0;
  const to = Math.min(order.length, (safePage + 1) * pageSize);
  const selectedRows = useMemo(() => [...selected].sort((a, b) => a - b).map(i => rows[i]), [selected, rows]);
  const firstActive = pageIdx.includes(active.row) ? active.row : pageIdx[0];
  const expandHead = <th className="narrow" scope="col"><span className="st-sr">Expand</span></th>;
  const checkHead = (
    <th className="narrow" scope="col">
      <input type="checkbox" aria-label="Select all rows" checked={allShownSelected} onChange={toggleAll} style={{ margin: 0, accentColor: "var(--st-accent)" }} />
    </th>
  );
  const toggleColumn = (n: string) => setHidden(h => { const x = new Set(h); if (x.has(n)) x.delete(n); else x.add(n); return x; });
  const columnList = columns.map(c => ({ key: c.name, label: c.name }));
  const columnsButton = <ColumnsButton columns={columnList} hidden={hidden} onToggle={toggleColumn}><Columns3 size={14} aria-hidden />Columns<ChevronDown size={12} aria-hidden /></ColumnsButton>;

  return (
    <div className="st-results">
      <div className="st-results-bar">
        <Tabs label="Results view" value={view} onChange={setView} className="st-tabs" tabClass="st-tab"
          tabs={[{ value: "results", label: "Results" }, { value: "chart", label: "Chart" }]} />
        <span className="st-cmdsep" aria-hidden />
        {!panel && columnsButton}
        {!ended && (
          <button type="button" className="st-cmd" disabled={selected.size === 0} onClick={() => setBookmarking(true)}>
            <BookmarkPlus size={14} aria-hidden />Add bookmark{selected.size > 0 ? ` (${selected.size})` : ""}
          </button>
        )}
        {!panel && <><span className="st-cmdsep" aria-hidden /><span className="st-row" style={{ gap: 6 }}><Clock size={14} color="#0078d4" aria-hidden />Display time (UTC+00:00)</span></>}
        <span className="st-grow" />
        <span role="status" aria-live="polite" className="st-small st-muted">{note}</span>
        {searching || search ? (
          <label className="st-search" style={{ width: 170 }}>
            <Search size={14} aria-hidden /><span className="st-sr">Search results</span>
            <input className="st-input" autoFocus style={{ height: 24 }} value={search} onChange={e => { setSearch(e.target.value); setPage(0); }} onBlur={() => setSearching(false)} placeholder="Search" />
          </label>
        ) : <button type="button" className="st-icon-btn" aria-label="Search results" onClick={() => setSearching(true)}><Search size={15} color="#0078d4" aria-hidden /></button>}
      </div>
      {panel ? (
        <>
          <span className="st-sr" role="status">Completed. Showing results from {outcome.phrase}. {fmtCount(rows.length)} records.</span>
          {(result.truncated || result.warnings.length > 0) && (
            <div className="st-results-status">
              {result.truncated && <span className="st-msg warn" style={{ padding: "1px 6px" }}>Partial result: limited to {fmtCount(rows.length)} records.</span>}
              {result.warnings.map(w => <span key={w} className="st-msg warn" style={{ padding: "1px 6px" }}>{w}</span>)}
            </div>
          )}
        </>
      ) : (
        <div className="st-results-status" role="status">
          <span><b>Completed.</b> Showing results from {outcome.phrase}.</span>
          {result.truncated && <span className="st-msg warn" style={{ padding: "1px 6px" }}>Partial result: limited to {fmtCount(rows.length)} records.</span>}
          {result.warnings.map(w => <span key={w} className="st-msg warn" style={{ padding: "1px 6px" }}>{w}</span>)}
          <span className="st-grow" />
          <span className="st-row st-muted" style={{ gap: 4 }}><Timer size={13} aria-hidden />{fmtDuration(outcome.ms)}</span>
          <span className="st-muted">{fmtCount(rows.length)} records</span>
        </div>
      )}
      {view === "chart" ? (
        <ChartView columns={columns} rows={rows} initial={kindFromResult(result.chart)} />
      ) : (
        <>
          <span id={helpId} className="st-sr">Arrow keys move between cells. Enter expands a row, Space selects it, Ctrl+C copies the cell, Page Up and Page Down change page.</span>
          <div className="st-grid-row">
          <div className="st-grid-wrap">
            <table className="st-grid" role="grid" aria-label="Query results" aria-rowcount={order.length + 1}
              aria-describedby={helpId}
              onKeyDown={onGridKey}>
              <thead>
                <tr>
                  {panel ? <>{checkHead}{expandHead}</> : <>{expandHead}{checkHead}</>}
                  {visible.map(c => {
                    const on = sort?.col === c.name;
                    return (
                      <th key={c.name} scope="col" aria-sort={on ? (sort!.dir === 1 ? "ascending" : "descending") : "none"}>
                        <span className="st-colhead">
                          <button type="button" className="st-sort" title={`${c.name} (${c.type})`}
                            onClick={() => { setPage(0); setSort(on ? (sort!.dir === -1 ? { col: c.name, dir: 1 } : null) : { col: c.name, dir: -1 }); }}>
                            <span>{c.name}{c.type === "datetime" ? " [UTC]" : ""}</span>
                            {on && (sort!.dir === 1 ? <ChevronUp size={12} aria-hidden /> : <ChevronDown size={12} aria-hidden />)}
                          </button>
                          <button type="button" className="st-colfilter" aria-label={`Filter ${c.name}`} data-on={!!filters[c.name]} title="Filter"
                            onClick={e => setFilterAt({ col: c, anchor: e.currentTarget })}>
                            {panel && !filters[c.name] ? <MoreHorizontal size={13} aria-hidden /> : <Filter size={12} aria-hidden fill={filters[c.name] ? "currentColor" : "none"} />}
                          </button>
                        </span>
                      </th>
                    );
                  })}
                </tr>
              </thead>
              <tbody ref={body}>
                {pageIdx.flatMap(i => {
                  const out = [
                    <Row key={i} row={rows[i]} index={i} cols={visible} selected={selected.has(i)} expanded={expanded.has(i)} checkFirst={panel}
                      activeCol={i === firstActive ? (i === active.row ? active.col : 0) : null}
                      onToggleSelect={toggleSelect} onToggleExpand={toggleExpand} onFocusCell={onFocusCell} onCopy={onCopy} fmt={fmt} />,
                  ];
                  if (expanded.has(i)) out.push(<ExpandedRow key={`x${i}`} row={rows[i]} span={span} columns={columns} onFilter={onFilter} onCopy={onCopy} fmt={fmt} />);
                  return out;
                })}
                {pageIdx.length === 0 && <tr><td colSpan={span} style={{ textAlign: "center", height: 64 }} className="st-muted">No results found from {outcome.phrase}.</td></tr>}
              </tbody>
            </table>
          </div>
          {panel && (
            <div className="st-col-rail">
              <ColumnsButton columns={columnList} hidden={hidden} onToggle={toggleColumn} className="st-col-tab"><Columns3 size={14} aria-hidden /><span>Columns</span></ColumnsButton>
            </div>
          )}
          </div>
          {panel ? (
            <div className="st-grid-foot">
              <span>{fmtElapsed(outcome.ms)}</span>
              <span className="st-row" style={{ gap: 6, marginLeft: 18 }}>Display time (UTC+00:00)</span>
              <span className="st-grow" />
              {pages > 1 && (
                <>
                  <button type="button" className="st-icon-btn" aria-label="Previous page" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}><ChevronLeft size={14} aria-hidden /></button>
                  <button type="button" className="st-icon-btn" aria-label="Next page" disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)}><ChevronRight size={14} aria-hidden /></button>
                </>
              )}
              <span className="st-cmdsep" aria-hidden />
              <span>{from} - {to} of {fmtCount(order.length)}</span>
            </div>
          ) : (
            <div className="st-grid-foot center">
              <button type="button" className="st-icon-btn" aria-label="First page" disabled={safePage === 0} onClick={() => setPage(0)}><ChevronFirst size={15} aria-hidden /></button>
              <button type="button" className="st-icon-btn" aria-label="Previous page" disabled={safePage === 0} onClick={() => setPage(safePage - 1)}><ChevronLeft size={15} aria-hidden /></button>
              <label className="st-row" style={{ gap: 6 }}>Page
                <input className="st-input" type="number" min={1} max={pages} value={safePage + 1} aria-label="Page number"
                  onChange={e => { const n = Number(e.target.value); if (n >= 1 && n <= pages) setPage(n - 1); }} />
              </label>
              <span>of {pages}</span>
              <button type="button" className="st-icon-btn" aria-label="Next page" disabled={safePage >= pages - 1} onClick={() => setPage(safePage + 1)}><ChevronRight size={15} aria-hidden /></button>
              <button type="button" className="st-icon-btn" aria-label="Last page" disabled={safePage >= pages - 1} onClick={() => setPage(pages - 1)}><ChevronLast size={15} aria-hidden /></button>
              <select className="st-input" aria-label="Items per page" value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(0); }}>
                {[50, 100, 150, 200].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
              <span>items per page</span>
              <span className="st-sr">{from} - {to} of {fmtCount(order.length)}</span>
            </div>
          )}
        </>
      )}
      {filterAt && (
        <FilterPopover col={filterAt.col} anchor={filterAt.anchor} value={filters[filterAt.col.name]} onClose={() => setFilterAt(null)}
          onApply={f => { setPage(0); setFilters(all => { const n = { ...all }; if (f) n[filterAt.col.name] = f; else delete n[filterAt.col.name]; return n; }); }} />
      )}
      {bookmarking && (
        <BookmarkDialog query={outcome.query} columns={visible} rows={selectedRows} incidentId={incidentId}
          onClose={() => setBookmarking(false)} onSaved={() => { setBookmarking(false); setSelected(new Set()); flash("Bookmark added"); }} />
      )}
    </div>
  );
});
