"use client";
// One component for the Query lab and for the Query panel inside an incident.
import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent as RKeyboardEvent } from "react";
import { ArrowRightFromLine, BarChart2, ChevronDown, ChevronsDown, ChevronsRight, ChevronsUp, Clock3, Database, FileQuestion, FileCode2, BookOpenText, Play, Plus, TriangleAlert, X } from "lucide-react";
import type { KqlColumn } from "@/lib/kql/types";
import { useSentinel, type LogsRequest } from "./context";
import { runQuery, setsTimeRange } from "./engine";
import { isoToLocalInput, localInputToDate, queryBlockAt, TIME_RANGES, whereClause, type RangeKey } from "./helpers";
import { KqlEditor, type EditorHandle } from "./KqlEditor";
import { ResultsArea, type Outcome, type ResultsHandle } from "./ResultsArea";
import { SchemaPane, type SchemaTab } from "./SchemaPane";
import { ButtonMenu, Empty, Popover } from "./ui";

interface TabState { id: number; title: string; query: string; runKey: number }

function TimeRangePicker({ value, custom, setInQuery, onChange }: {
  value: RangeKey; custom: { from: string; to: string }; setInQuery: boolean;
  onChange: (key: RangeKey, custom?: { from: string; to: string }) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(custom);
  const [showCustom, setShowCustom] = useState(value === "custom");
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const label = setInQuery ? "Set in query" : value === "custom" ? "Custom" : TIME_RANGES.find(t => t.key === value)?.label;
  const valid = !!draft.from && !!draft.to && draft.from <= draft.to;
  return (
    <>
      <button ref={btn} type="button" className="st-timepill xd-timebtn" aria-haspopup="true" aria-expanded={open} aria-label={`Time range: ${label}`} onClick={() => setOpen(o => !o)}>
        <Clock3 size={14} aria-hidden /><b>{label}</b><ChevronDown size={12} aria-hidden />
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={250} role="group" label="Time range">
          {setInQuery && <div className="st-msg info" style={{ margin: 8 }}>The query filters on TimeGenerated, so this picker is ignored.</div>}
          <div role="radiogroup" aria-label="Time range">
            {TIME_RANGES.map(t => (
              <label key={t.key} className="st-opt st-check">
                <input type="radio" name="st-time-range" checked={value === t.key} onChange={() => { setShowCustom(false); onChange(t.key); close(); }} />{t.label}
              </label>
            ))}
            <label className="st-opt st-check">
              <input type="radio" name="st-time-range" checked={value === "custom" || showCustom} onChange={() => setShowCustom(true)} />Custom
            </label>
          </div>
          {showCustom && (
            <form className="st-pop-pad" onSubmit={e => { e.preventDefault(); if (valid) { onChange("custom", draft); close(); } }}>
              <label><span className="st-label">Start time (UTC)</span>
                <input className="st-input" type="datetime-local" value={draft.from} onChange={e => setDraft(d => ({ ...d, from: e.target.value }))} />
              </label>
              <label><span className="st-label">End time (UTC)</span>
                <input className="st-input" type="datetime-local" value={draft.to} onChange={e => setDraft(d => ({ ...d, to: e.target.value }))} />
              </label>
              <button type="submit" className="st-btn primary" disabled={!valid}>Apply</button>
            </form>
          )}
        </Popover>
      )}
    </>
  );
}

function QueryPane({ tab, active, panel, incidentId, schemaOpen, setSchemaOpen, schemaTab, setSchemaTab, onQuery, workspaceName }: {
  tab: TabState; active: boolean; panel: boolean; incidentId?: string; schemaOpen: boolean; setSchemaOpen: (b: boolean) => void;
  schemaTab: SchemaTab; setSchemaTab: (t: SchemaTab) => void; onQuery: (id: number, q: string) => void; workspaceName: string;
}) {
  const { ws, tables, actions } = useSentinel();
  const editor = useRef<EditorHandle>(null);
  const results = useRef<ResultsHandle>(null);
  const [rangeKey, setRangeKey] = useState<RangeKey>("24h");
  const [custom, setCustom] = useState(() => ({ from: isoToLocalInput(new Date(Date.parse(ws.now) - 86_400_000).toISOString()), to: isoToLocalInput(ws.now) }));
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [running, setRunning] = useState(false);
  // A short screen (1280x720) keeps room for the results: the editor opens at a fifth of the height.
  const OPEN_HEIGHT = useMemo(() => {
    const max = panel ? 180 : 210;
    return typeof window === "undefined" ? max : Math.round(Math.min(max, Math.max(110, window.innerHeight * 0.2)));
  }, [panel]);
  const [height, setHeight] = useState(OPEN_HEIGHT);
  const seq = useRef(0);
  const timer = useRef<number | undefined>(undefined);
  const query = tab.query;

  const setInQuery = useMemo(() => setsTimeRange(query), [query]);

  const launch = useCallback((text: string, blockStart: number, firstLine: number) => {
    if (!text.trim()) return;
    setRunning(true);
    window.clearTimeout(timer.current);
    // A tick for the spinner to paint: the engine runs on this thread.
    timer.current = window.setTimeout(() => {
      const explicit = setsTimeRange(text);
      const preset = TIME_RANGES.find(t => t.key === rangeKey);
      const to = preset ? new Date(ws.now) : localInputToDate(custom.to);
      const from = preset ? new Date(Date.parse(ws.now) - preset.ms) : localInputToDate(custom.from);
      const started = performance.now();
      const result = runQuery(text, tables, ws.now, { from, to });
      const ms = performance.now() - started;
      seq.current += 1;
      setOutcome({ id: seq.current, query: text, blockStart, firstLine, result, ms, phrase: explicit || !preset ? "the custom time range" : preset.phrase });
      setRunning(false);
      try { actions.queryRan({ query: text, ok: result.ok, rows: result.ok ? result.rows.length : 0, incidentId }); } catch { /* telemetry never blocks */ }
    }, 0);
  }, [actions, custom, incidentId, rangeKey, tables, ws.now]);

  const run = useCallback(() => {
    const selection = editor.current?.selection() ?? "";
    const cursor = editor.current?.cursor() ?? 0;
    if (selection.trim()) {
      const at = Math.max(0, query.indexOf(selection));
      launch(selection, at, query.slice(0, at).split("\n").length - 1);
      return;
    }
    const b = queryBlockAt(query, cursor);
    launch(b.text, b.start, b.firstLine);
  }, [launch, query]);

  // A link into Logs runs its whole query, once per request.
  const lastRun = useRef(0);
  useEffect(() => {
    if (tab.runKey && tab.runKey !== lastRun.current) { lastRun.current = tab.runKey; launch(tab.query, 0, 0); }
  }, [tab.runKey, tab.query, launch]);

  const onFilter = useCallback((col: KqlColumn, value: unknown, exclude: boolean) => {
    if (!outcome) return;
    const clause = whereClause(col, value, exclude);
    const b = queryBlockAt(query, outcome.blockStart);
    const end = b.end;
    const next = `${query.slice(0, end)}\n${clause}${query.slice(end)}`;
    onQuery(tab.id, next);
    launch(next.slice(b.start, end + 1 + clause.length), b.start, b.firstLine);
  }, [launch, onQuery, outcome, query, tab.id]);

  const error = useMemo(() => {
    if (!outcome || outcome.result.ok) return null;
    const e = outcome.result.error;
    // The engine counts from the text it was given, which can start mid-editor.
    const start = outcome.blockStart;
    const lineStart = start === 0 ? 0 : query.lastIndexOf("\n", start - 1) + 1;
    return { line: outcome.firstLine + e.line, column: e.line === 1 ? e.column + (start - lineStart) : e.column, message: e.message };
  }, [outcome, query]);

  const load = useCallback((q: string) => {
    const next = query.trim() ? `${query.replace(/\s+$/, "")}\n\n${q}` : q;
    onQuery(tab.id, next);
    editor.current?.setCursor(next.length);
    editor.current?.focus();
  }, [onQuery, query, tab.id]);
  const preview = useCallback((table: string) => {
    const next = query.trim() ? `${query.replace(/\s+$/, "")}\n\n${table}` : table;
    onQuery(tab.id, next);
    launch(table, next.length - table.length, next.split("\n").length - 1);
  }, [launch, onQuery, query, tab.id]);

  const onResizeKey = (e: RKeyboardEvent) => {
    if (e.key === "ArrowUp") { e.preventDefault(); setHeight(h => Math.max(80, h - 19)); }
    if (e.key === "ArrowDown") { e.preventDefault(); setHeight(h => Math.min(520, h + 19)); }
  };
  const onResizeDown = (e: React.PointerEvent) => {
    const y = e.clientY; const h = height;
    const move = (ev: PointerEvent) => setHeight(Math.max(80, Math.min(520, h + ev.clientY - y)));
    const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  const ok = outcome?.result.ok === true;

  return (
    <div className="st-grow" hidden={!active} style={active ? { display: "flex", flexDirection: "column", minHeight: 0 } : undefined}>
      <div className="st-logbar">
        <span className="st-logbar-ws xd-ws" title={`Workspace: ${workspaceName}`}><Database size={13} aria-hidden /><span className="st-sr">Workspace: </span><span className="st-ellipsis">{workspaceName}</span></span>
        <button type="button" className="st-btn primary st-runbtn" disabled={!query.trim() || running} onClick={run} title="Run (Shift+Enter)"><Play size={13} aria-hidden />Run</button>
        <TimeRangePicker value={rangeKey} custom={custom} setInQuery={setInQuery}
          onChange={(k, c) => { setRangeKey(k); if (c) setCustom(c); }} />
        {!panel && (
          <>
            <span className="st-cmdsep" aria-hidden />
            {ok ? (
              <ButtonMenu label="Export" className="st-cmd" items={[
                { label: "CSV (displayed columns)", onSelect: () => results.current?.exportCsv(false) },
                { label: "CSV (all columns)", onSelect: () => results.current?.exportCsv(true) },
              ]}><ArrowRightFromLine size={14} aria-hidden />Export<ChevronDown size={12} aria-hidden /></ButtonMenu>
            ) : <button type="button" className="st-cmd" disabled title="Run a query first"><ArrowRightFromLine size={14} aria-hidden />Export</button>}
          </>
        )}
      </div>
      <div className="st-logs-main">
        {active && (schemaOpen
          ? <SchemaPane tab={schemaTab} onTab={setSchemaTab} onInsert={t => editor.current?.insert(t)} onLoad={load} onPreview={preview} onCollapse={() => setSchemaOpen(false)} />
          : (
            <div className="st-schema-collapsed">
              <button type="button" className="st-icon-btn" aria-label="Expand data sources pane" title="Expand" onClick={() => setSchemaOpen(true)}><ChevronsRight size={15} aria-hidden /></button>
              <span aria-hidden>Data sources</span>
            </div>
          ))}
        <div className="st-logs-right">
          <KqlEditor ref={editor} value={query} onChange={q => onQuery(tab.id, q)} onRun={run} height={height} label="Query editor" error={error ? { line: error.line, column: error.column } : null} />
          {error && (
            <div className="st-editor-err" role="alert">
              <TriangleAlert size={14} aria-hidden />
              <span>Query could not be parsed at line {error.line}, column {error.column}: {error.message}</span>
            </div>
          )}
          <div className="st-editor-collapse">
            <button type="button" className="st-icon-btn" style={{ width: 20, height: 20 }} aria-label={height <= 80 ? "Expand editor" : "Collapse editor"} aria-expanded={height > 80}
              onClick={() => setHeight(h => (h <= 80 ? OPEN_HEIGHT : 80))}>{height <= 80 ? <ChevronsDown size={14} aria-hidden /> : <ChevronsUp size={14} aria-hidden />}</button>
          </div>
          <div className="st-resize" role="separator" aria-orientation="horizontal" aria-label="Resize editor" aria-valuenow={height} aria-valuemin={80} aria-valuemax={520} tabIndex={0}
            onPointerDown={onResizeDown} onKeyDown={onResizeKey} />
          {running && !outcome && <Empty title="Running..."><span className="st-spinner" aria-hidden /></Empty>}
          {outcome?.result.ok && (
            <ResultsArea key={outcome.id} ref={results} outcome={outcome} incidentId={incidentId} onFilter={onFilter} panel={panel} />
          )}
          {!running && !outcome && <Empty icon={<BarChart2 size={32} aria-hidden />} title="Ready for a query">Write KQL in the editor, or double-click a data source table, then select Run.</Empty>}
          {!running && outcome && !outcome.result.ok && <Empty icon={<FileQuestion size={32} aria-hidden />} title="The query failed">Fix the query above and run it again.</Empty>}
        </div>
      </div>
    </div>
  );
}

export function LogsPanel({ mode, request, incidentId }: {
  mode: "workspace" | "panel";
  /** A new `key` opens the query: in the active tab when that is empty, in a new tab otherwise. */
  request?: (LogsRequest & { key: number }) | null;
  incidentId?: string;
}) {
  const { ws } = useSentinel();
  const panel = mode === "panel";
  const counter = useRef(1);
  const [tabs, setTabs] = useState<TabState[]>(() => [{ id: 1, title: "Query 1", query: request?.query ?? "", runKey: request?.run ? request.key : 0 }]);
  const [activeId, setActiveId] = useState(1);
  const [schemaOpen, setSchemaOpen] = useState(!panel);
  const [schemaTab, setSchemaTab] = useState<SchemaTab>("tables");
  const seenRequest = useRef(request?.key ?? 0);

  const addTab = useCallback((query = "", runKey = 0) => {
    counter.current += 1;
    const id = counter.current;
    setTabs(t => [...t, { id, title: `Query ${id}`, query, runKey }]);
    setActiveId(id);
  }, []);

  useEffect(() => {
    if (!request || request.key === seenRequest.current) return;
    seenRequest.current = request.key;
    const open = tabs.find(t => t.id === activeId);
    if (open && !open.query.trim()) {
      setTabs(ts => ts.map(t => (t.id === activeId ? { ...t, query: request.query, runKey: request.run ? request.key : 0 } : t)));
    } else addTab(request.query, request.run ? request.key : 0);
  }, [request, tabs, activeId, addTab]);

  const onQuery = useCallback((id: number, query: string) => setTabs(ts => ts.map(t => (t.id === id ? { ...t, query } : t))), []);

  const closeTab = (id: number) => {
    setTabs(ts => {
      const rest = ts.filter(t => t.id !== id);
      if (rest.length) {
        if (id === activeId) setActiveId(rest[Math.max(0, ts.findIndex(t => t.id === id) - 1)].id);
        return rest;
      }
      counter.current += 1;
      setActiveId(counter.current);
      return [{ id: counter.current, title: `Query ${counter.current}`, query: "", runKey: 0 }];
    });
  };

  return (
    <div className="st-logs">
      {/* The panel inside an incident holds one query, as in the product. */}
      {!panel && (
        <div className="st-qtabs xd-qtabs">
          <div role="tablist" aria-label="Open queries" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            {tabs.map(t => (
              <div key={t.id} className="st-qtab xd-qtab" data-active={t.id === activeId}>
                <button type="button" role="tab" aria-selected={t.id === activeId} onClick={() => setActiveId(t.id)}><FileCode2 size={13} aria-hidden />{t.title}{t.query.trim() && <><i className="xd-dirty" aria-hidden /><span className="st-sr"> (edited)</span></>}</button>
                <button type="button" className="st-icon-btn" style={{ width: 20, height: 20 }} aria-label={`Close ${t.title}`} onClick={() => closeTab(t.id)}><X size={12} aria-hidden /></button>
              </div>
            ))}
          </div>
          <button type="button" className="st-icon-btn" style={{ alignSelf: "center", marginLeft: 4 }} aria-label="New query tab" title="New query tab" onClick={() => addTab()}><Plus size={16} aria-hidden /></button>
          <span className="st-grow" />
          <button type="button" className="st-cmd" onClick={() => { setSchemaOpen(true); setSchemaTab("queries"); }}><BookOpenText size={14} aria-hidden />Browse saved queries</button>
        </div>
      )}
      {tabs.map(t => (
        <QueryPane key={t.id} tab={t} active={t.id === activeId} panel={panel} incidentId={incidentId}
          schemaOpen={schemaOpen} setSchemaOpen={setSchemaOpen} schemaTab={schemaTab} setSchemaTab={setSchemaTab} onQuery={onQuery} workspaceName={ws.name} />
      ))}
    </div>
  );
}
