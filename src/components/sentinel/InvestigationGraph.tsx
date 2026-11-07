"use client";
// The investigation graph: alerts and entities on a pannable canvas. Layout is deterministic, so
// every viewer sees the same picture. Exploration queries run through KQL and hang off a hub node.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bookmark, Briefcase, ChevronsRight, Clock, Info, Lightbulb, ListTree, Maximize, Minus, Plus, Redo2, Search, ShieldAlert, Undo2, Users, X,
} from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelEntity, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, InsightCard } from "./EntityCards";
import { insightsForIncident, runQuery } from "./engine";
import { alertsOf, entitiesOf, explorationsFor, fmtClock, fmtDateTime, fmtMonthDay, KIND_LABEL, type Exploration } from "./helpers";
import { Crumbs, EntityIcon, entityIcon, Tabs } from "./ui";

const SEV_STROKE: Record<SentinelSeverity, string> = { High: "#d13438", Medium: "#ff8c00", Low: "#c8a600", Informational: "#8a8886" };

type GNode =
  | { id: string; type: "entity"; entity: SentinelEntity; x: number; y: number }
  | { id: string; type: "alert"; alert: SentinelAlert; x: number; y: number };
interface Hub { id: string; parent: string; x: number; y: number; children: string[]; label: string }
interface Expansion { id: string; parent: string; label: string; items: ({ kind: "alert"; alert: SentinelAlert } | { kind: "entity"; entity: SentinelEntity })[] }

/** Alerts on an inner ring, entities evenly round an outer one, ordered by where their alerts sit, so
 * nothing overlaps and links cross as little as a ring allows. Pure and deterministic. */
function baseLayout(alerts: SentinelAlert[], entities: SentinelEntity[]): Map<string, { x: number; y: number }> {
  const pos = new Map<string, { x: number; y: number }>();
  const ra = alerts.length <= 1 ? 0 : Math.max(110, (alerts.length * 96) / (Math.PI * 2));
  alerts.forEach((a, i) => {
    const t = (i / Math.max(1, alerts.length)) * Math.PI * 2 - Math.PI / 2;
    pos.set(a.id, { x: Math.cos(t) * ra * 1.25, y: Math.sin(t) * ra * .85 });
  });
  const re = Math.max(250, ra + 170, (entities.length * 112) / (Math.PI * 2));
  const wanted = entities.map((e, i) => {
    const links = alerts.filter(a => a.entityIds.includes(e.id)).map(a => pos.get(a.id) as { x: number; y: number });
    const mx = links.reduce((sum, p) => sum + p.x, 0); const my = links.reduce((sum, p) => sum + p.y, 0);
    return { e, i, angle: links.length && (Math.abs(mx) > 1 || Math.abs(my) > 1) ? Math.atan2(my, mx) : (i / entities.length) * Math.PI * 2 - Math.PI };
  }).sort((a, b) => a.angle - b.angle || a.i - b.i);
  wanted.forEach((w, i) => {
    const t = (i / Math.max(1, wanted.length)) * Math.PI * 2 + (wanted[0]?.angle ?? 0);
    pos.set(w.e.id, { x: Math.cos(t) * re * 1.35, y: Math.sin(t) * re * .9 });
  });
  return pos;
}

function truncate(s: string, n: number) { return s.length > n ? `${s.slice(0, n - 1)}...` : s; }

const GraphNode = memo(function GraphNode({ node, selected, dim, onSelect, onHover, onLeave }: {
  node: GNode; selected: boolean; dim: boolean; onSelect: (id: string) => void; onHover: (id: string) => void; onLeave: () => void;
}) {
  const label = node.type === "alert" ? node.alert.name : node.entity.name;
  const aria = node.type === "alert" ? `Alert ${label}, ${node.alert.severity} severity` : `${KIND_LABEL[node.entity.kind]} ${label}`;
  const Icon = node.type === "entity" ? entityIcon(node.entity.kind) : ShieldAlert;
  return (
    <g className={`st-gnode${dim ? " dim" : ""}`} transform={`translate(${node.x},${node.y})`} tabIndex={0} role="button" aria-label={aria} aria-pressed={selected}
      data-node={node.id} onClick={e => { e.stopPropagation(); onSelect(node.id); }}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); onSelect(node.id); } }}
      onMouseEnter={() => onHover(node.id)} onMouseLeave={onLeave} onFocus={() => onHover(node.id)} onBlur={onLeave} onPointerDown={e => e.stopPropagation()}>
      {node.type === "alert" ? (
        <>
          <circle className="st-gfocus" r={29} fill="#f3f2f1" stroke={SEV_STROKE[node.alert.severity]} strokeWidth={3} />
          <circle r={24} fill="#323130" />
          <Icon x={-11} y={-11} width={22} height={22} color="#fff" aria-hidden />
        </>
      ) : (
        <>
          <circle className="st-gfocus" r={20} fill="#fff" stroke={selected ? "#0078d4" : "#c8c6c4"} strokeWidth={selected ? 2 : 1} />
          <Icon x={-9} y={-9} width={18} height={18} color="#323130" aria-hidden />
        </>
      )}
      {selected && node.type === "alert" && <circle r={33} fill="none" stroke="#0078d4" strokeWidth={2} />}
      <text y={node.type === "alert" ? 44 : 34} textAnchor="middle"><title>{label}</title>{truncate(label, 22)}</text>
    </g>
  );
});

function curve(x1: number, y1: number, x2: number, y2: number, bend = .14) {
  const mx = (x1 + x2) / 2; const my = (y1 + y2) / 2;
  const dx = x2 - x1; const dy = y2 - y1;
  return `M${x1},${y1}Q${mx - dy * bend},${my + dx * bend} ${x2},${y2}`;
}

function resolve(ws: ReturnType<typeof useSentinel>["ws"], exploration: Exploration, rows: Record<string, unknown>[], exclude: string): Expansion["items"] {
  const out: Expansion["items"] = [];
  const seen = new Set<string>([exclude]);
  for (const p of exploration.pick) {
    for (const r of rows) {
      const value = r[p.col];
      if (value === null || value === undefined || value === "") continue;
      const name = String(value);
      if (p.kind === "alert") {
        if (seen.has(name)) continue;
        seen.add(name);
        const alert = ws.alerts.find(a => a.id === name);
        if (alert) out.push({ kind: "alert", alert });
      } else {
        const id = `${p.kind}:${name.toLowerCase()}`;
        if (seen.has(id)) continue;
        seen.add(id);
        out.push({ kind: "entity", entity: ws.entities[id] ?? { id, kind: p.kind as EntityKind, name, info: { Source: exploration.label } } });
      }
      if (out.length >= 12) return out;
    }
  }
  return out;
}

type RailTab = "timeline" | "info" | "entities" | "insights";
interface ExplorationRun { ex: Exploration; rows: Record<string, unknown>[]; count: number; fresh: Expansion["items"] }

export function InvestigationGraph({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { ws, tables, stateOf, openLogs, go, actions } = useSentinel();
  const state = stateOf(incident.id);
  const alerts = useMemo(() => alertsOf(incident, ws).sort((a, b) => Date.parse(a.time) - Date.parse(b.time)), [incident, ws]);
  const entities = useMemo(() => entitiesOf(incident, ws), [incident, ws]);
  const insights = useMemo(() => insightsForIncident(incident, ws), [incident, ws]);

  const [expansions, setExpansions] = useState<Expansion[]>([]);
  const [undone, setUndone] = useState<Expansion[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [highlight, setHighlight] = useState<Set<string> | null>(null);
  const [view, setView] = useState({ x: 0, y: 0, k: .85 });
  const [panning, setPanning] = useState(false);
  const [size, setSize] = useState({ w: 900, h: 520 });
  const [rail, setRail] = useState<RailTab | null>("timeline");
  const [entityQ, setEntityQ] = useState("");
  const canvas = useRef<HTMLDivElement>(null);
  const hoverTimer = useRef<number | undefined>(undefined);
  const dragged = useRef(false);

  useEffect(() => {
    const el = canvas.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const graph = useMemo(() => {
    const pos = baseLayout(alerts, entities);
    const nodes = new Map<string, GNode>();
    for (const a of alerts) { const p = pos.get(a.id) as { x: number; y: number }; nodes.set(a.id, { id: a.id, type: "alert", alert: a, ...p }); }
    for (const e of entities) { const p = pos.get(e.id) as { x: number; y: number }; nodes.set(e.id, { id: e.id, type: "entity", entity: e, ...p }); }
    const hubs: Hub[] = [];
    for (const ex of expansions) {
      const parent = nodes.get(ex.parent);
      if (!parent) continue;
      const d = Math.hypot(parent.x, parent.y) || 1;
      const ux = parent.x / d || 1; const uy = parent.y / d;
      const hub: Hub = { id: ex.id, parent: ex.parent, x: parent.x + ux * 100, y: parent.y + uy * 100, children: [], label: ex.label };
      const base = Math.atan2(uy, ux);
      const count = ex.items.length;
      ex.items.forEach((it, i) => {
        const id = it.kind === "alert" ? it.alert.id : it.entity.id;
        hub.children.push(id);
        if (nodes.has(id)) return;
        const spread = Math.min(Math.PI * 1.1, count * .42);
        const t = base + (count === 1 ? 0 : (i / (count - 1) - .5) * spread);
        const r = 84 + (i % 2) * 20;
        const x = hub.x + Math.cos(t) * r; const y = hub.y + Math.sin(t) * r;
        nodes.set(id, it.kind === "alert" ? { id, type: "alert", alert: it.alert, x, y } : { id, type: "entity", entity: it.entity, x, y });
      });
      hubs.push(hub);
    }
    return { nodes, hubs };
  }, [alerts, entities, expansions]);

  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    const link = (a: string, b: string) => { (m.get(a) ?? m.set(a, new Set([a])).get(a) as Set<string>).add(b); (m.get(b) ?? m.set(b, new Set([b])).get(b) as Set<string>).add(a); };
    for (const al of alerts) for (const id of al.entityIds) link(al.id, id);
    for (const h of graph.hubs) for (const c of h.children) link(h.parent, c);
    return m;
  }, [alerts, graph.hubs]);
  const lit = highlight ?? (hover ? neighbours.get(hover) ?? null : null);

  const baseEdges = useMemo(() => alerts.flatMap(a => a.entityIds.filter(id => graph.nodes.has(id)).map(id => ({ from: a.id, to: id, sev: a.severity }))), [alerts, graph.nodes]);

  const explorationsOf = useCallback((id: string | null): ExplorationRun[] => {
    const node = id ? graph.nodes.get(id) : undefined;
    if (!node || node.type !== "entity") return [];
    return explorationsFor(node.entity, ws).map(ex => {
      const r = runQuery(ex.query, tables, ws.now);
      const rows = r.ok ? r.rows : [];
      // What is already on the graph stays where it is: a question only adds what is new.
      const fresh = resolve(ws, ex, rows, node.id).filter(it => !graph.nodes.has(it.kind === "alert" ? it.alert.id : it.entity.id));
      return { ex, rows, count: rows.length, fresh };
    });
  }, [graph.nodes, ws, tables]);
  const hoverRuns = useMemo(() => explorationsOf(hover), [explorationsOf, hover]);
  const selectedRuns = useMemo(() => explorationsOf(selected), [explorationsOf, selected]);

  const onHover = useCallback((id: string) => { window.clearTimeout(hoverTimer.current); setHover(id); }, []);
  const onLeave = useCallback(() => { hoverTimer.current = window.setTimeout(() => setHover(null), 260); }, []);
  const holdHover = () => window.clearTimeout(hoverTimer.current);
  const onSelect = useCallback((id: string) => { setSelected(id); setRail("info"); }, []);

  const explore = (nodeId: string, entry: ExplorationRun) => {
    try { actions.queryRan({ query: entry.ex.query, ok: true, rows: entry.count, incidentId: incident.id }); } catch { /* telemetry never blocks */ }
    if (!entry.fresh.length) return;
    setExpansions(list => [...list, { id: `${nodeId}|${entry.ex.id}`, parent: nodeId, label: entry.ex.label, items: entry.fresh }]);
    setUndone([]);
    setHover(null);
  };
  const undo = () => setExpansions(l => { const last = l[l.length - 1]; if (last) setUndone(u => [...u, last]); return l.slice(0, -1); });
  const redo = () => setUndone(u => { const last = u[u.length - 1]; if (last) setExpansions(l => [...l, last]); return u.slice(0, -1); });

  const zoom = (f: number) => setView(v => ({ ...v, k: Math.max(.25, Math.min(2.5, v.k * f)) }));
  const fit = useCallback(() => {
    const pts = [...graph.nodes.values(), ...graph.hubs];
    if (!pts.length) return;
    const xs = pts.map(p => p.x); const ys = pts.map(p => p.y);
    const minX = Math.min(...xs) - 70; const maxX = Math.max(...xs) + 70; const minY = Math.min(...ys) - 60; const maxY = Math.max(...ys) + 70;
    const k = Math.max(.25, Math.min(1.4, Math.min(size.w / (maxX - minX), size.h / (maxY - minY))));
    setView({ k, x: -((minX + maxX) / 2) * k, y: -((minY + maxY) / 2) * k });
  }, [graph, size]);
  const fitted = useRef(false);
  useEffect(() => { if (!fitted.current && size.w) { fitted.current = true; fit(); } }, [fit, size.w]);

  const onPanStart = (e: React.PointerEvent) => {
    if (e.button !== 0) return;
    const sx = e.clientX; const sy = e.clientY; const v = view;
    setPanning(true);
    dragged.current = false;
    const move = (ev: PointerEvent) => {
      if (Math.abs(ev.clientX - sx) + Math.abs(ev.clientY - sy) > 3) dragged.current = true;
      setView({ ...v, x: v.x + ev.clientX - sx, y: v.y + ev.clientY - sy });
    };
    const up = () => { setPanning(false); window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };
  const onCanvasKey = (e: React.KeyboardEvent) => {
    if (e.target !== e.currentTarget) return;
    const step = 40;
    if (e.key === "ArrowLeft") setView(v => ({ ...v, x: v.x + step }));
    else if (e.key === "ArrowRight") setView(v => ({ ...v, x: v.x - step }));
    else if (e.key === "ArrowUp") setView(v => ({ ...v, y: v.y + step }));
    else if (e.key === "ArrowDown") setView(v => ({ ...v, y: v.y - step }));
    else if (e.key === "+" || e.key === "=") zoom(1.2);
    else if (e.key === "-") zoom(1 / 1.2);
    else return;
    e.preventDefault();
  };

  const cx = size.w / 2 + view.x; const cy = size.h / 2 + view.y;
  const hoverNode = hover ? graph.nodes.get(hover) : undefined;
  const pop = hoverNode ? {
    left: Math.max(4, Math.min(size.w - 256, cx + hoverNode.x * view.k + 30)),
    top: Math.max(4, Math.min(size.h - 150, cy + hoverNode.y * view.k - 20)),
  } : null;

  const selectedNode = selected ? graph.nodes.get(selected) : undefined;

  const renderRuns = (nodeId: string, runs: ExplorationRun[]) => runs.map(entry => (
    <div key={entry.ex.id} className="q">
      <button type="button" disabled={!entry.fresh.length} onClick={() => explore(nodeId, entry)}
        title={entry.count === 0 ? "No results" : entry.fresh.length ? entry.ex.label : "Everything this query found is already on the graph"}
        style={entry.fresh.length ? undefined : { color: "#797775" }}>
        {entry.ex.label} ({entry.count})
      </button>
      <button type="button" className="st-link" aria-label={`Events for ${entry.ex.label}`} onClick={() => openLogs({ query: entry.ex.query, run: true, incidentId: incident.id })}>Events &gt;</button>
    </div>
  ));

  /* time strip */
  const span = useMemo(() => {
    const times = [...alerts.map(a => Date.parse(a.time)), ...state.bookmarks.map(b => Date.parse(b.at))].filter(Number.isFinite);
    if (!times.length) return null;
    const a = Math.min(...times); const b = Math.max(...times);
    const pad = Math.max(60_000, (b - a) * .06);
    return { from: a - pad, to: b + pad };
  }, [alerts, state.bookmarks]);
  const stripPos = (iso: string) => (span ? ((Date.parse(iso) - span.from) / (span.to - span.from)) * 100 : 0);
  // Alerts raised together would sit on one spot and hide each other: they stack up instead.
  const stripLevel = useMemo(() => {
    const levels = new Map<string, number>();
    const placed: { at: number; level: number }[] = [];
    for (const a of alerts) {
      const at = stripPos(a.time);
      const taken = new Set(placed.filter(p => Math.abs(p.at - at) < 1.2).map(p => p.level));
      let level = 0;
      while (taken.has(level)) level += 1;
      placed.push({ at, level });
      levels.set(a.id, level);
    }
    return levels;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alerts, span]);
  const nodeList = useMemo(() => [...graph.nodes.values()].filter((n): n is Extract<GNode, { type: "entity" }> => n.type === "entity"), [graph.nodes]);
  const shownEntities = nodeList.filter(n => !entityQ.trim() || n.entity.name.toLowerCase().includes(entityQ.trim().toLowerCase()));

  const tabs: { value: RailTab; label: React.ReactNode }[] = [
    { value: "timeline", label: <><ListTree size={18} color="#0078d4" aria-hidden />Timeline</> },
    { value: "info", label: <><Info size={18} color="#0078d4" aria-hidden />Info</> },
    { value: "entities", label: <><Users size={18} color="#0078d4" aria-hidden />Entities</> },
    { value: "insights", label: <><Lightbulb size={18} color="#0078d4" aria-hidden />Insights</> },
  ];

  const region = useRef<HTMLDivElement>(null);
  useEffect(() => { region.current?.focus({ preventScroll: true }); }, []);

  return (
    <div ref={region} tabIndex={-1} className="st-inv" role="region" aria-label="Investigation">
      <Crumbs items={[{ label: "Home", onClick: () => { onClose(); go("overview"); } }, { label: "Sentinel", onClick: onClose }, { label: `Incident ${incident.number}`, onClick: onClose }]} />
      <div className="st-inc-head" style={{ alignItems: "center" }}>
        <h1 className="st-grow">Investigation</h1>
        <button type="button" className="st-icon-btn" aria-label="Close investigation" onClick={onClose}><X size={18} aria-hidden /></button>
      </div>
      <div className="st-cmdbar" role="toolbar" aria-label="Investigation commands" style={{ paddingLeft: 8 }}>
        <button type="button" className="st-cmd" disabled={!expansions.length} onClick={undo}><Undo2 size={14} aria-hidden />Undo</button>
        <button type="button" className="st-cmd" disabled={!undone.length} onClick={redo}><Redo2 size={14} aria-hidden />Redo</button>
      </div>
      <div className="st-inv-summary">
        <div style={{ minWidth: 0 }}><b><Briefcase size={16} color="#0078d4" aria-hidden /><span className="st-ellipsis" style={{ maxWidth: 360 }}>{incident.title}</span></b><span>Incident</span></div>
        <div><b><i className={`st-band ${state.severity}`} style={{ height: 18 }} aria-hidden />{state.severity}</b><span>Severity</span></div>
        <div><b>{state.status}</b><span>Status</span></div>
        <div><b>{state.owner ?? "Unassigned"}</b><span>Owner</span></div>
        <div><b><Clock size={15} color="#0078d4" aria-hidden />{fmtDateTime(incident.lastUpdate)}</b><span>Last incident update time</span></div>
      </div>
      <div className="st-inv-main">
        <div ref={canvas} className={`st-canvas${panning ? " panning" : ""}`} tabIndex={0} role="group"
          aria-label="Investigation graph. Arrow keys pan, plus and minus zoom. Tab moves between nodes."
          onPointerDown={onPanStart} onKeyDown={onCanvasKey} onWheel={e => zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08)}
          onClick={() => { if (!dragged.current) setSelected(null); }}>
          <svg aria-hidden={false}>
            <defs>
              <marker id="st-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#323130" /></marker>
            </defs>
            <g transform={`translate(${cx},${cy}) scale(${view.k})`}>
              {baseEdges.map(e => {
                const a = graph.nodes.get(e.from); const b = graph.nodes.get(e.to);
                if (!a || !b) return null;
                const on = !lit || (lit.has(e.from) && lit.has(e.to));
                return <path key={`${e.from}-${e.to}`} d={curve(a.x, a.y, b.x, b.y, .08)} fill="none" stroke={SEV_STROKE[e.sev]} strokeWidth={lit && on ? 2.5 : 1.75} opacity={on ? 1 : .12} />;
              })}
              {graph.hubs.map(h => {
                const p = graph.nodes.get(h.parent);
                if (!p) return null;
                return (
                  <g key={h.id} data-testid="graph-hub">
                    <path d={curve(p.x, p.y, h.x, h.y, .1)} fill="none" stroke="#323130" strokeWidth={1.5} />
                    {h.children.map(c => {
                      const n = graph.nodes.get(c);
                      if (!n) return null;
                      const d = Math.hypot(n.x - h.x, n.y - h.y) || 1;
                      const end = { x: n.x - ((n.x - h.x) / d) * 24, y: n.y - ((n.y - h.y) / d) * 24 };
                      return <path key={c} data-testid="graph-dotted" d={curve(h.x, h.y, end.x, end.y, .1)} fill="none" stroke="#323130" strokeWidth={1.5} strokeDasharray="2 4" markerEnd="url(#st-arrow)" />;
                    })}
                    <circle cx={h.x} cy={h.y} r={5} fill="#323130"><title>{h.label}</title></circle>
                  </g>
                );
              })}
              {[...graph.nodes.values()].map(n => (
                <GraphNode key={n.id} node={n} selected={n.id === selected} dim={!!lit && !lit.has(n.id)} onSelect={onSelect} onHover={onHover} onLeave={onLeave} />
              ))}
            </g>
          </svg>
          <div className="st-zoom" onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()}>
            <button type="button" aria-label="Fit graph" title="Fit" onClick={fit}><Maximize size={15} aria-hidden /></button>
            <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.2)}><Plus size={15} aria-hidden /></button>
            <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus size={15} aria-hidden /></button>
          </div>
          {hoverNode && pop && (
            <div className="st-explore" style={pop} onMouseEnter={holdHover} onMouseLeave={onLeave} onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()} role="group" aria-label="Exploration queries">
              <header>{hoverNode.type === "alert" ? "Alert" : "Exploration queries"}</header>
              {hoverNode.type === "alert" ? (
                <div className="q">
                  <span className="st-grow st-ellipsis" title={hoverNode.alert.name}>{hoverNode.alert.name}</span>
                  <button type="button" className="st-link" onClick={() => openLogs({ query: hoverNode.alert.query, run: true, incidentId: incident.id })}>Events &gt;</button>
                </div>
              ) : renderRuns(hoverNode.id, hoverRuns)}
            </div>
          )}
        </div>
        {rail && (
          <aside className="st-railpane" aria-label={rail}>
            <div className="st-railpane-head">
              <span className="st-grow" style={{ textTransform: "capitalize" }}>{rail}</span>
              <button type="button" className="st-icon-btn" aria-label="Collapse side pane" onClick={() => setRail(null)}><ChevronsRight size={15} aria-hidden /></button>
            </div>
            <div className="st-railpane-body">
              {rail === "timeline" && (
                <>
                  {alerts.map(a => (
                    <button key={a.id} type="button" className={`st-railcard ${a.severity}`} onClick={() => onSelect(a.id)}
                      onMouseEnter={() => setHighlight(new Set([a.id, ...a.entityIds]))} onMouseLeave={() => setHighlight(null)}>
                      <span className="st-row" style={{ fontWeight: 600 }}><ShieldAlert size={13} aria-hidden /><span className="st-ellipsis">{a.name}</span></span>
                      <span className="st-small st-muted" style={{ display: "block" }}>{fmtDateTime(a.time)}</span>
                      <span className="st-small st-ellipsis" style={{ display: "block" }}>{a.description}</span>
                    </button>
                  ))}
                  {state.bookmarks.map(b => (
                    <button key={b.id} type="button" className="st-railcard" onClick={() => openLogs({ query: b.query, run: true, incidentId: incident.id })}>
                      <span className="st-row" style={{ fontWeight: 600 }}><Bookmark size={13} aria-hidden /><span className="st-ellipsis">{b.name}</span></span>
                      <span className="st-small st-muted" style={{ display: "block" }}>{fmtDateTime(b.at)}, {b.author}</span>
                    </button>
                  ))}
                </>
              )}
              {rail === "info" && (
                selectedNode?.type === "entity" ? (
                  <>
                    <div className="st-row" style={{ marginBottom: 8 }}><EntityIcon kind={selectedNode.entity.kind} /><div><strong>{selectedNode.entity.name}</strong><div className="st-small st-muted">{KIND_LABEL[selectedNode.entity.kind]}</div></div></div>
                    {selectedRuns.length > 0 && (
                      <div className="st-explore-rail">
                        <div className="st-k" style={{ marginBottom: 2 }}>Exploration queries</div>
                        {renderRuns(selectedNode.id, selectedRuns)}
                      </div>
                    )}
                    <EntityInfoCard entity={selectedNode.entity} />
                  </>
                ) : selectedNode?.type === "alert" ? (
                  <>
                    <div className="st-row" style={{ alignItems: "stretch" }}><i className={`st-band ${selectedNode.alert.severity}`} aria-hidden /><strong>{selectedNode.alert.name}</strong></div>
                    <div className="st-field"><div className="k">Description</div><div className="v">{selectedNode.alert.description || "--"}</div></div>
                    <div className="st-field"><div className="k">Product name</div><div className="v">{selectedNode.alert.product}</div></div>
                    <div className="st-field"><div className="k">Time generated</div><div className="v">{fmtDateTime(selectedNode.alert.time)}</div></div>
                    <div className="st-field"><div className="k">Tactics</div><div className="v">{selectedNode.alert.tactics.join(", ") || "--"}</div></div>
                    <button type="button" className="st-link" style={{ marginTop: 8 }} onClick={() => openLogs({ query: selectedNode.alert.query, run: true, incidentId: incident.id })}>Events &gt;</button>
                  </>
                ) : (
                  <>
                    <strong>{incident.title}</strong>
                    <p className="st-small st-muted" style={{ marginTop: 4 }}>{incident.description || "Select a node on the graph to see its details."}</p>
                    <div className="st-field"><div className="k">Alerts</div><div className="v">{alerts.length}</div></div>
                    <div className="st-field"><div className="k">Entities</div><div className="v">{entities.length}</div></div>
                  </>
                )
              )}
              {rail === "entities" && (
                <>
                  <label className="st-search" style={{ marginBottom: 8 }}><Search size={14} aria-hidden /><span className="st-sr">Search entities</span>
                    <input className="st-input" value={entityQ} onChange={e => setEntityQ(e.target.value)} placeholder="Search" />
                  </label>
                  <ul>
                    {shownEntities.map(n => (
                      <li key={n.id}>
                        <button type="button" className="st-entity-row" onClick={() => onSelect(n.id)} onMouseEnter={() => setHighlight(new Set([n.id]))} onMouseLeave={() => setHighlight(null)}>
                          <EntityIcon kind={n.entity.kind} size={12} /><span className="st-ellipsis st-grow">{n.entity.name}</span><span className="st-small st-muted">{KIND_LABEL[n.entity.kind]}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {rail === "insights" && (
                selectedNode?.type === "entity"
                  ? <EntityInsightsCard entity={selectedNode.entity} />
                  : insights.map(i => <InsightCard key={i.title} insight={i} />)
              )}
            </div>
          </aside>
        )}
        <Tabs label="Investigation side pane" value={rail ?? ("" as RailTab)} onChange={setRail} className="st-rail" tabClass="" tabs={tabs} />
      </div>
      {span && (
        <div className="st-strip" aria-label="Timeline strip">
          <div className="st-small st-muted">Timeline</div>
          <div className="st-strip-track">
            {alerts.map(a => (
              <button key={a.id} type="button" className="st-strip-dot" style={{ left: `${stripPos(a.time)}%`, bottom: 2 + (stripLevel.get(a.id) ?? 0) * 13, background: SEV_STROKE[a.severity] }} aria-label={`${a.name}, ${fmtDateTime(a.time)}`} title={`${a.name}, ${fmtClock(a.time)}`}
                onMouseEnter={() => setHighlight(new Set([a.id, ...a.entityIds]))} onMouseLeave={() => setHighlight(null)} onFocus={() => setHighlight(new Set([a.id, ...a.entityIds]))} onBlur={() => setHighlight(null)}
                onClick={() => onSelect(a.id)} />
            ))}
            {state.bookmarks.map(b => (
              <button key={b.id} type="button" className="st-strip-dot bookmark" style={{ left: `${stripPos(b.at)}%`, background: "#0078d4" }} aria-label={`Bookmark ${b.name}, ${fmtDateTime(b.at)}`} title={b.name}
                onClick={() => openLogs({ query: b.query, run: true, incidentId: incident.id })} />
            ))}
          </div>
          <div className="st-strip-axis" aria-hidden>
            <span>{fmtMonthDay(new Date(span.from).toISOString())} {fmtClock(new Date(span.from).toISOString())}</span>
            <span>{fmtClock(new Date((span.from + span.to) / 2).toISOString())}</span>
            <span>{fmtMonthDay(new Date(span.to).toISOString())} {fmtClock(new Date(span.to).toISOString())}</span>
          </div>
        </div>
      )}
    </div>
  );
}
