"use client";
// The investigation graph, as in investigation-map.png and related-alerts.png. An alert runs one trunk
// to a junction that branches to its entities, with an activity dot that opens its events. Exploration
// queries run through KQL and hang off a hub with an X. Layout is deterministic: every viewer sees the same picture.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, Bookmark, Siren, ChevronDown, ChevronUp, ChevronsRight, CircleHelp, CircleUserRound, Clock, Info, Lightbulb, ListTree, Maximize, Minus, Plus, Redo2, Search, ShieldAlert, Undo2, Users, X,
} from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelEntity, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, InsightCard } from "./EntityCards";
import { insightsForIncident, runQuery } from "./engine";
import { alertsOf, entitiesOf, explorationsFor, fmtClock, fmtDateTime, fmtMonthDay, KIND_LABEL, type Exploration } from "./helpers";
import { Crumbs, EntityIcon, entityIcon, StatusIcon, Tabs } from "./ui";

const SEV_STROKE: Record<SentinelSeverity, string> = { High: "var(--st-high)", Medium: "var(--st-medium)", Low: "var(--st-low)", Informational: "var(--st-info)" };
const DARK = "var(--st-node)";
const INK = "var(--st-node-ink)";
/** XDR draws an alert as a hexagon (pointy top) and an entity as a rounded square: its own graph language. */
const hex = (r: number, dx = 0, dy = 0) => Array.from({ length: 6 }, (_, i) => {
  const a = Math.PI / 6 + i * Math.PI / 3;
  return `${(dx + r * Math.cos(a)).toFixed(1)},${(dy + r * Math.sin(a)).toFixed(1)}`;
}).join(" ");

type GNode =
  | { id: string; type: "entity"; entity: SentinelEntity; x: number; y: number }
  | { id: string; type: "alert"; alert: SentinelAlert; more: SentinelAlert[]; x: number; y: number };
interface Hub { id: string; parent: string; x: number; y: number; children: string[]; label: string; query: string }
type Item = { kind: "alert"; alert: SentinelAlert } | { kind: "entity"; entity: SentinelEntity };
interface Expansion { id: string; parent: string; label: string; query: string; items: Item[] }
interface ExplorationRun { ex: Exploration; rows: Record<string, unknown>[]; count: number; fresh: Item[] }
type RailTab = "timeline" | "info" | "entities" | "insights" | "help";

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

const GraphNode = memo(function GraphNode({ node, selected, hovered, dim, onSelect, onHover, onLeave }: {
  node: GNode; selected: boolean; hovered: boolean; dim: boolean; onSelect: (id: string) => void; onHover: (id: string) => void; onLeave: () => void;
}) {
  const isAlert = node.type === "alert";
  const name = isAlert ? node.alert.name : node.entity.name;
  const label = isAlert && node.more.length ? `+ ${node.more.length + 1} ${name}` : name;
  const aria = isAlert ? `Alert ${label}, ${node.alert.severity} severity` : `${KIND_LABEL[node.entity.kind]} ${label}`;
  const Icon = isAlert ? ShieldAlert : entityIcon(node.entity.kind);
  const blue = selected || hovered;
  return (
    <g className={`st-gnode${dim ? " dim" : ""}`} transform={`translate(${node.x},${node.y})`} tabIndex={0} role="button" aria-label={aria} aria-pressed={selected}
      data-node={node.id} onClick={e => { e.stopPropagation(); onSelect(node.id); }}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); onSelect(node.id); } }}
      onMouseEnter={() => onHover(node.id)} onMouseLeave={onLeave} onFocus={() => onHover(node.id)} onBlur={onLeave} onPointerDown={e => e.stopPropagation()}>
      {isAlert ? (
        <>
          {node.more.length > 0 && <polygon points={hex(30, 7, -5)} fill="var(--st-node-ring)" stroke={SEV_STROKE[node.alert.severity]} strokeWidth={3} />}
          <polygon className="st-gfocus" points={hex(30)} fill="var(--st-node-ring)" stroke={SEV_STROKE[node.alert.severity]} strokeWidth={3} />
          <polygon points={hex(23)} fill={selected ? "var(--st-accent)" : DARK} />
          <Icon x={-12} y={-12} width={24} height={24} color={selected ? "var(--st-on-accent)" : INK} aria-hidden />
        </>
      ) : (
        <>
          <rect className="st-gfocus" x={-21} y={-21} width={42} height={42} rx={11} fill={blue ? "var(--st-accent)" : "var(--st-node-soft)"} stroke={blue ? "var(--st-accent)" : "var(--st-border-2)"} strokeWidth={1.5} />
          <Icon x={-10} y={-10} width={20} height={20} color={blue ? "var(--st-on-accent)" : "var(--st-text)"} aria-hidden />
        </>
      )}
      <text y={isAlert ? 46 : 38} textAnchor="middle"><title>{label}</title>{truncate(label, 20)}</text>
    </g>
  );
});

function curve(x1: number, y1: number, x2: number, y2: number, bend = .14) {
  const mx = (x1 + x2) / 2; const my = (y1 + y2) / 2;
  const dx = x2 - x1; const dy = y2 - y1;
  const qx = mx - dy * bend; const qy = my + dx * bend;
  return { d: `M${x1},${y1}Q${qx},${qy} ${x2},${y2}`, mid: { x: .25 * x1 + .5 * qx + .25 * x2, y: .25 * y1 + .5 * qy + .25 * y2 } };
}

function resolve(ws: ReturnType<typeof useSentinel>["ws"], exploration: Exploration, rows: Record<string, unknown>[], exclude: string): Item[] {
  const out: Item[] = [];
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
    }
  }
  return out;
}

/** Results with one name collapse: the first stands alone, the rest stack as "+ 41 name". */
function stackItems(items: Item[]): { item: Item; more: SentinelAlert[] }[] {
  const byName = new Map<string, SentinelAlert[]>();
  for (const it of items) if (it.kind === "alert") byName.set(it.alert.name, [...(byName.get(it.alert.name) ?? []), it.alert]);
  const out: { item: Item; more: SentinelAlert[] }[] = [];
  for (const it of items) {
    if (it.kind === "entity") { out.push({ item: it, more: [] }); continue; }
    const same = byName.get(it.alert.name) as SentinelAlert[];
    if (same[0] === it.alert) out.push({ item: it, more: [] });
    else if (same[1] === it.alert) out.push({ item: it, more: same.slice(2) });
  }
  return out.slice(0, 12);
}

const iconFor = (ex: Exploration) => {
  const k = ex.pick[0]?.kind;
  return !k || k === "alert" ? ShieldAlert : entityIcon(k);
};

export function InvestigationGraph({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { ws, tables, stateOf, openLogs, openEntity, actions } = useSentinel();
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
  const [moreOpen, setMoreOpen] = useState(false);
  const [stripOpen, setStripOpen] = useState(false);
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
    const ids = new Set<string>();
    for (const a of alerts) { const p = pos.get(a.id) as { x: number; y: number }; nodes.set(a.id, { id: a.id, type: "alert", alert: a, more: [], ...p }); ids.add(a.id); }
    for (const e of entities) { const p = pos.get(e.id) as { x: number; y: number }; nodes.set(e.id, { id: e.id, type: "entity", entity: e, ...p }); ids.add(e.id); }
    const hubs: Hub[] = [];
    for (const ex of expansions) {
      const parent = nodes.get(ex.parent);
      if (!parent) continue;
      const d = Math.hypot(parent.x, parent.y) || 1;
      const ux = parent.x / d || 1; const uy = parent.y / d;
      const hub: Hub = { id: ex.id, parent: ex.parent, x: parent.x + ux * 120, y: parent.y + uy * 120, children: [], label: ex.label, query: ex.query };
      const base = Math.atan2(uy, ux);
      const list = stackItems(ex.items);
      const count = list.length;
      list.forEach(({ item, more }, i) => {
        const id = item.kind === "alert" ? item.alert.id : item.entity.id;
        hub.children.push(id);
        ids.add(id);
        more.forEach(m => ids.add(m.id));
        if (nodes.has(id)) return;
        const spread = Math.min(Math.PI * 1.1, count * .5);
        const t = base + (count === 1 ? 0 : (i / (count - 1) - .5) * spread);
        const r = 110 + (i % 2) * 24;
        const x = hub.x + Math.cos(t) * r; const y = hub.y + Math.sin(t) * r;
        nodes.set(id, item.kind === "alert" ? { id, type: "alert", alert: item.alert, more, x, y } : { id, type: "entity", entity: item.entity, x, y });
      });
      hubs.push(hub);
    }
    return { nodes, hubs, ids };
  }, [alerts, entities, expansions]);

  const neighbours = useMemo(() => {
    const m = new Map<string, Set<string>>();
    const link = (a: string, b: string) => { (m.get(a) ?? m.set(a, new Set([a])).get(a) as Set<string>).add(b); (m.get(b) ?? m.set(b, new Set([b])).get(b) as Set<string>).add(a); };
    for (const al of alerts) for (const id of al.entityIds) link(al.id, id);
    for (const h of graph.hubs) for (const c of h.children) link(h.parent, c);
    return m;
  }, [alerts, graph.hubs]);
  const focus = hover ?? selected;
  const lit = highlight ?? (focus ? neighbours.get(focus) ?? new Set([focus]) : null);

  const trunks = useMemo(() => alerts.flatMap(alert => {
    const from = graph.nodes.get(alert.id);
    const targets = alert.entityIds.map(id => graph.nodes.get(id)).filter((n): n is GNode => !!n);
    if (!from || !targets.length) return [];
    const cx = targets.reduce((n, t) => n + t.x, 0) / targets.length; const cy = targets.reduce((n, t) => n + t.y, 0) / targets.length;
    const j = targets.length === 1 ? { x: targets[0].x, y: targets[0].y } : { x: from.x + (cx - from.x) * .55, y: from.y + (cy - from.y) * .55 };
    return [{ alert, from, j, targets, trunk: curve(from.x, from.y, j.x, j.y, .14) }];
  }), [alerts, graph.nodes]);

  const explorationsOf = useCallback((id: string | null): ExplorationRun[] => {
    const node = id ? graph.nodes.get(id) : undefined;
    if (!node || node.type !== "entity") return [];
    return explorationsFor(node.entity, ws).map(ex => {
      const r = runQuery(ex.query, tables, ws.now);
      const rows = r.ok ? r.rows : [];
      // What is already on the graph stays where it is: a question only adds what is new.
      const fresh = resolve(ws, ex, rows, node.id).filter(it => !graph.ids.has(it.kind === "alert" ? it.alert.id : it.entity.id));
      return { ex, rows, count: rows.length, fresh };
    });
  }, [graph.nodes, graph.ids, ws, tables]);
  const hoverRuns = useMemo(() => explorationsOf(hover), [explorationsOf, hover]);
  const selectedRuns = useMemo(() => explorationsOf(selected), [explorationsOf, selected]);

  const onHover = useCallback((id: string) => { window.clearTimeout(hoverTimer.current); setHover(h => { if (h !== id) setMoreOpen(false); return id; }); }, []);
  const onLeave = useCallback(() => { hoverTimer.current = window.setTimeout(() => setHover(null), 260); }, []);
  const holdHover = () => window.clearTimeout(hoverTimer.current);
  const onSelect = useCallback((id: string) => { setSelected(id); setRail("info"); }, []);

  const explore = (nodeId: string, entry: ExplorationRun) => {
    try { actions.queryRan({ query: entry.ex.query, ok: true, rows: entry.count, incidentId: incident.id }); } catch { /* telemetry never blocks */ }
    if (!entry.fresh.length) return;
    setExpansions(list => [...list, { id: `${nodeId}|${entry.ex.id}`, parent: nodeId, label: entry.ex.label, query: entry.ex.query, items: entry.fresh }]);
    setUndone([]);
    setHover(null);
  };
  /** The X on a hub takes its results off the graph, with anything that hung off them. */
  const removeHub = (hub: Hub) => {
    setExpansions(list => {
      const gone = new Set(hub.children);
      const keep: Expansion[] = [];
      for (const e of list) {
        if (e.id === hub.id) continue;
        if (gone.has(e.parent)) { for (const it of e.items) gone.add(it.kind === "alert" ? it.alert.id : it.entity.id); continue; }
        keep.push(e);
      }
      return keep;
    });
    setUndone([]);
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
  const at = hoverNode ? { x: cx + hoverNode.x * view.k, y: cy + hoverNode.y * view.k } : null;
  const arcR = 22 * view.k + 24;
  const flip = !!at && at.x + arcR + 340 > size.w;
  const panelTop = at ? Math.max(4 - at.y, Math.min(-52, size.h - at.y - 210)) : 0;

  const selectedNode = selected ? graph.nodes.get(selected) : undefined;
  const logs = (query: string) => openLogs({ query, run: true, incidentId: incident.id });

  const renderRun = (nodeId: string, entry: ExplorationRun) => (
    <div key={entry.ex.id} className="q">
      <button type="button" disabled={!entry.fresh.length} onClick={() => explore(nodeId, entry)}
        title={entry.count === 0 ? "No results" : entry.fresh.length ? entry.ex.label : "Everything this query found is already on the graph"}>
        {entry.ex.label} ({entry.count})
      </button>
      <button type="button" className="st-link" aria-label={`Events for ${entry.ex.label}`} onClick={() => logs(entry.ex.query)}>Events&gt;</button>
    </div>
  );

  /* time strip */
  const span = useMemo(() => {
    const times = [...alerts.map(a => Date.parse(a.time)), ...state.bookmarks.map(b => Date.parse(b.at))].filter(Number.isFinite);
    if (!times.length) return null;
    const a = Math.min(...times); const b = Math.max(...times);
    const pad = Math.max(60_000, (b - a) * .06);
    return { from: a - pad, to: b + pad };
  }, [alerts, state.bookmarks]);
  const stripPos = useCallback((iso: string) => (span ? ((Date.parse(iso) - span.from) / (span.to - span.from)) * 100 : 0), [span]);
  // Alerts raised together would sit on one spot and hide each other: they stack up instead.
  const stripLevel = useMemo(() => {
    const levels = new Map<string, number>();
    const placed: { at: number; level: number }[] = [];
    for (const a of alerts) {
      const pos = stripPos(a.time);
      const taken = new Set(placed.filter(p => Math.abs(p.at - pos) < 1.2).map(p => p.level));
      let level = 0;
      while (taken.has(level)) level += 1;
      placed.push({ at: pos, level });
      levels.set(a.id, level);
    }
    return levels;
  }, [alerts, stripPos]);
  const nodeList = useMemo(() => [...graph.nodes.values()].filter((n): n is Extract<GNode, { type: "entity" }> => n.type === "entity"), [graph.nodes]);
  const shownEntities = nodeList.filter(n => !entityQ.trim() || n.entity.name.toLowerCase().includes(entityQ.trim().toLowerCase()));

  const tabs: { value: RailTab; label: React.ReactNode }[] = [
    { value: "timeline", label: <><ListTree size={22} aria-hidden />Timeline</> },
    { value: "info", label: <><Info size={22} aria-hidden />Info</> },
    { value: "entities", label: <><Users size={22} aria-hidden />Entities</> },
    { value: "insights", label: <><Lightbulb size={22} aria-hidden />Insights</> },
    { value: "help", label: <><CircleHelp size={22} aria-hidden />Help</> },
  ];
  const RAIL_ICON: Record<RailTab, typeof ListTree> = { timeline: ListTree, info: Info, entities: Users, insights: Lightbulb, help: CircleHelp };
  const RailIcon = rail ? RAIL_ICON[rail] : ListTree;
  const timelineFocus = rail === "timeline" && selectedNode?.type === "alert" ? selectedNode.alert : null;

  return (
    <div ref={useFocusOnMount()} tabIndex={-1} className="st-inv" role="region" aria-label="Investigation">
      <Crumbs items={[{ label: `Incident ${incident.number}`, onClick: onClose }, { label: "Investigation" }]} />
      <div className="st-inc-head" style={{ alignItems: "center" }}>
        <h1 className="st-grow st-inv-title">Investigation</h1>
        <button type="button" className="st-icon-btn" aria-label="Close investigation" onClick={onClose}><X size={18} aria-hidden /></button>
      </div>
      <div className="st-cmdbar st-inv-cmd" role="toolbar" aria-label="Investigation commands">
        <button type="button" className="st-cmd" disabled={!expansions.length} onClick={undo}><Undo2 size={15} aria-hidden />Undo</button>
        <button type="button" className="st-cmd" disabled={!undone.length} onClick={redo}><Redo2 size={15} aria-hidden />Redo</button>
      </div>
      <div className="st-inv-summary">
        <div style={{ minWidth: 0 }}><b><Siren size={22} color="var(--st-accent)" aria-hidden /><span className="st-ellipsis" style={{ maxWidth: 380 }} title={incident.title}>{incident.title}</span></b><span>Incident</span></div>
        <div><b><i className={`st-band ${state.severity}`} style={{ height: 22, width: 5 }} aria-hidden />{state.severity}</b><span>Severity</span></div>
        <div><b><StatusIcon status={state.status} size={20} />{state.status}</b><span>Status</span></div>
        <div><b><CircleUserRound size={20} color="var(--st-accent)" aria-hidden />{state.owner ?? "Unassigned"}</b><span>Owner</span></div>
        <div><b><Clock size={20} color="var(--st-accent)" aria-hidden />{fmtDateTime(incident.lastUpdate)}</b><span>Last incident update time</span></div>
      </div>
      <div className="st-inv-main">
        <div ref={canvas} className={`st-canvas${panning ? " panning" : ""}`} tabIndex={0} role="group"
          aria-label="Investigation graph. Arrow keys pan, plus and minus zoom. Tab moves between nodes."
          onPointerDown={onPanStart} onKeyDown={onCanvasKey} onWheel={e => zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08)}
          onClick={() => { if (!dragged.current) setSelected(null); }}>
          <svg aria-hidden={false}>
            <defs>
              <marker id="st-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M1,1L9,5L1,9" fill="none" stroke="var(--st-edge)" strokeWidth="1.8" /></marker>
            </defs>
            <g transform={`translate(${cx},${cy}) scale(${view.k})`}>
              {trunks.map(t => {
                const on = !lit || lit.has(t.alert.id);
                const color = SEV_STROKE[t.alert.severity];
                return (
                  <g key={t.alert.id} opacity={on ? 1 : .14}>
                    <path d={t.trunk.d} fill="none" stroke={color} strokeWidth={2.5} />
                    {t.targets.length > 1 && t.targets.map(n => {
                      const branchOn = !lit || lit.has(n.id);
                      return <path key={n.id} d={curve(t.j.x, t.j.y, n.x, n.y, .16).d} fill="none" stroke={color} strokeWidth={2.5} opacity={branchOn ? 1 : .2} />;
                    })}
                    <g className="st-gdot" transform={`translate(${t.trunk.mid.x},${t.trunk.mid.y})`} tabIndex={0} role="button" aria-label={`Events for ${t.alert.name}`} data-events={t.alert.id}
                      onClick={e => { e.stopPropagation(); logs(t.alert.query); }} onPointerDown={e => e.stopPropagation()}
                      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); logs(t.alert.query); } }}>
                      <circle r={9} fill={DARK} /><Activity x={-6} y={-6} width={12} height={12} color={INK} aria-hidden />
                    </g>
                  </g>
                );
              })}
              {graph.hubs.map(h => {
                const p = graph.nodes.get(h.parent);
                if (!p) return null;
                const link = curve(p.x, p.y, h.x, h.y, .16);
                return (
                  <g key={h.id} data-testid="graph-hub">
                    <path d={link.d} fill="none" stroke="var(--st-edge)" strokeWidth={2.5} />
                    <g className="st-gdot" transform={`translate(${link.mid.x},${link.mid.y})`} tabIndex={0} role="button" aria-label={`Events for ${h.label}`}
                      onClick={e => { e.stopPropagation(); logs(h.query); }} onPointerDown={e => e.stopPropagation()}
                      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); logs(h.query); } }}>
                      <circle r={9} fill={DARK} /><Activity x={-6} y={-6} width={12} height={12} color={INK} aria-hidden />
                    </g>
                    {h.children.map(c => {
                      const n = graph.nodes.get(c);
                      if (!n) return null;
                      const d = Math.hypot(n.x - h.x, n.y - h.y) || 1;
                      const gap = n.type === "alert" ? 33 : 25;
                      const end = { x: n.x - ((n.x - h.x) / d) * gap, y: n.y - ((n.y - h.y) / d) * gap };
                      return <path key={c} data-testid="graph-link" d={curve(h.x, h.y, end.x, end.y, .18).d} fill="none" stroke="var(--st-edge)" strokeWidth={2.5} markerEnd="url(#st-arrow)" />;
                    })}
                    <g className="st-gdot" transform={`translate(${h.x},${h.y})`} tabIndex={0} role="button" aria-label={`Remove ${h.label}`} data-hub={h.id}
                      onClick={e => { e.stopPropagation(); removeHub(h); }} onPointerDown={e => e.stopPropagation()}
                      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); removeHub(h); } }}>
                      <circle r={8} fill={DARK} /><X x={-6} y={-6} width={12} height={12} color={INK} strokeWidth={3} aria-hidden />
                      <title>{h.label}</title>
                    </g>
                  </g>
                );
              })}
              {[...graph.nodes.values()].map(n => (
                <GraphNode key={n.id} node={n} selected={n.id === selected} hovered={n.id === hover} dim={!!lit && !lit.has(n.id)} onSelect={onSelect} onHover={onHover} onLeave={onLeave} />
              ))}
            </g>
          </svg>
          <div className="st-zoom" onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()}>
            <button type="button" aria-label="Fit graph" title="Fit" onClick={fit}><Maximize size={15} aria-hidden /></button>
            <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.2)}><Plus size={18} aria-hidden /></button>
            <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus size={18} aria-hidden /></button>
          </div>
          {span && (
            <button type="button" className="st-relevents" aria-expanded={stripOpen} onPointerDown={e => e.stopPropagation()} onClick={e => { e.stopPropagation(); setStripOpen(o => !o); }}>
              {stripOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronUp size={14} aria-hidden />}View related events
            </button>
          )}
          {hoverNode && at && (
            <div className="st-explore-at" style={{ left: at.x, top: at.y }} onMouseEnter={holdHover} onMouseLeave={onLeave} onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()}>
              {hoverNode.type === "entity" && hoverRuns.length > 0 && (
                <svg className="st-arc" width={(arcR + 22) * 2} height={(arcR + 22) * 2} style={{ left: -(arcR + 22), top: -(arcR + 22), transform: flip ? "scaleX(-1)" : undefined }} aria-hidden>
                  <g transform={`translate(${arcR + 22},${arcR + 22})`}>
                    <path d={`M${Math.cos(-1.15) * arcR},${Math.sin(-1.15) * arcR}A${arcR},${arcR} 0 0 1 ${Math.cos(1.3) * arcR},${Math.sin(1.3) * arcR}`} fill="none" stroke={DARK} strokeWidth={26} strokeLinecap="round" />
                    {hoverRuns.slice(0, 3).map((r, i) => {
                      const a = -.8 + i * .75; const I = iconFor(r.ex);
                      return <I key={r.ex.id} x={Math.cos(a) * arcR - 8} y={Math.sin(a) * arcR - 8} width={16} height={16} color={r.count ? INK : "var(--st-text-3)"} />;
                    })}
                    <Plus x={Math.cos(1.3) * arcR - 8} y={Math.sin(1.3) * arcR - 8} width={16} height={16} color={INK} />
                  </g>
                </svg>
              )}
              <div className="st-explore" style={{ top: panelTop, ...(flip ? { right: arcR + 18 } : { left: arcR + 18 }) }} role="group" aria-label="Exploration queries">
                {hoverNode.type === "alert" ? (
                  <div className="q">
                    <span className="st-grow st-ellipsis" title={hoverNode.alert.name}>{hoverNode.alert.name}</span>
                    <button type="button" className="st-link" aria-label={`Events for ${hoverNode.alert.name}`} onClick={() => logs(hoverNode.alert.query)}>Events&gt;</button>
                  </div>
                ) : (
                  <>
                    {hoverRuns.slice(0, 3).map(r => renderRun(hoverNode.id, r))}
                    {hoverRuns.length > 3 && (
                      <>
                        <button type="button" className="st-explore-more" aria-expanded={moreOpen} onClick={() => setMoreOpen(o => !o)}>More<ChevronDown size={14} aria-hidden /></button>
                        {moreOpen && hoverRuns.slice(3).map(r => renderRun(hoverNode.id, r))}
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          )}
        </div>
        {rail && (
          <aside className="st-railpane" aria-label={rail}>
            {timelineFocus ? (
              <div className={`st-railpane-head sev ${timelineFocus.severity}`}><ShieldAlert size={22} aria-hidden /><span className="st-ellipsis st-grow" title={timelineFocus.name}>{timelineFocus.name}</span></div>
            ) : (
              <div className="st-railpane-head"><RailIcon size={26} aria-hidden /><span className="st-grow" style={{ textTransform: "capitalize" }}>{rail}</span></div>
            )}
            <button type="button" className="st-icon-btn corner" aria-label="Collapse side pane" onClick={() => setRail(null)}><ChevronsRight size={13} aria-hidden /></button>
            <div className="st-railpane-body">
              {rail === "timeline" && (
                <ol className="st-rtl">
                  {alerts.map(a => (
                    <li key={a.id}>
                      <button type="button" className={`st-railcard ${a.severity}${selected === a.id ? " on" : ""}`} onClick={() => setSelected(s => (s === a.id ? null : a.id))}
                        onMouseEnter={() => setHighlight(neighbours.get(a.id) ?? new Set([a.id]))} onMouseLeave={() => setHighlight(null)}>
                        <span className="st-row" style={{ fontWeight: 600, fontSize: 14 }}><ShieldAlert size={15} aria-hidden /><span className="st-ellipsis">{a.name}</span></span>
                        <span className="st-small st-muted" style={{ display: "block", marginTop: 2 }}>{fmtDateTime(a.time)}</span>
                        <span className="st-small st-muted st-ellipsis" style={{ display: "block", marginTop: 2 }}>{a.description}</span>
                      </button>
                    </li>
                  ))}
                  {state.bookmarks.map(b => (
                    <li key={b.id}>
                      <button type="button" className="st-railcard" onClick={() => logs(b.query)}>
                        <span className="st-row" style={{ fontWeight: 600, fontSize: 14 }}><Bookmark size={15} aria-hidden /><span className="st-ellipsis">{b.name}</span></span>
                        <span className="st-small st-muted" style={{ display: "block", marginTop: 2 }}>{fmtDateTime(b.at)}, {b.author}</span>
                      </button>
                    </li>
                  ))}
                </ol>
              )}
              {rail === "info" && (
                selectedNode?.type === "entity" ? (
                  <>
                    <div className="st-row" style={{ marginBottom: 10 }}><EntityIcon kind={selectedNode.entity.kind} size={28} /><strong style={{ fontSize: 16 }} className="st-ellipsis">{selectedNode.entity.name}</strong></div>
                    {selectedRuns.length > 0 && (
                      <div className="st-explore-rail">
                        <div className="st-k" style={{ marginBottom: 2 }}>Exploration queries</div>
                        {selectedRuns.map(r => renderRun(selectedNode.id, r))}
                      </div>
                    )}
                    <EntityInfoCard entity={selectedNode.entity} />
                  </>
                ) : selectedNode?.type === "alert" ? (
                  <>
                    <div className="st-row" style={{ alignItems: "stretch" }}><i className={`st-band ${selectedNode.alert.severity}`} aria-hidden /><strong style={{ fontSize: 16 }}>{selectedNode.alert.name}</strong></div>
                    {selectedNode.more.length > 0 && <p className="st-small st-muted">And {selectedNode.more.length} more alerts with this name.</p>}
                    <div className="st-field"><div className="k">Description</div><div className="v">{selectedNode.alert.description || "--"}</div></div>
                    <div className="st-field"><div className="k">Product name</div><div className="v">{selectedNode.alert.product}</div></div>
                    <div className="st-field"><div className="k">Time generated</div><div className="v">{fmtDateTime(selectedNode.alert.time)}</div></div>
                    <div className="st-field"><div className="k">Tactics</div><div className="v">{selectedNode.alert.tactics.join(", ") || "--"}</div></div>
                    <button type="button" className="st-link" style={{ marginTop: 8 }} aria-label={`Events for ${selectedNode.alert.name}`} onClick={() => logs(selectedNode.alert.query)}>Events&gt;</button>
                  </>
                ) : (
                  <>
                    <strong>{incident.title}</strong>
                    <p className="st-small st-muted" style={{ marginTop: 4, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{incident.description || "Select a node on the graph to see its details."}</p>
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
                          <EntityIcon kind={n.entity.kind} size={18} /><span className="st-ellipsis st-grow">{n.entity.name}</span><span className="st-small st-muted">{KIND_LABEL[n.entity.kind]}</span>
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
              {rail === "help" && (
                <ul className="st-bullets st-stack" style={{ gap: 8 }}>
                  <li>Select an entity or alert to read about it in Info.</li>
                  <li>Hover an entity for its exploration queries. Select one to add its results to the graph, or Events&gt; to read the rows in Logs.</li>
                  <li>The dot on a link opens the events behind it. The X on a junction removes what that query added.</li>
                  <li>Drag the canvas to pan. Use the buttons or the wheel to zoom.</li>
                </ul>
              )}
            </div>
            {rail === "info" && selectedNode?.type === "entity" && ws.entities[selectedNode.entity.id] && (
              <div className="st-preview-foot"><button type="button" className="st-btn primary" onClick={() => openEntity(selectedNode.entity.id)}>View full details</button></div>
            )}
          </aside>
        )}
        <Tabs label="Investigation side pane" value={rail ?? ("" as RailTab)} onChange={setRail} className="st-rail" tabClass="" tabs={tabs} />
      </div>
      {span && stripOpen && (
        <div className="st-strip" aria-label="Timeline strip">
          <div className="st-strip-track">
            {alerts.map(a => (
              <button key={a.id} type="button" className="st-strip-dot" style={{ left: `${stripPos(a.time)}%`, bottom: 2 + (stripLevel.get(a.id) ?? 0) * 13, background: SEV_STROKE[a.severity] }} aria-label={`${a.name}, ${fmtDateTime(a.time)}`} title={`${a.name}, ${fmtClock(a.time)}`}
                onMouseEnter={() => setHighlight(neighbours.get(a.id) ?? new Set([a.id]))} onMouseLeave={() => setHighlight(null)} onFocus={() => setHighlight(neighbours.get(a.id) ?? new Set([a.id]))} onBlur={() => setHighlight(null)}
                onClick={() => onSelect(a.id)} />
            ))}
            {state.bookmarks.map(b => (
              <button key={b.id} type="button" className="st-strip-dot bookmark" style={{ left: `${stripPos(b.at)}%`, background: "var(--st-accent)" }} aria-label={`Bookmark ${b.name}, ${fmtDateTime(b.at)}`} title={b.name}
                onClick={() => logs(b.query)} />
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

function useFocusOnMount() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { ref.current?.focus({ preventScroll: true }); }, []);
  return ref;
}
