"use client";
// The investigation graph, in XDR's own drawing (owner, 2026-11-08: not one-to-one with Sentinel).
// Alerts are cards with a severity side stripe on a central lane, ordered by time; their entities sit
// in rows above and below as rounded tiles with icon and label inside, joined by right-angled links
// with small arrowheads. Each alert carries an Events chip; exploration queries hang off a hub with an
// X and a labelled link. Layout is deterministic: every viewer sees the same picture.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, Bookmark, Siren, ChevronDown, ChevronUp, UserRound, Clock3, Maximize, Minus, PanelRightClose, PanelRightOpen, Plus, Redo2, Search, ShieldAlert, Undo2, X,
} from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelEntity, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, InsightCard } from "./EntityCards";
import { insightsForIncident, runQuery } from "./engine";
import { alertsOf, entitiesOf, explorationsFor, fmtClock, fmtDateTime, fmtMonthDay, KIND_LABEL, type Exploration } from "./helpers";
import { Crumbs, entityIcon, StatusIcon, Tabs } from "./ui";
import { AlertCardBody, EntityTile, Kv, PaneSection, ProductChip, SevChip, TacticChips } from "./XdrParts";

const SEV_STROKE: Record<SentinelSeverity, string> = { High: "#c50f1f", Medium: "#e86c00", Low: "#a08600", Informational: "#8a8886" };
/** Node sizes: an entity is a rounded tile, an alert a wider card with a stripe. */
const ENT = { w: 172, h: 40 };
const ALR = { w: 204, h: 50 };
const half = (n: GNode) => (n.type === "alert" ? ALR : ENT);
const EDGE = "#8b5cf6";
const EDGE_LIT = "#6d28d9";

type GNode =
  | { id: string; type: "entity"; entity: SentinelEntity; x: number; y: number }
  | { id: string; type: "alert"; alert: SentinelAlert; more: SentinelAlert[]; x: number; y: number };
interface Hub { id: string; parent: string; x: number; y: number; children: string[]; label: string; query: string }
type Item = { kind: "alert"; alert: SentinelAlert } | { kind: "entity"; entity: SentinelEntity };
interface Expansion { id: string; parent: string; label: string; query: string; items: Item[] }
interface ExplorationRun { ex: Exploration; rows: Record<string, unknown>[]; count: number; fresh: Item[] }
type RailTab = "timeline" | "info" | "entities" | "insights" | "help";

/** Alerts on one central lane in time order; each entity sits above or below it, as close as rows
 * allow to the alerts that name it, so links stay short and nothing overlaps. Pure and deterministic. */
function baseLayout(alerts: SentinelAlert[], entities: SentinelEntity[]): Map<string, { x: number; y: number }> {
  const pos = new Map<string, { x: number; y: number }>();
  const AX = 300;
  alerts.forEach((a, i) => pos.set(a.id, { x: (i - (alerts.length - 1) / 2) * AX, y: 0 }));
  const wanted = entities.map((e, i) => {
    const xs = alerts.filter(a => a.entityIds.includes(e.id)).map(a => (pos.get(a.id) as { x: number }).x);
    return { e, i, x: xs.length ? xs.reduce((n, v) => n + v, 0) / xs.length : (i - (entities.length - 1) / 2) * 190 };
  }).sort((a, b) => a.x - b.x || a.i - b.i);
  const per = Math.max(4, Math.min(7, Math.ceil(wanted.length / 2)));
  const sides: (typeof wanted)[] = [[], []];
  wanted.forEach((w, i) => sides[i % 2].push(w));
  sides.forEach((list, side) => {
    const sign = side === 0 ? -1 : 1;
    for (let t = 0; t * per < list.length; t++) {
      const row = list.slice(t * per, (t + 1) * per);
      const xs: number[] = [];
      row.forEach((w, j) => xs.push(j ? Math.max(w.x, xs[j - 1] + ENT.w + 26) : w.x));
      const shift = row.reduce((n, w) => n + w.x, 0) / row.length - (xs[0] + xs[xs.length - 1]) / 2;
      row.forEach((w, j) => pos.set(w.e.id, { x: xs[j] + shift, y: sign * (150 + t * 88) }));
    }
  });
  return pos;
}

/** A right-angled link with rounded corners: down (or up) from the source, across, then to the target. */
function elbow(x1: number, y1: number, x2: number, y2: number, r = 8) {
  const my = (y1 + y2) / 2;
  if (Math.abs(x2 - x1) < 1) return { d: `M${x1},${y1}V${y2}`, mid: { x: x1, y: my } };
  const sx = Math.sign(x2 - x1); const sy = Math.sign(y2 - y1) || 1;
  const rr = Math.max(0, Math.min(r, Math.abs(x2 - x1) / 2, Math.abs(my - y1)));
  return {
    d: `M${x1},${y1}V${my - sy * rr}Q${x1},${my} ${x1 + sx * rr},${my}H${x2 - sx * rr}Q${x2},${my} ${x2},${my + sy * rr}V${y2}`,
    mid: { x: (x1 + x2) / 2, y: my },
  };
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
  const { w, h } = isAlert ? ALR : ENT;
  const x0 = -w / 2; const y0 = -h / 2;
  return (
    <g className={`st-gnode xd-gnode ${isAlert ? `alert ${node.alert.severity}` : `ent k-${node.entity.kind}`}${selected ? " on" : ""}${hovered ? " hover" : ""}${dim ? " dim" : ""}`}
      transform={`translate(${node.x},${node.y})`} tabIndex={0} role="button" aria-label={aria} aria-pressed={selected}
      data-node={node.id} onClick={e => { e.stopPropagation(); onSelect(node.id); }}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); onSelect(node.id); } }}
      onMouseEnter={() => onHover(node.id)} onMouseLeave={onLeave} onFocus={() => onHover(node.id)} onBlur={onLeave} onPointerDown={e => e.stopPropagation()}>
      <title>{label}</title>
      {isAlert ? (
        <>
          {node.more.length > 0 && <rect className="xd-gbox stack" x={x0 + 6} y={y0 - 6} width={w} height={h} rx={5} />}
          <rect className="st-gfocus xd-gbox" x={x0} y={y0} width={w} height={h} rx={5} />
          <rect x={x0} y={y0} width={6} height={h} rx={3} fill={SEV_STROKE[node.alert.severity]} />
          <rect x={x0 + 3} y={y0} width={3} height={h} fill={SEV_STROKE[node.alert.severity]} />
          <Icon x={x0 + 14} y={-9} width={18} height={18} color={SEV_STROKE[node.alert.severity]} aria-hidden />
          <text className="xd-gname" x={x0 + 40} y={-3}>{truncate(label, 24)}</text>
          <text className="xd-gsub" x={x0 + 40} y={13}>{node.alert.severity} alert</text>
        </>
      ) : (
        <>
          <rect className="st-gfocus xd-gbox" x={x0} y={y0} width={w} height={h} rx={9} />
          <rect className="xd-gtile" x={x0 + 6} y={-14} width={28} height={28} rx={7} />
          <Icon x={x0 + 12} y={-8} width={16} height={16} aria-hidden />
          <text className="xd-gname" x={x0 + 42} y={-2}>{truncate(label, 19)}</text>
          <text className="xd-gsub" x={x0 + 42} y={12}>{KIND_LABEL[node.entity.kind]}</text>
        </>
      )}
    </g>
  );
});

/** A small rounded chip on the canvas: the way into the events behind an alert or a question. */
function EventsChip({ x, y, label, text, onOpen, testId, ...rest }: { x: number; y: number; label: string; text: string; onOpen: () => void; testId?: string; "data-events"?: string }) {
  const w = Math.min(190, 30 + text.length * 6.1);
  return (
    <g className="st-gdot xd-evchip" transform={`translate(${x},${y})`} tabIndex={0} role="button" aria-label={label} data-testid={testId} {...rest}
      onClick={e => { e.stopPropagation(); onOpen(); }} onPointerDown={e => e.stopPropagation()}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); onOpen(); } }}>
      <rect x={-w / 2} y={-10} width={w} height={20} rx={10} />
      <Activity x={-w / 2 + 7} y={-6} width={12} height={12} aria-hidden />
      <text x={-w / 2 + 23} y={4}>{text}</text>
    </g>
  );
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
  const { ws, tables, stateOf, openLogs, openEntity, go, actions } = useSentinel();
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
      // Straight out from the parent, away from the alert lane; the results line up in rows of four.
      const dir = parent.y < 0 ? -1 : 1;
      const hub: Hub = { id: ex.id, parent: ex.parent, x: parent.x, y: parent.y + dir * (half(parent).h / 2 + 58), children: [], label: ex.label, query: ex.query };
      const list = stackItems(ex.items);
      const PER = 4;
      list.forEach(({ item, more }, i) => {
        const id = item.kind === "alert" ? item.alert.id : item.entity.id;
        hub.children.push(id);
        ids.add(id);
        more.forEach(m => ids.add(m.id));
        if (nodes.has(id)) return;
        const row = Math.floor(i / PER); const inRow = Math.min(PER, list.length - row * PER); const j = i % PER;
        const x = hub.x + (j - (inRow - 1) / 2) * 214; const y = hub.y + dir * (70 + row * 64);
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

  // One right-angled link from each alert to each of its entities, leaving the card on the entity's side.
  const trunks = useMemo(() => alerts.flatMap(alert => {
    const from = graph.nodes.get(alert.id);
    const targets = alert.entityIds.map(id => graph.nodes.get(id)).filter((n): n is GNode => !!n);
    if (!from) return [];
    const links = targets.map(n => {
      const down = n.y >= from.y ? 1 : -1;
      return { id: n.id, ...elbow(from.x, from.y + down * ALR.h / 2, n.x, n.y - down * (half(n).h / 2 + 2)) };
    });
    return [{ alert, from, links }];
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
    const minX = Math.min(...xs) - 150; const maxX = Math.max(...xs) + 150; const minY = Math.min(...ys) - 70; const maxY = Math.max(...ys) + 70;
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
  const reach = hoverNode ? (half(hoverNode).w / 2) * view.k + 10 : 0;
  const flip = !!at && at.x + reach + 300 > size.w;
  const panelTop = at ? Math.max(4 - at.y, Math.min(-18, size.h - at.y - 210)) : 0;

  const selectedNode = selected ? graph.nodes.get(selected) : undefined;
  const logs = (query: string) => openLogs({ query, run: true, incidentId: incident.id });

  const renderRun = (nodeId: string, entry: ExplorationRun) => {
    const I = iconFor(entry.ex);
    return (
    <div key={entry.ex.id} className="q">
      <button type="button" disabled={!entry.fresh.length} onClick={() => explore(nodeId, entry)}
        title={entry.count === 0 ? "No results" : entry.fresh.length ? entry.ex.label : "Everything this query found is already on the graph"}>
        <I size={13} aria-hidden className="xd-qicon" />{entry.ex.label} ({entry.count})
      </button>
      <button type="button" className="st-link" aria-label={`Events for ${entry.ex.label}`} onClick={() => logs(entry.ex.query)}>Events&gt;</button>
    </div>
    );
  };

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
    { value: "timeline", label: "Timeline" },
    { value: "info", label: "Info" },
    { value: "entities", label: "Entities" },
    { value: "insights", label: "Insights" },
    { value: "help", label: "Help" },
  ];
  const timelineFocus = rail === "timeline" && selectedNode?.type === "alert" ? selectedNode.alert : null;

  return (
    <div ref={useFocusOnMount()} tabIndex={-1} className="st-inv" role="region" aria-label="Investigation">
      <Crumbs trailing items={[{ label: "Home", onClick: () => { onClose(); go("overview"); } }, { label: "XDR", onClick: onClose }, { label: "Incident", onClick: onClose }]} />
      <div className="st-inc-head" style={{ alignItems: "center" }}>
        <h1 className="st-grow st-inv-title">Investigation</h1>
        <button type="button" className="st-icon-btn" aria-label="Close investigation" onClick={onClose}><X size={18} aria-hidden /></button>
      </div>
      <div className="st-cmdbar st-inv-cmd" role="toolbar" aria-label="Investigation commands">
        <button type="button" className="st-cmd" disabled={!expansions.length} onClick={undo}><Undo2 size={15} aria-hidden />Undo</button>
        <button type="button" className="st-cmd" disabled={!undone.length} onClick={redo}><Redo2 size={15} aria-hidden />Redo</button>
      </div>
      <div className="st-inv-summary">
        <div style={{ minWidth: 0 }}><b><Siren size={20} color="#6d28d9" aria-hidden /><span className="st-ellipsis" style={{ maxWidth: 380 }} title={incident.title}>{incident.title}</span></b><span>Incident</span></div>
        <div><b><i className={`st-band ${state.severity}`} style={{ height: 22, width: 5 }} aria-hidden />{state.severity}</b><span>Severity</span></div>
        <div><b><StatusIcon status={state.status} size={20} />{state.status}</b><span>Status</span></div>
        <div><b><UserRound size={20} color="#6d28d9" aria-hidden />{state.owner ?? "Unassigned"}</b><span>Owner</span></div>
        <div><b><Clock3 size={20} color="#6d28d9" aria-hidden />{fmtDateTime(incident.lastUpdate)}</b><span>Last incident update time</span></div>
      </div>
      <div className="st-inv-main">
        <div ref={canvas} className={`st-canvas${panning ? " panning" : ""}`} tabIndex={0} role="group"
          aria-label="Investigation graph. Arrow keys pan, plus and minus zoom. Tab moves between nodes."
          onPointerDown={onPanStart} onKeyDown={onCanvasKey} onWheel={e => zoom(e.deltaY < 0 ? 1.08 : 1 / 1.08)}
          onClick={() => { if (!dragged.current) setSelected(null); }}>
          <svg aria-hidden={false}>
            <defs>
              <marker id="xd-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0.5,0.8L7,4L0.5,7.2Z" fill={EDGE} /></marker>
              <marker id="xd-arrow-lit" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0.5,0.8L7,4L0.5,7.2Z" fill={EDGE_LIT} /></marker>
            </defs>
            <g transform={`translate(${cx},${cy}) scale(${view.k})`}>
              {trunks.map(t => {
                const on = !lit || lit.has(t.alert.id);
                const strong = !!lit && on;
                return (
                  <g key={t.alert.id} className={`xd-edges${strong ? " lit" : ""}`} opacity={on ? 1 : .16}>
                    {t.links.map(l => {
                      const branchOn = !lit || lit.has(l.id);
                      return <path key={l.id} d={l.d} className="xd-edge" markerEnd={strong ? "url(#xd-arrow-lit)" : "url(#xd-arrow)"} opacity={branchOn ? 1 : .25} />;
                    })}
                    <EventsChip x={t.from.x + ALR.w / 2 + 38} y={t.from.y} text="Events" label={`Events for ${t.alert.name}`} data-events={t.alert.id} onOpen={() => logs(t.alert.query)} />
                  </g>
                );
              })}
              {graph.hubs.map(h => {
                const p = graph.nodes.get(h.parent);
                if (!p) return null;
                const dir = h.y < p.y ? -1 : 1;
                const y1 = p.y + dir * (half(p).h / 2 + 2);
                return (
                  <g key={h.id} data-testid="graph-hub" className="xd-edges">
                    <path d={`M${p.x},${y1}V${h.y}`} className="xd-edge dashed" />
                    {h.children.map(c => {
                      const n = graph.nodes.get(c);
                      if (!n) return null;
                      const d = elbow(h.x, h.y, n.x, n.y - dir * (half(n).h / 2 + 2), 6).d;
                      return <path key={c} data-testid="graph-link" d={d} className="xd-edge" markerEnd="url(#xd-arrow)" />;
                    })}
                    <EventsChip x={p.x} y={(y1 + h.y) / 2 - dir * 2} text={truncate(h.label, 28)} label={`Events for ${h.label}`} onOpen={() => logs(h.query)} />
                    <g className="st-gdot xd-hub" transform={`translate(${h.x},${h.y})`} tabIndex={0} role="button" aria-label={`Remove ${h.label}`} data-hub={h.id}
                      onClick={e => { e.stopPropagation(); removeHub(h); }} onPointerDown={e => e.stopPropagation()}
                      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); e.stopPropagation(); removeHub(h); } }}>
                      <rect x={-9} y={-9} width={18} height={18} rx={4} /><X x={-6} y={-6} width={12} height={12} strokeWidth={2.5} aria-hidden />
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
          <ul className="xd-legend" aria-label="Graph legend" onPointerDown={e => e.stopPropagation()}>
            <li><i className="sw alert" aria-hidden />Alert</li>
            <li><i className="sw ent" aria-hidden />Entity</li>
            <li><i className="sw ev" aria-hidden />Events</li>
            <li className="sep" aria-hidden />
            {(["High", "Medium", "Low", "Informational"] as SentinelSeverity[]).map(s => <li key={s}><i className="sq" style={{ background: SEV_STROKE[s] }} aria-hidden />{s}</li>)}
          </ul>
          <div className="xd-zoom" role="group" aria-label="Zoom" onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()}>
            <button type="button" aria-label="Zoom out" title="Zoom out" onClick={() => zoom(1 / 1.2)}><Minus size={15} aria-hidden /></button>
            <span className="pct" aria-live="off">{Math.round(view.k * 100)}%</span>
            <button type="button" aria-label="Zoom in" title="Zoom in" onClick={() => zoom(1.2)}><Plus size={15} aria-hidden /></button>
            <button type="button" aria-label="Fit graph" title="Fit" onClick={fit}><Maximize size={14} aria-hidden /></button>
          </div>
          {span && (
            <button type="button" className="st-relevents" aria-expanded={stripOpen} onPointerDown={e => e.stopPropagation()} onClick={e => { e.stopPropagation(); setStripOpen(o => !o); }}>
              {stripOpen ? <ChevronDown size={14} aria-hidden /> : <ChevronUp size={14} aria-hidden />}View related events
            </button>
          )}
          {hoverNode && at && (
            <div className="st-explore-at" style={{ left: at.x, top: at.y }} onMouseEnter={holdHover} onMouseLeave={onLeave} onPointerDown={e => e.stopPropagation()} onClick={e => e.stopPropagation()}>
              <div className="st-explore xd-explore" style={{ top: panelTop, ...(flip ? { right: reach } : { left: reach }) }} role="group" aria-label="Exploration queries">
                <div className="xd-explore-head st-ellipsis">{hoverNode.type === "alert" ? "Alert" : `Explore ${KIND_LABEL[hoverNode.entity.kind].toLowerCase()}`}</div>
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
        {rail ? (
          <aside className="st-railpane xd-side" aria-label={rail}>
            <div className="xd-side-top">
              <Tabs label="Investigation side pane" value={rail} onChange={setRail} className="xd-side-tabs" tabClass="xd-side-tab" tabs={tabs} />
              <button type="button" className="st-icon-btn" aria-label="Collapse side pane" title="Collapse side pane" onClick={() => setRail(null)}><PanelRightClose size={15} aria-hidden /></button>
            </div>
            {timelineFocus && (
              <div className={`xd-side-focus ${timelineFocus.severity}`}><ShieldAlert size={16} aria-hidden /><span className="st-ellipsis st-grow" title={timelineFocus.name}>{timelineFocus.name}</span></div>
            )}
            <div className="st-railpane-body">
              {rail === "timeline" && (
                <ol className="xd-tl">
                  {alerts.map(a => (
                    <li key={a.id} className="xd-tl-item">
                      <button type="button" className={`xd-alert-card ${a.severity}`} aria-current={selected === a.id ? "true" : undefined} onClick={() => setSelected(s => (s === a.id ? null : a.id))}
                        onMouseEnter={() => setHighlight(neighbours.get(a.id) ?? new Set([a.id]))} onMouseLeave={() => setHighlight(null)}>
                        <AlertCardBody alert={a} entities={a.entityIds.map(id => ws.entities[id]).filter(Boolean)} maxEntities={2} dense />
                      </button>
                    </li>
                  ))}
                  {state.bookmarks.map(b => (
                    <li key={b.id} className="xd-tl-item">
                      <button type="button" className="xd-alert-card bm" onClick={() => logs(b.query)}>
                        <span className="xd-ac-top"><span className="xd-ac-title st-ellipsis"><Bookmark size={13} aria-hidden style={{ verticalAlign: -2, marginRight: 4 }} />{b.name}</span><time className="xd-ac-time" dateTime={b.at}>{fmtClock(b.at)}</time></span>
                        <span className="xd-ac-chips"><span className="xd-chip prod">{fmtDateTime(b.at)}, {b.author}</span></span>
                      </button>
                    </li>
                  ))}
                </ol>
              )}
              {rail === "info" && (
                selectedNode?.type === "entity" ? (
                  <>
                    <div className="st-row" style={{ marginBottom: 10 }}><EntityTile kind={selectedNode.entity.kind} size={34} /><span style={{ minWidth: 0 }}><strong style={{ fontSize: 15, display: "block" }} className="st-ellipsis">{selectedNode.entity.name}</strong><span className="st-small st-muted">{KIND_LABEL[selectedNode.entity.kind]}</span></span></div>
                    {selectedRuns.length > 0 && (
                      <div className="st-explore-rail">
                        <div className="xd-k" style={{ marginBottom: 2 }}>Exploration queries</div>
                        {selectedRuns.map(r => renderRun(selectedNode.id, r))}
                      </div>
                    )}
                    <EntityInfoCard entity={selectedNode.entity} />
                  </>
                ) : selectedNode?.type === "alert" ? (
                  <>
                    <div className={`xd-alert-card static ${selectedNode.alert.severity}`}>
                      <span className="xd-ac-top"><span className="xd-ac-title" style={{ whiteSpace: "normal" }}>{selectedNode.alert.name}</span></span>
                      <span className="xd-ac-chips"><SevChip value={selectedNode.alert.severity} /><ProductChip product={selectedNode.alert.product} /></span>
                    </div>
                    {selectedNode.more.length > 0 && <p className="st-small st-muted" style={{ marginTop: 6 }}>And {selectedNode.more.length} more alerts with this name.</p>}
                    <PaneSection title="Details">
                      <Kv k="Description">{selectedNode.alert.description || "--"}</Kv>
                      <Kv k="Product name">{selectedNode.alert.product}</Kv>
                      <Kv k="Time generated">{fmtDateTime(selectedNode.alert.time)}</Kv>
                      <Kv k="Tactics">{selectedNode.alert.tactics.length ? <span className="xd-ac-chips wrap"><TacticChips tactics={selectedNode.alert.tactics} max={6} /></span> : "--"}</Kv>
                    </PaneSection>
                    <button type="button" className="st-link" style={{ marginTop: 8 }} aria-label={`Events for ${selectedNode.alert.name}`} onClick={() => logs(selectedNode.alert.query)}>Events&gt;</button>
                  </>
                ) : (
                  <>
                    <strong>{incident.title}</strong>
                    <p className="st-small st-muted" style={{ marginTop: 4, whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{incident.description || "Select a node on the graph to see its details."}</p>
                    <PaneSection title="On the graph">
                      <Kv k="Alerts">{alerts.length}</Kv>
                      <Kv k="Entities">{entities.length}</Kv>
                    </PaneSection>
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
                      <li key={n.id} className={`xd-erow${selected === n.id ? " on" : ""}`}>
                        <button type="button" className="xd-erow-main" onClick={() => onSelect(n.id)} onMouseEnter={() => setHighlight(new Set([n.id]))} onMouseLeave={() => setHighlight(null)}>
                          <EntityTile kind={n.entity.kind} size={24} /><span className="xd-ename st-ellipsis">{n.entity.name}</span><span className="st-small st-muted">{KIND_LABEL[n.entity.kind]}</span>
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
                  <li>The Events chip beside an alert, or on a question&apos;s link, opens the rows behind it. The X on a junction removes what that question added.</li>
                  <li>Drag the canvas to pan. Use the zoom buttons or the wheel to zoom.</li>
                </ul>
              )}
            </div>
            {rail === "info" && selectedNode?.type === "entity" && ws.entities[selectedNode.entity.id] && (
              <div className="st-preview-foot"><button type="button" className="st-btn primary" onClick={() => openEntity(selectedNode.entity.id)}>View full details</button></div>
            )}
          </aside>
        ) : (
          <button type="button" className="xd-side-open" aria-label="Open side pane" title="Open side pane" onClick={() => setRail("timeline")}><PanelRightOpen size={16} aria-hidden /></button>
        )}
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
              <button key={b.id} type="button" className="st-strip-dot bookmark" style={{ left: `${stripPos(b.at)}%`, background: "#6d28d9" }} aria-label={`Bookmark ${b.name}, ${fmtDateTime(b.at)}`} title={b.name}
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
