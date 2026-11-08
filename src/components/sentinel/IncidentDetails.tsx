"use client";
// The incident details page, laid out as incident-details-overview.png: toolbar, left details panel,
// Overview and Entities tabs, four widgets. Alert details open in a flyout beside the timeline.
import { memo, useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  Bookmark, Briefcase, ChevronDown, ChevronRight, ChevronsLeft, ChevronsRight, ClipboardList, Clock, Filter, Info, Lightbulb,
  ListTree, MessageSquareText, RefreshCw, Search, ShieldAlert, ShieldPlus, Target, TerminalSquare, Workflow, X,
} from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelBookmark, SentinelEntity, SentinelIncident , GraphAlertDetails } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, EntityTimelineCard, InsightCard } from "./EntityCards";
import { insightsForIncident, runQuery } from "./engine";
import {
  alertRecord, alertsOf, canAddToTi, canRunPlaybook, entitiesOf, fmtClock, fmtDateTime, fmtMediumTime, fmtMonthDay, KIND_LABEL, SEVERITIES, similarIncidents, tacticLabel, type SimilarIncident,
} from "./helpers";
import { FieldBar } from "./IncidentFields";
import { IncidentDescription } from "./IncidentDescription";
import { ActivityPane, TasksPane } from "./IncidentPanes";
import { Evidence, TasksSummary } from "./IncidentsPage";
import { ButtonMenu, Crumbs, Empty, EntityIcon, InfoMark, MoreMenu, Popover, Select, SevGlyph, StatusIcon, Tabs, type MenuItem } from "./ui";

/* ---------------------------------------------- tactics ------------------------------------------- */

/** One expandable line per tactic, each with its techniques, as the left panel lists them. */
function TacticsTree({ alerts }: { alerts: SentinelAlert[] }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const tree = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const a of alerts) for (const t of a.tactics) { const s = m.get(t) ?? new Set<string>(); a.techniques.forEach(x => s.add(x)); m.set(t, s); }
    return [...m].map(([tactic, techniques]) => ({ tactic, techniques: [...techniques] }));
  }, [alerts]);
  if (!tree.length) return <div className="v">--</div>;
  return (
    <ul>
      {tree.map(({ tactic, techniques }) => {
        const on = open.has(tactic);
        return (
          <li key={tactic}>
            <button type="button" className="st-tactic" aria-expanded={on} onClick={() => setOpen(o => { const n = new Set(o); if (n.has(tactic)) n.delete(tactic); else n.add(tactic); return n; })}>
              {on ? <ChevronDown size={16} color="#0078d4" aria-hidden /> : <ChevronRight size={16} color="#0078d4" aria-hidden />}
              <Target size={14} color="#0078d4" aria-hidden /><span>{tacticLabel(tactic)} ({techniques.length})</span>
            </button>
            {on && <ul className="st-small st-muted" style={{ paddingLeft: 42 }}>{techniques.map(t => <li key={t}>{t}</li>)}</ul>}
          </li>
        );
      })}
    </ul>
  );
}

/* ---------------------------------------------- timeline ------------------------------------------ */

type TLItem = { type: "Alert"; at: string; alert: SentinelAlert } | { type: "Bookmark"; at: string; bookmark: SentinelBookmark };
const itemId = (i: TLItem) => (i.type === "Alert" ? i.alert.id : i.bookmark.id);

function TimelineFilter({ tactics, sev, setSev, tac, setTac, type, setType }: {
  tactics: string[]; sev: string[]; setSev: (v: string[]) => void; tac: string[]; setTac: (v: string[]) => void; type: string[]; setType: (v: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const flip = (list: string[], set: (v: string[]) => void, v: string) => set(list.includes(v) ? list.filter(x => x !== v) : [...list, v]);
  const group = (title: string, values: string[], list: string[], set: (v: string[]) => void, show: (v: string) => string = v => v) => (
    <div role="group" aria-label={title}>
      <div className="st-small" style={{ fontWeight: 600, padding: "6px 12px 2px" }}>{title}</div>
      {values.map(v => <label key={v} className="st-opt st-check" style={{ minHeight: 26 }}><input type="checkbox" checked={list.includes(v)} onChange={() => flip(list, set, v)} /><span className="st-ellipsis">{show(v)}</span></label>)}
    </div>
  );
  const count = sev.length + tac.length + type.length;
  return (
    <>
      <button ref={btn} type="button" className="st-pill" aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <Filter size={13} aria-hidden />{count ? `Filters (${count})` : "Add filter"}
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={230} role="group" label="Timeline filters">
          {group("Severity", SEVERITIES, sev, setSev)}
          {group("Type", ["Alert", "Bookmark"], type, setType)}
          {tactics.length > 0 && group("Tactics", tactics, tac, setTac, tacticLabel)}
          {count > 0 && <div className="st-pop-pad"><button type="button" className="st-link st-small" onClick={() => { setSev([]); setTac([]); setType([]); }}>Clear filters</button></div>}
        </Popover>
      )}
    </>
  );
}

function Flyout({ title, icon, left, arrow, onClose, closeLabel, children }: {
  title: string; icon: React.ReactNode; left: number; arrow: number; onClose: () => void; closeLabel: string; children: React.ReactNode;
}) {
  const ref = useRef<HTMLButtonElement>(null);
  const back = useRef<HTMLElement | null>(null);
  useEffect(() => {
    back.current = document.activeElement as HTMLElement | null;
    ref.current?.focus({ preventScroll: true });
    return () => { back.current?.focus?.({ preventScroll: true }); };
  }, []);
  return (
    <aside className="st-flyout" style={{ left }} aria-label={title} onKeyDown={e => { if (e.key === "Escape") { e.stopPropagation(); onClose(); } }}>
      <i className="arrow" style={{ top: arrow }} aria-hidden />
      <div className="head">
        {icon}<h3 className="st-grow">{title}</h3>
        <button ref={ref} type="button" className="st-icon-btn" aria-label={closeLabel} onClick={onClose}><X size={16} color="#0078d4" aria-hidden /></button>
      </div>
      <div className="body">{children}</div>
    </aside>
  );
}

function AlertDetails({ alert, left, arrow, onClose, onEntity }: { alert: SentinelAlert; left: number; arrow: number; onClose: () => void; onEntity: (id: string) => void }) {
  const { ws, tables, openLogs } = useSentinel();
  const rule = ws.rules.find(r => r.id === alert.ruleId);
  const entities = alert.entityIds.map(id => ws.entities[id]).filter(Boolean);
  const row = useMemo(() => alertRecord(ws, alert.id), [ws, alert.id]);
  const events = useMemo(() => { const r = runQuery(alert.query, tables, ws.now); return r.ok ? r.rows.length : null; }, [alert.query, tables, ws.now]);
  const fromRow = (c: string) => (row?.[c] ? fmtMediumTime(row[c] as string) : fmtMediumTime(alert.time));
  const status = typeof row?.Status === "string" ? row.Status : "New";
  return (
    <Flyout title={alert.name} icon={<ShieldAlert size={18} color="#fff" fill="#0078d4" aria-hidden />} left={left} arrow={arrow} onClose={onClose} closeLabel="Close alert details">
      {alert.description && <div className="st-field"><div className="k">Description</div><div className="v">{alert.description}</div></div>}
      <div className="st-2col st-field">
        <div><div className="st-k">Severity</div><span className="st-row" style={{ gap: 4 }}><SevGlyph value={alert.severity} />{alert.severity}</span></div>
        <div><div className="st-k">Status</div><span className="st-row" style={{ gap: 4 }}><StatusIcon status={status === "Resolved" ? "Closed" : "New"} />{status}</span></div>
      </div>
      <div className="st-2col st-field">
        <div><div className="st-k">Events</div>{events ?? "N/A"}</div>
        <div><div className="st-k">Product name</div>{alert.product}</div>
      </div>
      <div className="st-field"><div className="k">Entities ({entities.length})</div>
        <ul>{entities.map(e => <li key={e.id}><button type="button" className="st-link st-row" style={{ gap: 6, maxWidth: "100%" }} onClick={() => onEntity(e.id)}><EntityIcon kind={e.kind} size={14} /><span className="st-ellipsis">{e.name}</span></button></li>)}</ul>
      </div>
      <div className="st-field"><div className="k">Tactics and techniques</div><TacticsTree alerts={[alert]} /></div>
      <div className="st-2col st-field">
        <div style={{ minWidth: 0 }}><div className="st-k">System alert ID</div>
          <button type="button" className="st-link st-ellipsis" style={{ display: "block", maxWidth: "100%" }} title={alert.id} onClick={() => openLogs({ query: alert.query, run: true })}>{alert.id}</button>
        </div>
        <div><div className="st-k">Rule name</div>{rule?.name ?? "-"}</div>
      </div>
      <div className="st-2col st-field">
        <div><div className="st-k">Last update time</div>{fromRow("ProcessingEndTime")}</div>
        <div />
      </div>
      <div className="st-2col st-field">
        <div><div className="st-k">Start time</div>{fromRow("StartTime")}</div>
        <div><div className="st-k">End time</div>{fromRow("EndTime")}</div>
      </div>
      {alert.graph && <GraphFields graph={alert.graph} />}
    </Flyout>
  );
}

/** The alert as Microsoft Graph Security reports it, with a way into its row in Logs. */
function GraphFields({ graph }: { graph: GraphAlertDetails }) {
  const { openLogs } = useSentinel();
  return (
    <div className="st-field">
      <div className="k">Microsoft Graph alert</div>
      <div className="st-2col st-field">
        <div style={{ minWidth: 0 }}><div className="st-k">Graph alert ID</div>
          <button type="button" className="st-link st-ellipsis" style={{ display: "block", maxWidth: "100%" }} title={graph.id} onClick={() => openLogs({ query: `GraphSecurityAlerts_CL\n| where id == "${graph.id}"`, run: true })}>{graph.id}</button>
        </div>
        <div><div className="st-k">Status</div>{graph.status}</div>
      </div>
      <div className="st-2col st-field">
        <div><div className="st-k">Service source</div>{graph.serviceSource}</div>
        <div><div className="st-k">Detection source</div>{graph.detectionSource}</div>
      </div>
      <div className="st-2col st-field">
        <div><div className="st-k">Category</div>{graph.category || "-"}</div>
        <div><div className="st-k">Classification</div>{graph.classification}</div>
      </div>
      {graph.recommendedActions && <div className="st-field"><div className="k">Recommended actions</div><div className="v">{graph.recommendedActions}</div></div>}
    </div>
  );
}

function BookmarkDetails({ bookmark, left, arrow, onClose, onEntity }: { bookmark: SentinelBookmark; left: number; arrow: number; onClose: () => void; onEntity: (id: string) => void }) {
  const { ws, openLogs } = useSentinel();
  const entities = bookmark.entityIds.map(id => ws.entities[id]).filter(Boolean);
  return (
    <Flyout title={bookmark.name} icon={<Bookmark size={18} color="#0078d4" fill="#0078d4" aria-hidden />} left={left} arrow={arrow} onClose={onClose} closeLabel="Close bookmark details">
      <div className="st-2col st-field">
        <div><div className="st-k">Created by</div>{bookmark.author}</div>
        <div><div className="st-k">Created time</div>{fmtMediumTime(bookmark.at)}</div>
      </div>
      <div className="st-field"><div className="k">Notes</div><div className="v">{bookmark.notes || "--"}</div></div>
      <div className="st-field"><div className="k">Entities ({entities.length})</div>
        <ul>{entities.map(e => <li key={e.id}><button type="button" className="st-link st-row" style={{ gap: 6 }} onClick={() => onEntity(e.id)}><EntityIcon kind={e.kind} size={14} />{e.name}</button></li>)}</ul>
      </div>
      <div className="st-field"><div className="k">Query result rows ({bookmark.rows.length})</div>
        <div style={{ overflow: "auto", maxHeight: 180 }}>
          <table className="st-mini" style={{ tableLayout: "auto" }}>
            <thead><tr>{bookmark.columns.map(c => <th key={c} scope="col">{c}</th>)}</tr></thead>
            <tbody>{bookmark.rows.map((r, i) => <tr key={i}>{bookmark.columns.map(c => <td key={c}>{r[c]}</td>)}</tr>)}</tbody>
          </table>
        </div>
      </div>
      <div className="st-field"><div className="k">Bookmark ID</div><div className="v st-mono st-small">{bookmark.id}</div></div>
      <button type="button" className="st-link" style={{ marginTop: 10 }} onClick={() => openLogs({ query: bookmark.query, run: true })}>View bookmark logs</button>
    </Flyout>
  );
}

const TimelineRow = memo(function TimelineRow({ item, active, onOpen, onLogs }: { item: TLItem; active: boolean; onOpen: (i: TLItem, row: HTMLElement) => void; onLogs: (q: string) => void }) {
  const alert = item.type === "Alert" ? item.alert : null;
  const bookmark = item.type === "Bookmark" ? item.bookmark : null;
  const query = alert?.query ?? bookmark?.query ?? "";
  return (
    <li className={`st-tl-item${active ? " active" : ""}`}>
      <span className="st-tl-date" style={{ gridColumn: 1 }}><b>{fmtMonthDay(item.at)}</b><br />{fmtClock(item.at)}</span>
      <span className="st-tl-rail"><span className="st-tl-dot">{alert ? <ShieldAlert size={14} color="#fff" fill="#0078d4" aria-hidden /> : <Bookmark size={13} color="#0078d4" fill="#0078d4" aria-hidden />}</span></span>
      <button type="button" className="st-tl-main" onClick={e => onOpen(item, e.currentTarget)}>
        {alert && <i className={`st-band ${alert.severity}`} aria-hidden />}
        {bookmark && <i className="st-band" style={{ background: "#0078d4" }} aria-hidden />}
        <span style={{ minWidth: 0, display: "block", width: "100%" }}>
          <span className="st-tl-title st-ellipsis" style={{ display: "block" }} title={alert?.name ?? bookmark?.name}>{alert?.name ?? bookmark?.name}</span>
          <span className="st-tl-meta">
            {alert
              ? <>
                  <span className="sev" title={alert.severity}>{alert.severity}</span>
                  <span className="st-ellipsis det" title={`Detected by ${alert.product}`}>Detected by {alert.product}</span>
                  {alert.tactics.length > 0 && <span className="tac" title={alert.tactics.map(tacticLabel).join(", ")}>Tactics:<Target size={13} color="#0078d4" aria-hidden /></span>}
                </>
              : <><span>Bookmark</span><span className="st-ellipsis">Created by {bookmark?.author}</span></>}
          </span>
        </span>
      </button>
      <span style={{ display: "flex", alignItems: "center" }}>
        <MoreMenu label={`Actions for ${alert?.name ?? bookmark?.name}`} items={[{ label: "Open in Logs", icon: <TerminalSquare size={14} color="#0078d4" aria-hidden />, onSelect: () => onLogs(query) }]} />
      </span>
    </li>
  );
});

function TimelineWidget({ incident, alerts, onEntity }: { incident: SentinelIncident; alerts: SentinelAlert[]; onEntity: (id: string) => void }) {
  const { stateOf, openLogs } = useSentinel();
  const state = stateOf(incident.id);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  const [tac, setTac] = useState<string[]>([]);
  const [type, setType] = useState<string[]>([]);
  const [open, setOpen] = useState<{ item: TLItem; arrow: number } | null>(null);
  const [left, setLeft] = useState(0);
  const section = useRef<HTMLElement>(null);
  const tactics = useMemo(() => [...new Set(alerts.flatMap(a => a.tactics))].sort(), [alerts]);
  const items = useMemo(() => {
    const s = q.trim().toLowerCase();
    const all: TLItem[] = [
      ...alerts.map(alert => ({ type: "Alert" as const, at: alert.time, alert })),
      ...state.bookmarks.map(bookmark => ({ type: "Bookmark" as const, at: bookmark.at, bookmark })),
    ];
    return all
      .filter(i => !type.length || type.includes(i.type))
      .filter(i => !sev.length || (i.type === "Alert" && sev.includes(i.alert.severity)))
      .filter(i => !tac.length || (i.type === "Alert" && i.alert.tactics.some(t => tac.includes(t))))
      .filter(i => !s || (i.type === "Alert" ? `${i.alert.name} ${i.alert.product} ${i.alert.description}` : `${i.bookmark.name} ${i.bookmark.notes}`).toLowerCase().includes(s))
      .sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  }, [alerts, state.bookmarks, q, sev, tac, type]);
  const onLogs = useCallback((query: string) => openLogs({ query, run: true }), [openLogs]);
  const onOpen = useCallback((item: TLItem, row: HTMLElement) => {
    const host = section.current?.closest(".st-inc-main") as HTMLElement | null;
    const top = host ? row.getBoundingClientRect().top - host.getBoundingClientRect().top : 40;
    setOpen({ item, arrow: top + 18 });
  }, []);
  useLayoutEffect(() => {
    const el = section.current;
    const host = el?.closest(".st-inc-main") as HTMLElement | null;
    if (el && host) setLeft(el.getBoundingClientRect().right - host.getBoundingClientRect().left);
  }, [open]);
  const close = useCallback(() => setOpen(null), []);
  return (
    <section ref={section} className="st-widget" aria-label="Incident timeline">
      <h3>Incident timeline</h3>
      <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">Search timeline</span>
        <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" />
      </label>
      <div style={{ marginTop: 8 }}><TimelineFilter tactics={tactics} sev={sev} setSev={setSev} tac={tac} setTac={setTac} type={type} setType={setType} /></div>
      <ul className="st-wscroll st-tl">
        {items.map(i => <TimelineRow key={itemId(i)} item={i} active={!!open && itemId(open.item) === itemId(i)} onOpen={onOpen} onLogs={onLogs} />)}
        {items.length === 0 && <li className="st-muted st-small" style={{ padding: 12 }}>No item matches.</li>}
      </ul>
      {open?.item.type === "Alert" && <AlertDetails key={open.item.alert.id} alert={open.item.alert} left={left} arrow={open.arrow} onClose={close} onEntity={onEntity} />}
      {open?.item.type === "Bookmark" && <BookmarkDetails key={open.item.bookmark.id} bookmark={open.item.bookmark} left={left} arrow={open.arrow} onClose={close} onEntity={onEntity} />}
    </section>
  );
}

/* ---------------------------------------------- entities ------------------------------------------ */

function useEntityActions(incident: SentinelIncident) {
  const { addToTi, openPlaybook, ended } = useSentinel();
  return useCallback((e: SentinelEntity): MenuItem[] => {
    if (ended) return [];
    const items: MenuItem[] = [];
    if (canAddToTi(e)) items.push({ label: "Add to TI", icon: <ShieldPlus size={14} color="#0078d4" aria-hidden />, onSelect: () => addToTi(e, incident.id) });
    if (canRunPlaybook(e)) items.push({ label: "Run playbook (Preview)", icon: <Workflow size={14} color="#0078d4" aria-hidden />, onSelect: () => openPlaybook({ incidentId: incident.id, host: e.name }) });
    return items;
  }, [addToTi, ended, incident.id, openPlaybook]);
}

function kindOptions(entities: SentinelEntity[]) {
  const kinds = [...new Set(entities.map(e => e.kind))];
  return [{ value: "All", label: "All" }, ...kinds.map(k => ({ value: k, label: KIND_LABEL[k] }))] as { value: EntityKind | "All"; label: string }[];
}

function EntitiesWidget({ incident, entities, onSelect }: { incident: SentinelIncident; entities: SentinelEntity[]; onSelect: (id: string) => void }) {
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<EntityKind | "All">("All");
  const menu = useEntityActions(incident);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return entities.filter(e => (kind === "All" || e.kind === kind) && (!s || e.name.toLowerCase().includes(s)));
  }, [entities, q, kind]);
  return (
    <section className="st-widget" aria-label="Entities">
      <h3>Entities</h3>
      <div className="st-row">
        <label className="st-search st-grow"><Search size={14} aria-hidden /><span className="st-sr">Search entities</span>
          <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" />
        </label>
        <Select label="Type" value={kind} options={kindOptions(entities)} onChange={setKind} className="st-pill">Type : <b>{kind === "All" ? "All" : KIND_LABEL[kind]}</b></Select>
      </div>
      <ul className="st-wscroll">
        {shown.map(e => (
          <li key={e.id} className="st-entity-row">
            <button type="button" className="st-row st-grow" style={{ minWidth: 0, gap: 10 }} onClick={() => onSelect(e.id)}>
              <EntityIcon kind={e.kind} size={24} />
              <span style={{ minWidth: 0 }}><span className="st-ellipsis" style={{ display: "block", fontWeight: 600 }} title={e.name}>{e.name}</span><span className="st-small">{KIND_LABEL[e.kind]}</span></span>
            </button>
            <MoreMenu label={`Actions for ${e.name}`} items={menu(e)} />
          </li>
        ))}
        {shown.length === 0 && <li className="st-muted st-small" style={{ padding: 12 }}>No entity matches.</li>}
      </ul>
    </section>
  );
}

/** The info button in Similarity reason: the common items, in a card beside the row. */
function SimilarityInfo({ s }: { s: SimilarIncident }) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  return (
    <>
      <button ref={btn} type="button" className="st-icon-btn" style={{ width: 18, height: 18 }} aria-label={`${s.reason}: show the common items`} aria-expanded={open} onClick={() => setOpen(o => !o)}><Info size={13} aria-hidden /></button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={440} align="right" role="dialog" label={s.reason}>
          <div className="st-pop-pad">
            <strong>{s.reason}</strong>
            <ul className="st-stack" style={{ gap: 6 }}>
              {s.entities.map(e => <li key={e.id} className="st-row"><EntityIcon kind={e.kind} size={16} /><span className="st-ellipsis" title={e.name}>{e.name}</span></li>)}
              {s.rules.map(r => <li key={r} className="st-row"><ShieldAlert size={16} color="#0078d4" aria-hidden /><span className="st-ellipsis" title={r}>{r}</span></li>)}
            </ul>
          </div>
        </Popover>
      )}
    </>
  );
}

function SimilarWidget({ incident }: { incident: SentinelIncident }) {
  const { ws, stateOf, openIncident } = useSentinel();
  const similar = useMemo(() => similarIncidents(incident, ws), [incident, ws]);
  return (
    <section className="st-widget span2" aria-label="Similar incidents">
      <h3>Similar incidents <InfoMark title="Up to 20 incidents that most closely resemble this one." /></h3>
      {similar.length === 0 ? <p className="st-muted st-small">No similar incidents in this workspace.</p> : (
        <div className="st-wscroll">
          <table className="st-table st-similar">
            <thead><tr>
              <th scope="col" style={{ width: 96 }}>Severity</th><th scope="col" style={{ width: 84 }}>Incident ID</th><th scope="col">Title</th>
              <th scope="col" style={{ width: 150 }}>Last update time</th><th scope="col" style={{ width: 100 }}>Status</th><th scope="col" style={{ width: 140 }}>Similarity reason</th><th scope="col" style={{ width: 100 }}>Owner</th>
            </tr></thead>
            <tbody>
              {similar.map(s => {
                const st = stateOf(s.incident.id);
                const status = st.status === "Closed" && st.classification ? `Closed - ${st.classification}` : st.status;
                return (
                  <tr key={s.incident.id}>
                    <td className="st-sevcell"><i className={`st-cellband ${st.severity}`} aria-hidden />{st.severity}</td>
                    <td><button type="button" className="st-link" onClick={() => openIncident(s.incident.id)}>{s.incident.number}</button></td>
                    <td title={s.incident.title}>{s.incident.title}</td>
                    <td>{fmtMediumTime(s.incident.lastUpdate)}</td>
                    <td title={status}>{status}</td>
                    <td><span className="st-row" style={{ gap: 4 }}><span className="st-ellipsis">{s.reason}</span><SimilarityInfo s={s} /></span></td>
                    <td title={st.owner ?? "Unassigned"}>{st.owner ?? "Unassigned"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function InsightsWidget({ incident }: { incident: SentinelIncident }) {
  const { ws } = useSentinel();
  const insights = useMemo(() => insightsForIncident(incident, ws), [incident, ws]);
  const first = useMemo(() => {
    const times = alertsOf(incident, ws).map(a => Date.parse(a.time)).filter(Number.isFinite);
    return times.length ? Math.min(...times) : Date.parse(incident.created);
  }, [incident, ws]);
  const last = useMemo(() => Date.parse(incident.lastUpdate), [incident]);
  const range = `${fmtDateTime(first - 86_400_000)} - ${fmtDateTime(last)}`;
  return (
    <section className="st-widget tall" aria-label="Top insights">
      <h3>Top insights</h3>
      <div className="st-small st-muted st-row" style={{ gap: 4 }}><Clock size={13} aria-hidden />Last 24 hours before the first alert<InfoMark title="From 24 hours before the earliest alert until the latest alert." /></div>
      <div className="st-wscroll">
        {insights.map(i => <InsightCard key={i.title} insight={i} range={range} />)}
        {insights.length === 0 && <Empty icon={<Lightbulb size={22} aria-hidden />} title="No insights yet" />}
      </div>
    </section>
  );
}

/* --------------------------------------------- entities tab --------------------------------------- */

function EntitiesTab({ incident, entities, selected, onSelect }: { incident: SentinelIncident; entities: SentinelEntity[]; selected: string | null; onSelect: (id: string | null) => void }) {
  const { openEntity } = useSentinel();
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<EntityKind | "All">("All");
  const [card, setCard] = useState<"info" | "timeline" | "insights">("info");
  const menu = useEntityActions(incident);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return entities.filter(e => (kind === "All" || e.kind === kind) && (!s || e.name.toLowerCase().includes(s)));
  }, [entities, q, kind]);
  const entity = entities.find(e => e.id === selected) ?? null;
  const actions = entity ? menu(entity) : [];
  return (
    <div className="st-entities-tab">
      <div className="st-entities-list">
        <div className="st-row">
          <label className="st-search st-grow" style={{ maxWidth: 280 }}><Search size={14} aria-hidden /><span className="st-sr">Search entities</span>
            <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" />
          </label>
          <Select label="Type" value={kind} options={kindOptions(entities)} onChange={setKind} className="st-pill">Type : <b>{kind === "All" ? "All" : KIND_LABEL[kind]}</b></Select>
        </div>
        <div className="st-wscroll">
          <table className="st-table">
            <thead><tr><th scope="col">Name</th><th scope="col" style={{ width: 150 }}>Type</th><th scope="col" style={{ width: 36 }}><span className="st-sr">Actions</span></th></tr></thead>
            <tbody>
              {shown.map(e => (
                <tr key={e.id} className={e.id === selected ? "selected" : undefined} tabIndex={0} aria-current={e.id === selected ? "true" : undefined}
                  onClick={() => onSelect(e.id)} onKeyDown={ev => { if (ev.key === "Enter" && ev.target === ev.currentTarget) onSelect(e.id); }}>
                  <td title={e.name}><button type="button" className="st-link" onClick={ev => { ev.stopPropagation(); openEntity(e.id); }}>{e.name}</button></td>
                  <td><span className="st-row"><EntityIcon kind={e.kind} size={16} />{KIND_LABEL[e.kind]}</span></td>
                  <td style={{ padding: 0 }}><MoreMenu label={`Actions for ${e.name}`} items={menu(e)} /></td>
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan={3} className="st-muted">No entity matches.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      {entity && (
        <aside className="st-entity-pane" aria-label={`${entity.name} details`}>
          <div className="st-preview-head">
            <EntityIcon kind={entity.kind} size={30} />
            <div className="st-grow" style={{ minWidth: 0 }}><h2 title={entity.name}>{entity.name}</h2><div className="st-small">{KIND_LABEL[entity.kind]}</div></div>
            <button type="button" className="st-icon-btn corner" aria-label="Close entity pane" onClick={() => onSelect(null)}><ChevronsRight size={13} aria-hidden /></button>
          </div>
          <Tabs label="Entity cards" value={card} onChange={setCard} className="st-card-tabs" tabClass="st-card-tab" tabs={[
            { value: "info", label: <><Info size={18} aria-hidden />Info</> },
            { value: "timeline", label: <><ListTree size={18} aria-hidden />Timeline</> },
            { value: "insights", label: <><Lightbulb size={18} color="#7a5fc0" aria-hidden />Insights</> },
          ]} />
          <div className="st-preview-body" style={{ paddingTop: 12 }}>
            {card === "info" && <EntityInfoCard entity={entity} />}
            {card === "timeline" && <EntityTimelineCard entity={entity} incident={incident} />}
            {card === "insights" && <EntityInsightsCard entity={entity} />}
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => openEntity(entity.id)}>View full details</button>
            {actions.length === 1
              ? <button type="button" className="st-btn" onClick={actions[0].onSelect}>{actions[0].label}</button>
              : <ButtonMenu label="Entity actions" className="st-btn" items={actions}>Entity actions<ChevronDown size={12} aria-hidden /></ButtonMenu>}
          </div>
        </aside>
      )}
    </div>
  );
}

/* ------------------------------------------------ page -------------------------------------------- */

export function IncidentDetails({ incident, focusEntity, onClose, hidden }: { incident: SentinelIncident; focusEntity?: string; onClose: () => void; hidden?: boolean }) {
  const { ws, stateOf, openLogs, openInvestigation, openPlaybook, refresh, ended, go } = useSentinel();
  const state = stateOf(incident.id);
  const [tab, setTab] = useState<"overview" | "entities">(focusEntity ? "entities" : "overview");
  const [selected, setSelected] = useState<string | null>(focusEntity ?? null);
  const [collapsed, setCollapsed] = useState(false);
  const [pane, setPane] = useState<"tasks" | "activity" | null>(null);
  const alerts = useMemo(() => alertsOf(incident, ws), [incident, ws]);
  const entities = useMemo(() => entitiesOf(incident, ws), [incident, ws]);
  const showEntity = useCallback((id: string) => { setSelected(id); setTab("entities"); }, []);
  const region = useRef<HTMLDivElement>(null);
  useEffect(() => { region.current?.focus({ preventScroll: true }); }, []);

  const collapse = (
    <button type="button" className="st-collapse-btn" aria-label={collapsed ? "Expand details panel" : "Collapse details panel"} aria-expanded={!collapsed} onClick={() => setCollapsed(c => !c)}>
      {collapsed ? <ChevronsRight size={13} aria-hidden /> : <ChevronsLeft size={13} aria-hidden />}
    </button>
  );

  return (
    <div ref={region} tabIndex={-1} className="st-inc" role="region" aria-label={`Incident ${incident.number}`} hidden={hidden}>
      <Crumbs trailing items={[{ label: "Home", onClick: () => { onClose(); go("overview"); } }, { label: "Sentinel | Incidents", onClick: onClose }]} />
      <div className="st-inc-head">
        <Briefcase size={30} color="#0078d4" fill="#c7e0f4" aria-hidden style={{ marginTop: 3 }} />
        <div className="st-grow" style={{ minWidth: 0 }}><h1 className="st-wrap" title={incident.title}>{incident.title}</h1><div className="st-small">Incident ID {incident.number}</div></div>
        <button type="button" className="st-icon-btn" aria-label="Close incident" onClick={onClose}><X size={18} aria-hidden /></button>
      </div>
      <div className="st-cmdbar" role="toolbar" aria-label="Incident commands" style={{ paddingLeft: 8 }}>
        <button type="button" className="st-cmd" onClick={refresh}><RefreshCw size={15} aria-hidden />Refresh</button>
        <span className="st-cmdsep" aria-hidden />
        <button type="button" className="st-cmd" onClick={() => openLogs({ query: "" })}><TerminalSquare size={15} aria-hidden />Logs</button>
        <button type="button" className="st-cmd" onClick={() => setPane("tasks")}><ClipboardList size={15} aria-hidden />Tasks</button>
        <button type="button" className="st-cmd" onClick={() => setPane("activity")}><MessageSquareText size={15} aria-hidden />Activity log</button>
      </div>
      <div className="st-inc-body">
        <aside className={`st-inc-left${collapsed ? " collapsed" : ""}`} aria-label="Incident details">
          <FieldBar incident={incident} state={state} order={["severity", "status", "owner"]} collapsed={collapsed} tail={collapse} />
          {!collapsed && (
            <>
              <div className="st-inc-scroll">
                <div className="st-field"><div className="k">Workspace name</div><div className="v">{ws.name}</div></div>
                <IncidentDescription incident={incident} />
                <div className="st-field"><div className="k">Alert product names</div>
                  <ul className="st-bullets">{incident.products.map(p => <li key={p}>{p}</li>)}</ul>
                </div>
                <TasksSummary state={state} onOpen={() => setPane("tasks")} />
                <div className="st-field"><div className="k">Evidence</div><Evidence incident={incident} state={state} /></div>
                <div className="st-2col st-field">
                  <div><div className="st-k">Last update time</div>{fmtDateTime(incident.lastUpdate)}</div>
                  <div><div className="st-k">Creation time</div>{fmtDateTime(incident.created)}</div>
                </div>
                {state.status === "Closed" && (
                  <div className="st-field"><div className="k">Closing classification</div>
                    <div className="v">{state.classification ?? "-"}</div>
                    {state.closingComment && <div className="v st-small st-muted">{state.closingComment}</div>}
                  </div>
                )}
                <div className="st-field"><div className="k">Entities ({entities.length})</div>
                  <ul>
                    {entities.slice(0, 4).map(e => (
                      <li key={e.id}><button type="button" className="st-link st-row" style={{ gap: 6, maxWidth: "100%" }} title={e.name} onClick={() => showEntity(e.id)}><EntityIcon kind={e.kind} size={14} /><span className="st-ellipsis">{e.name}</span></button></li>
                    ))}
                  </ul>
                  {entities.length > 0 && <button type="button" className="st-link" onClick={() => setTab("entities")}>View all &gt;</button>}
                </div>
                <div className="st-field"><div className="k">Tactics and techniques</div><TacticsTree alerts={alerts} /></div>
              </div>
              <div className="st-inc-foot">
                <button type="button" className="st-btn primary" onClick={() => openInvestigation(incident.id)}>Investigate</button>
              </div>
            </>
          )}
        </aside>
        <div className="st-inc-main">
          <div className="st-inc-tabs">
            <Tabs label="Incident views" value={tab} onChange={setTab} tabs={[{ value: "overview", label: "Overview" }, { value: "entities", label: "Entities" }]} />
            {!ended && (
              <ButtonMenu label="Incident actions" className="st-btn primary" align="right"
                items={[{ label: "Run playbook (Preview)", icon: <Workflow size={14} color="#0078d4" aria-hidden />, onSelect: () => openPlaybook({ incidentId: incident.id }) }]}>
                Incident actions<ChevronDown size={12} aria-hidden />
              </ButtonMenu>
            )}
          </div>
          {tab === "overview" ? (
            <div className="st-widgets" role="tabpanel" aria-label="Overview">
              <TimelineWidget incident={incident} alerts={alerts} onEntity={showEntity} />
              <EntitiesWidget incident={incident} entities={entities} onSelect={showEntity} />
              <InsightsWidget incident={incident} />
              <SimilarWidget incident={incident} />
            </div>
          ) : (
            <EntitiesTab incident={incident} entities={entities} selected={selected} onSelect={setSelected} />
          )}
        </div>
      </div>
      {pane === "tasks" && <TasksPane incident={incident} onClose={() => setPane(null)} />}
      {pane === "activity" && <ActivityPane incident={incident} onClose={() => setPane(null)} />}
    </div>
  );
}
