"use client";
// The incident details page, laid out as incident-details-overview.png: toolbar, left details panel,
// Overview and Entities tabs, four widgets.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity, ArrowLeft, Bookmark, Briefcase, ChevronDown, ChevronRight, ChevronsLeft, ChevronsRight, ClipboardList, Clock, Filter, Info, Lightbulb,
  ListTree, MessageSquareText, RefreshCw, Search, ShieldAlert, Target, TerminalSquare, X,
} from "lucide-react";
import type { EntityKind, SentinelAlert, SentinelBookmark, SentinelEntity, SentinelIncident } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, EntityTimelineCard, InsightCard } from "./EntityCards";
import { insightsForIncident } from "./engine";
import {
  alertsOf, alertsQuery, bookmarksQuery, canAddToTi, canRunPlaybook, entitiesOf, fmtClock, fmtCount, fmtDateTime, fmtMonthDay, KIND_LABEL, SEVERITIES, similarIncidents,
} from "./helpers";
import { FieldBar } from "./IncidentFields";
import { ActivityPane, TasksPane } from "./IncidentPanes";
import { ButtonMenu, Crumbs, Empty, EntityIcon, MoreMenu, Popover, Select, Severity, Tabs, type MenuItem } from "./ui";

/* ---------------------------------------------- timeline ------------------------------------------ */

type TLItem = { type: "Alert"; at: string; alert: SentinelAlert } | { type: "Bookmark"; at: string; bookmark: SentinelBookmark };

function TimelineFilter({ tactics, sev, setSev, tac, setTac, type, setType }: {
  tactics: string[]; sev: string[]; setSev: (v: string[]) => void; tac: string[]; setTac: (v: string[]) => void; type: string[]; setType: (v: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  const flip = (list: string[], set: (v: string[]) => void, v: string) => set(list.includes(v) ? list.filter(x => x !== v) : [...list, v]);
  const group = (title: string, values: string[], list: string[], set: (v: string[]) => void) => (
    <div role="group" aria-label={title}>
      <div className="st-small" style={{ fontWeight: 600, padding: "6px 12px 2px" }}>{title}</div>
      {values.map(v => <label key={v} className="st-opt st-check" style={{ minHeight: 26 }}><input type="checkbox" checked={list.includes(v)} onChange={() => flip(list, set, v)} /><span className="st-ellipsis">{v}</span></label>)}
    </div>
  );
  const count = sev.length + tac.length + type.length;
  return (
    <>
      <button ref={btn} type="button" className="st-pill" aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        <Filter size={12} aria-hidden />{count ? `Filters (${count})` : "Add filter"}
      </button>
      {open && (
        <Popover anchor={btn.current} onClose={close} width={230} role="group" label="Timeline filters">
          {group("Severity", SEVERITIES, sev, setSev)}
          {group("Type", ["Alert", "Bookmark"], type, setType)}
          {tactics.length > 0 && group("Tactics", tactics, tac, setTac)}
          {count > 0 && <div className="st-pop-pad"><button type="button" className="st-link st-small" onClick={() => { setSev([]); setTac([]); setType([]); }}>Clear filters</button></div>}
        </Popover>
      )}
    </>
  );
}

function AlertDetails({ alert, onBack }: { alert: SentinelAlert; onBack: () => void }) {
  const { ws, openLogs } = useSentinel();
  const rule = ws.rules.find(r => r.id === alert.ruleId);
  const entities = alert.entityIds.map(id => ws.entities[id]).filter(Boolean);
  return (
    <div className="st-wscroll">
      <button type="button" className="st-cmd" style={{ height: 24, padding: 0 }} onClick={onBack}><ArrowLeft size={14} aria-hidden />Back to timeline</button>
      <div className="st-row" style={{ marginTop: 6, alignItems: "stretch" }}>
        <i className={`st-band ${alert.severity}`} aria-hidden /><h4 style={{ fontSize: 14 }}>{alert.name}</h4>
      </div>
      <div className="st-field"><div className="k">Severity</div><div className="v"><Severity value={alert.severity} /></div></div>
      {alert.description && <div className="st-field"><div className="k">Description</div><div className="v">{alert.description}</div></div>}
      <div className="st-field"><div className="k">Analytics rule</div><div className="v">{rule?.name ?? "Raised by the product"}</div></div>
      <div className="st-field"><div className="k">Product name</div><div className="v">{alert.product}</div></div>
      <div className="st-field"><div className="k">Time generated</div><div className="v">{fmtDateTime(alert.time)}</div></div>
      <div className="st-field"><div className="k">Entities ({entities.length})</div>
        <ul>{entities.map(e => <li key={e.id} className="st-row" style={{ marginTop: 2 }}><EntityIcon kind={e.kind} size={12} /><span className="st-ellipsis">{e.name}</span></li>)}</ul>
      </div>
      <div className="st-field"><div className="k">Tactics and techniques</div>
        <div className="v">{alert.tactics.length ? alert.tactics.join(", ") : "-"}{alert.techniques.length ? ` (${alert.techniques.join(", ")})` : ""}</div>
      </div>
      <div className="st-field"><div className="k">System alert ID</div>
        <button type="button" className="st-link st-mono st-small" style={{ wordBreak: "break-all" }} onClick={() => openLogs({ query: alert.query, run: true })}>{alert.id}</button>
      </div>
    </div>
  );
}

function BookmarkDetails({ bookmark, onBack }: { bookmark: SentinelBookmark; onBack: () => void }) {
  const { ws, openLogs } = useSentinel();
  const entities = bookmark.entityIds.map(id => ws.entities[id]).filter(Boolean);
  return (
    <div className="st-wscroll">
      <button type="button" className="st-cmd" style={{ height: 24, padding: 0 }} onClick={onBack}><ArrowLeft size={14} aria-hidden />Back to timeline</button>
      <h4 style={{ fontSize: 14, marginTop: 6 }}>{bookmark.name}</h4>
      <div className="st-field"><div className="k">Created by</div><div className="v">{bookmark.author}, {fmtDateTime(bookmark.at)}</div></div>
      {bookmark.notes && <div className="st-field"><div className="k">Notes</div><div className="v">{bookmark.notes}</div></div>}
      <div className="st-field"><div className="k">Entities ({entities.length})</div>
        <ul>{entities.map(e => <li key={e.id} className="st-row" style={{ marginTop: 2 }}><EntityIcon kind={e.kind} size={12} />{e.name}</li>)}</ul>
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
      <button type="button" className="st-link" style={{ marginTop: 8 }} onClick={() => openLogs({ query: bookmark.query, run: true })}>View bookmark logs</button>
    </div>
  );
}

const TimelineRow = memo(function TimelineRow({ item, onOpen, onLogs }: { item: TLItem; onOpen: (i: TLItem) => void; onLogs: (q: string) => void }) {
  const alert = item.type === "Alert" ? item.alert : null;
  const bookmark = item.type === "Bookmark" ? item.bookmark : null;
  const query = alert?.query ?? bookmark?.query ?? "";
  return (
    <li className="st-tl-item">
      <span className="st-tl-date" style={{ gridColumn: 1 }}>{fmtMonthDay(item.at)}<br />{fmtClock(item.at)}</span>
      <span className="st-tl-rail"><span className="st-tl-dot">{alert ? <ShieldAlert size={13} aria-hidden /> : <Bookmark size={13} aria-hidden />}</span></span>
      <button type="button" className="st-tl-main" onClick={() => onOpen(item)}>
        {alert && <i className={`st-band ${alert.severity}`} aria-hidden />}
        {bookmark && <i className="st-band" style={{ background: "#0078d4" }} aria-hidden />}
        <span style={{ minWidth: 0, display: "block" }}>
          <span className="st-tl-title st-ellipsis" style={{ display: "block" }} title={alert?.name ?? bookmark?.name}>{alert?.name ?? bookmark?.name}</span>
          <span className="st-tl-meta">
            {alert
              ? <>
                  <span title={alert.severity}>{alert.severity}</span>
                  <span className="st-ellipsis" title={`Detected by ${alert.product}`}>Detected by {alert.product}</span>
                  {alert.tactics.length > 0 && <span className="st-ellipsis" title={alert.tactics.join(", ")}>Tactics: {alert.tactics.join(", ")}</span>}
                </>
              : <><span>Bookmark</span><span className="st-ellipsis">Created by {bookmark?.author}</span></>}
          </span>
        </span>
      </button>
      <span style={{ display: "flex", alignItems: "center" }}>
        <MoreMenu label={`Actions for ${alert?.name ?? bookmark?.name}`} items={[
          { label: alert ? "Alert details" : "Bookmark details", onSelect: () => onOpen(item) },
          { label: "Open in Logs", onSelect: () => onLogs(query) },
        ]} />
      </span>
    </li>
  );
});

function TimelineWidget({ incident, alerts }: { incident: SentinelIncident; alerts: SentinelAlert[] }) {
  const { stateOf, openLogs } = useSentinel();
  const state = stateOf(incident.id);
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  const [tac, setTac] = useState<string[]>([]);
  const [type, setType] = useState<string[]>([]);
  const [open, setOpen] = useState<TLItem | null>(null);
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
  return (
    <section className="st-widget" aria-label="Incident timeline">
      <h3>Incident timeline</h3>
      {open ? (
        open.type === "Alert" ? <AlertDetails alert={open.alert} onBack={() => setOpen(null)} /> : <BookmarkDetails bookmark={open.bookmark} onBack={() => setOpen(null)} />
      ) : (
        <>
          <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">Search timeline</span>
            <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" />
          </label>
          <div style={{ marginTop: 6 }}><TimelineFilter tactics={tactics} sev={sev} setSev={setSev} tac={tac} setTac={setTac} type={type} setType={setType} /></div>
          <ul className="st-wscroll st-tl">
            {items.map(i => <TimelineRow key={i.type === "Alert" ? i.alert.id : i.bookmark.id} item={i} onOpen={setOpen} onLogs={onLogs} />)}
            {items.length === 0 && <li className="st-muted st-small" style={{ padding: 12 }}>No item matches.</li>}
          </ul>
        </>
      )}
    </section>
  );
}

/* ---------------------------------------------- entities ------------------------------------------ */

function useEntityActions(incident: SentinelIncident) {
  const { addToTi, openPlaybook, ended } = useSentinel();
  return useCallback((e: SentinelEntity): MenuItem[] => {
    if (ended) return [];
    const items: MenuItem[] = [];
    if (canRunPlaybook(e)) items.push({ label: "Run playbook", onSelect: () => openPlaybook({ incidentId: incident.id, host: e.name }) });
    if (canAddToTi(e)) items.push({ label: "Add to TI", onSelect: () => addToTi(e, incident.id) });
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
            <button type="button" className="st-row st-grow" style={{ minWidth: 0 }} onClick={() => onSelect(e.id)}>
              <EntityIcon kind={e.kind} />
              <span style={{ minWidth: 0 }}><span className="st-ellipsis" style={{ display: "block", fontWeight: 600 }}>{e.name}</span><span className="st-small st-muted">{KIND_LABEL[e.kind]}</span></span>
            </button>
            <MoreMenu label={`Actions for ${e.name}`} items={menu(e)} />
          </li>
        ))}
        {shown.length === 0 && <li className="st-muted st-small" style={{ padding: 12 }}>No entity matches.</li>}
      </ul>
    </section>
  );
}

function SimilarWidget({ incident }: { incident: SentinelIncident }) {
  const { ws, stateOf, openIncident } = useSentinel();
  const similar = useMemo(() => similarIncidents(incident, ws), [incident, ws]);
  return (
    <section className="st-widget span2" aria-label="Similar incidents">
      <h3>Similar incidents <span title="Up to 20 incidents that share entities or a detection with this one." aria-hidden><Info size={13} color="#605e5c" /></span></h3>
      {similar.length === 0 ? <p className="st-muted st-small">No similar incidents in this workspace.</p> : (
        <div className="st-wscroll">
          <table className="st-table">
            <thead><tr>
              <th scope="col" style={{ width: 100 }}>Severity</th><th scope="col" style={{ width: 80 }}>Incident ID</th><th scope="col">Title</th>
              <th scope="col" style={{ width: 160 }}>Last update time</th><th scope="col" style={{ width: 70 }}>Status</th><th scope="col" style={{ width: 130 }}>Similarity reason</th>
            </tr></thead>
            <tbody>
              {similar.map(s => {
                const st = stateOf(s.incident.id);
                return (
                  <tr key={s.incident.id}>
                    <td><Severity value={st.severity} /></td>
                    <td><button type="button" className="st-link" onClick={() => openIncident(s.incident.id)}>{s.incident.number}</button></td>
                    <td title={s.incident.title}>{s.incident.title}</td>
                    <td>{fmtDateTime(s.incident.lastUpdate)}</td>
                    <td>{st.status}</td>
                    <td title={s.common.join(", ")}><span className="st-row" style={{ gap: 4 }}><span className="st-ellipsis">{s.reason}</span><Info size={12} color="#605e5c" aria-hidden /></span><span className="st-sr">Common items: {s.common.join(", ")}</span></td>
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
      <div className="st-small st-muted st-row" style={{ gap: 4 }}><Clock size={12} aria-hidden />Last 24 hours before the first alert</div>
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
                  <td><span className="st-row"><EntityIcon kind={e.kind} size={12} />{KIND_LABEL[e.kind]}</span></td>
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
            <EntityIcon kind={entity.kind} size={16} />
            <div className="st-grow"><h2>{entity.name}</h2><div className="st-small st-muted">{KIND_LABEL[entity.kind]}</div></div>
            <button type="button" className="st-icon-btn" aria-label="Close entity pane" onClick={() => onSelect(null)}><ChevronsRight size={16} aria-hidden /></button>
          </div>
          <Tabs label="Entity cards" value={card} onChange={setCard} className="st-card-tabs" tabClass="st-card-tab" tabs={[
            { value: "info", label: <><Info size={16} aria-hidden />Info</> },
            { value: "timeline", label: <><ListTree size={16} aria-hidden />Timeline</> },
            { value: "insights", label: <><Lightbulb size={16} aria-hidden />Insights</> },
          ]} />
          <div className="st-preview-body" style={{ paddingTop: 12 }}>
            {card === "info" && <EntityInfoCard entity={entity} />}
            {card === "timeline" && <EntityTimelineCard entity={entity} incident={incident} />}
            {card === "insights" && <EntityInsightsCard entity={entity} />}
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => openEntity(entity.id)}>View full details</button>
            <ButtonMenu label="Entity actions" className="st-btn" items={actions}>Entity actions<ChevronDown size={12} aria-hidden /></ButtonMenu>
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
  const [tacticsOpen, setTacticsOpen] = useState(false);
  const alerts = useMemo(() => alertsOf(incident, ws), [incident, ws]);
  const entities = useMemo(() => entitiesOf(incident, ws), [incident, ws]);
  const showEntity = useCallback((id: string) => { setSelected(id); setTab("entities"); }, []);
  const tasksDone = state.tasks.filter(t => t.done).length;
  const region = useRef<HTMLDivElement>(null);
  useEffect(() => { region.current?.focus({ preventScroll: true }); }, []);

  return (
    <div ref={region} tabIndex={-1} className="st-inc" role="region" aria-label={`Incident ${incident.number}`} hidden={hidden}>
      <Crumbs items={[{ label: "Home", onClick: () => { onClose(); go("overview"); } }, { label: "Sentinel | Incidents", onClick: onClose }, { label: `Incident ${incident.number}` }]} />
      <div className="st-inc-head">
        <Briefcase size={26} color="#0078d4" aria-hidden style={{ marginTop: 4 }} />
        <div className="st-grow"><h1>{incident.title}</h1><div className="st-small st-muted">Incident ID {incident.number}</div></div>
        <button type="button" className="st-icon-btn" aria-label="Close incident" onClick={onClose}><X size={18} aria-hidden /></button>
      </div>
      <div className="st-cmdbar" role="toolbar" aria-label="Incident commands" style={{ paddingLeft: 8 }}>
        <button type="button" className="st-cmd" onClick={refresh}><RefreshCw size={14} aria-hidden />Refresh</button>
        <span className="st-cmdsep" aria-hidden />
        <button type="button" className="st-cmd" onClick={() => openLogs({ query: "" })}><TerminalSquare size={14} aria-hidden />Logs</button>
        <button type="button" className="st-cmd" onClick={() => setPane("tasks")}><ClipboardList size={14} aria-hidden />Tasks</button>
        <button type="button" className="st-cmd" onClick={() => setPane("activity")}><MessageSquareText size={14} aria-hidden />Activity log</button>
      </div>
      <div className="st-inc-body">
        <aside className={`st-inc-left${collapsed ? " collapsed" : ""}`} aria-label="Incident details">
          <FieldBar incident={incident} state={state} collapsed={collapsed} onToggle={() => setCollapsed(c => !c)}
            collapseIcon={collapsed ? <ChevronsRight size={13} aria-hidden /> : <ChevronsLeft size={13} aria-hidden />} />
          {!collapsed && (
            <>
              <div className="st-inc-scroll">
                <div className="st-field"><div className="k">Workspace name</div><div className="v">{ws.name}</div></div>
                <div className="st-field"><div className="k">Description</div><div className="v">{incident.description || "--"}</div></div>
                <div className="st-field"><div className="k">Alert product names</div>
                  <ul style={{ listStyle: "disc", paddingLeft: 20 }}>{incident.products.map(p => <li key={p}>{p}</li>)}</ul>
                </div>
                {state.tasks.length > 0 && (
                  <div className="st-field"><div className="k">Tasks</div>
                    <div className="st-progress" aria-hidden><i style={{ width: `${(tasksDone / state.tasks.length) * 100}%` }} /></div>
                    <span className="st-small">{tasksDone}/{state.tasks.length} completed. </span>
                    <button type="button" className="st-link st-small" onClick={() => setPane("tasks")}>View full details</button>
                  </div>
                )}
                <div className="st-field"><div className="k">Evidence</div>
                  <div className="st-ev">
                    <button type="button" onClick={() => openLogs({ query: incident.eventsQuery, run: true })} aria-label={`Events, ${incident.eventCount}`}>
                      <b><Activity size={16} color="#0078d4" aria-hidden />{fmtCount(incident.eventCount)}</b><span>Events</span>
                    </button>
                    <button type="button" onClick={() => openLogs({ query: alertsQuery(incident), run: true })} aria-label={`Alerts, ${incident.alertIds.length}`}>
                      <b><ShieldAlert size={16} color="#0078d4" aria-hidden />{incident.alertIds.length}</b><span>Alerts</span>
                    </button>
                    <button type="button" onClick={() => openLogs({ query: bookmarksQuery(incident), run: true })} aria-label={`Bookmarks, ${state.bookmarks.length}`}>
                      <b><Bookmark size={16} color="#0078d4" aria-hidden />{state.bookmarks.length}</b><span>Bookmarks</span>
                    </button>
                  </div>
                </div>
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
                      <li key={e.id}><button type="button" className="st-link st-row" style={{ gap: 4, maxWidth: "100%" }} onClick={() => showEntity(e.id)}><EntityIcon kind={e.kind} size={11} /><span className="st-ellipsis">{e.name}</span></button></li>
                    ))}
                  </ul>
                  {entities.length > 0 && <button type="button" className="st-link" onClick={() => setTab("entities")}>View all &gt;</button>}
                </div>
                <div className="st-field"><div className="k">Tactics and techniques</div>
                  {incident.tactics.length === 0 && <div className="v">--</div>}
                  {incident.tactics.length > 0 && (
                    <>
                      <button type="button" className="st-row" style={{ fontWeight: 600 }} aria-expanded={tacticsOpen} onClick={() => setTacticsOpen(o => !o)}>
                        {tacticsOpen ? <ChevronDown size={14} color="#0078d4" aria-hidden /> : <ChevronRight size={14} color="#0078d4" aria-hidden />}
                        <Target size={13} color="#0078d4" aria-hidden />{incident.tactics[0]}{incident.tactics.length > 1 ? ` +${incident.tactics.length - 1}` : ""} ({incident.techniques.length})
                      </button>
                      {tacticsOpen && (
                        <div style={{ paddingLeft: 22, marginTop: 4 }}>
                          <div>{incident.tactics.join(", ")}</div>
                          <ul className="st-small st-muted" style={{ marginTop: 4 }}>{incident.techniques.map(t => <li key={t}>{t}</li>)}</ul>
                        </div>
                      )}
                    </>
                  )}
                </div>
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
                items={[{ label: "Run playbook", onSelect: () => openPlaybook({ incidentId: incident.id }) }]}>
                Incident actions<ChevronDown size={12} aria-hidden />
              </ButtonMenu>
            )}
          </div>
          {tab === "overview" ? (
            <div className="st-widgets" role="tabpanel" aria-label="Overview">
              <TimelineWidget incident={incident} alerts={alerts} />
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
