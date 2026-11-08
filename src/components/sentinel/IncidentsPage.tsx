"use client";
// The Incidents blade, as in incident-grid.png: command bar, KPI strip with the severity bar, search and
// filter pills, the Auto-refresh switch, a grid with selection, and the details pane.
import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  BellRing, BookMarked, ChevronDown, ChevronUp, ChevronsRight, CircleDot, Clock3, FolderOpen, Hourglass, ListChecks, RotateCw, Rows3, Search, Siren, Table2,
} from "lucide-react";
import type { ClosingClassification, IncidentState, IncidentStatus, SentinelIncident, SentinelSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import {
  alertsQuery, bookmarksQuery, CLASSIFICATIONS, entitiesOf, escalationInfo, fmtCompact, fmtShortTime, SEV_RANK, SEVERITIES, STATUSES, tacticLabel,
} from "./helpers";
import { FieldBar } from "./IncidentFields";
import { IncidentDescription } from "./IncidentDescription";
import {
  ButtonMenu, ColumnsButton, Empty, FilterPill, rowKeys, Select, SimplePager, SlidePanel, SortTh, StatusIcon, Switch, type SortState,
} from "./ui";
import { EntityTile, SevChip } from "./XdrParts";

type SortKey = "severity" | "number" | "title" | "alerts" | "products" | "created" | "lastUpdate" | "owner" | "status" | "tactics";
const PAGE = 50;
const HOUR = 3_600_000;
const RANGES = [
  { value: "24", label: "Last 24 hours" }, { value: "48", label: "Last 48 hours" }, { value: "72", label: "Last 3 days" },
  { value: "168", label: "Last 7 days" }, { value: "720", label: "Last 30 days" },
];
const COLUMNS: { key: SortKey; label: string; width: number; always?: boolean }[] = [
  { key: "severity", label: "Severity", width: 124, always: true },
  { key: "number", label: "Incident ID", width: 104 },
  { key: "title", label: "Title", width: 250, always: true },
  { key: "alerts", label: "Alerts", width: 84 },
  { key: "products", label: "Product names", width: 150 },
  { key: "created", label: "Created time", width: 140 },
  { key: "lastUpdate", label: "Last update time", width: 150 },
  { key: "owner", label: "Owner", width: 120 },
  { key: "status", label: "Status", width: 84 },
  { key: "tactics", label: "Tactics", width: 170 },
];

/** The escalation tag and the analyst's summary, under an incident's title (preview and incident page). */
export function EscalationTag({ incident }: { incident: SentinelIncident }) {
  const esc = escalationInfo(incident);
  if (!esc) return null;
  return (
    <div className="st-inc-esc" data-escalated>
      <span className="st-esc-tag" title={esc.tag}>{esc.tag}</span>
      {esc.summary && <span className="st-esc-sub"><bdi>{esc.summary}</bdi></span>}
    </div>
  );
}

/** Evidence, as the details panel and the preview draw it. */
export function Evidence({ incident, state, linkLabels }: { incident: SentinelIncident; state: IncidentState; linkLabels?: boolean }) {
  const { openLogs } = useSentinel();
  const label = linkLabels ? "st-link" : undefined;
  return (
    <div className="st-ev">
      <button type="button" onClick={() => openLogs({ query: incident.eventsQuery, run: true })} aria-label={`Events, ${incident.eventCount}`}>
        <b><Rows3 size={18} color="#6d28d9" aria-hidden />{incident.eventCount}</b><span className={label}>Events</span>
      </button>
      <button type="button" onClick={() => openLogs({ query: alertsQuery(incident), run: true })} aria-label={`Alerts, ${incident.alertIds.length}`}>
        <b><BellRing size={18} color="#6d28d9" aria-hidden />{incident.alertIds.length}</b><span className={label}>Alerts</span>
      </button>
      <button type="button" onClick={() => openLogs({ query: bookmarksQuery(incident), run: true })} aria-label={`Bookmarks, ${state.bookmarks.length}`}>
        <b><BookMarked size={18} color="#6d28d9" aria-hidden />{state.bookmarks.length}</b><span className={label}>Bookmarks</span>
      </button>
    </div>
  );
}

export function TasksSummary({ state, onOpen }: { state: IncidentState; onOpen: () => void }) {
  if (!state.tasks.length) return null;
  const done = state.tasks.filter(t => t.done).length;
  return (
    <div className="st-field"><div className="k">Tasks</div>
      <div className="st-progress" aria-hidden><i style={{ width: `${(done / state.tasks.length) * 100}%` }} /></div>
      <span className="st-small">{done}/{state.tasks.length} completed. </span>
      <button type="button" className="st-link st-small" onClick={onOpen}>View full details</button>
    </div>
  );
}

export function IncidentPreview({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { ws, stateOf, openIncident, openInvestigation, openPlaybook, ended } = useSentinel();
  const state = stateOf(incident.id);
  const entities = useMemo(() => entitiesOf(incident, ws), [incident, ws]);
  const items = [
    { label: "Investigate", onSelect: () => openInvestigation(incident.id) },
    ...(ended ? [] : [{ label: "Run playbook", onSelect: () => openPlaybook({ incidentId: incident.id }) }]),
  ];
  return (
    <aside className="st-preview" aria-label={`Incident ${incident.number} preview`}>
      <div className="st-preview-head">
        <i className={`st-band ${state.severity} edge`} aria-hidden />
        <span className="xd-head-tile sm" aria-hidden><Siren size={16} /></span>
        <div className="st-grow" style={{ minWidth: 0 }}>
          <h2 className="st-wrap" title={incident.title}>{incident.title}</h2>
          <div className="st-small" style={{ fontWeight: 600 }}>Incident ID: {incident.number}</div>
          <EscalationTag incident={incident} />
        </div>
        <button type="button" className="st-icon-btn corner" aria-label="Close preview" onClick={onClose}><ChevronsRight size={13} aria-hidden /></button>
      </div>
      <FieldBar incident={incident} state={state} order={["owner", "status", "severity"]} />
      <div className="st-preview-body">
        <IncidentDescription incident={incident} />
        <div className="st-field"><div className="k">Alert product names</div>
          <ul className="xd-ac-chips wrap" style={{ marginTop: 4 }}>{incident.products.map(p => <li key={p} className="xd-chip prod">{p}</li>)}</ul>
        </div>
        <TasksSummary state={state} onOpen={() => openIncident(incident.id)} />
        <div className="st-field"><div className="k">Evidence</div><Evidence incident={incident} state={state} linkLabels /></div>
        <div className="st-2col st-field">
          <div><div className="st-k">Last update time</div>{fmtShortTime(incident.lastUpdate)}</div>
          <div><div className="st-k">Creation time</div>{fmtShortTime(incident.created)}</div>
        </div>
        <div className="st-field"><div className="k">Entities ({entities.length})</div>
          <ul>
            {entities.slice(0, 4).map(e => (
              <li key={e.id}>
                <button type="button" className="st-link st-row xd-elink" style={{ gap: 8, maxWidth: "100%" }} title={e.name} onClick={() => openIncident(incident.id, { entityId: e.id })}>
                  <EntityTile kind={e.kind} size={20} /><span className="st-ellipsis">{e.name}</span>
                </button>
              </li>
            ))}
          </ul>
          {entities.length > 0 && <button type="button" className="st-link" onClick={() => openIncident(incident.id, { entityId: entities[0].id })}>View full details &gt;</button>}
        </div>
      </div>
      <div className="st-preview-foot">
        <button type="button" className="st-btn primary" onClick={() => openIncident(incident.id)}>View full details</button>
        <ButtonMenu label="Actions" className="st-btn" items={items}>Actions<ChevronDown size={12} aria-hidden /></ButtonMenu>
      </div>
    </aside>
  );
}

/** The Actions command: the same three fields, applied to every ticked incident. */
function BulkActions({ ids, onClose }: { ids: string[]; onClose: () => void }) {
  const { actions, report } = useSentinel();
  const [severity, setSeverity] = useState<SentinelSeverity | "">("");
  const [status, setStatus] = useState<IncidentStatus | "">("");
  const [owner, setOwner] = useState("");
  const [classification, setClassification] = useState<ClosingClassification | "">("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const closing = status === "Closed";
  const any = !!severity || !!status || !!owner;
  const apply = async () => {
    setBusy(true);
    for (const id of ids) {
      report(await actions.updateIncident(id, {
        ...(severity ? { severity } : {}),
        ...(status ? { status } : {}),
        ...(owner ? { owner: owner === "__none" ? null : owner } : {}),
        ...(closing ? { classification: classification as ClosingClassification, closingComment: comment.trim() } : {}),
      }));
    }
    setBusy(false);
    onClose();
  };
  return (
    <SlidePanel title="Actions" subtitle={`${ids.length} ${ids.length === 1 ? "incident" : "incidents"} selected`} onClose={onClose} width={400}
      footer={<>
        <button type="button" className="st-btn primary" disabled={!any || busy || (closing && !classification)} onClick={() => void apply()}>Apply</button>
        <button type="button" className="st-btn" onClick={onClose}>Cancel</button>
      </>}>
      <div className="st-stack">
        <label><span className="st-label">Severity</span>
          <select data-autofocus className="st-input" value={severity} onChange={e => setSeverity(e.target.value as SentinelSeverity | "")}>
            <option value="">No change</option>{SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label><span className="st-label">Status</span>
          <select className="st-input" value={status} onChange={e => setStatus(e.target.value as IncidentStatus | "")}>
            <option value="">No change</option>{STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        {closing && (
          <>
            <label><span className="st-label">Classification</span>
              <select className="st-input" value={classification} onChange={e => setClassification(e.target.value as ClosingClassification)}>
                <option value="" disabled>Select classification</option>{CLASSIFICATIONS.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
            <label><span className="st-label">Comment</span>
              <textarea className="st-input st-textarea" maxLength={4000} value={comment} onChange={e => setComment(e.target.value)} />
            </label>
          </>
        )}
        <label><span className="st-label">Owner</span>
          <select className="st-input" value={owner} onChange={e => setOwner(e.target.value)}>
            <option value="">No change</option><option value="__none">Unassign Incident</option>
            {[...new Set(actions.people)].map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </label>
      </div>
    </SlidePanel>
  );
}

const IncidentRow = memo(function IncidentRow({ incident, state, selected, ticked, tickable, isNew, hidden, onSelect, onTick }: {
  incident: SentinelIncident; state: IncidentState; selected: boolean; ticked: boolean; tickable: boolean; isNew: boolean; hidden: Set<string>;
  onSelect: (id: string) => void; onTick: (id: string) => void;
}) {
  const show = (k: SortKey) => !hidden.has(k);
  const esc = escalationInfo(incident);
  return (
    <tr className={selected ? "selected" : undefined} tabIndex={0} aria-current={selected ? "true" : undefined} onClick={() => onSelect(incident.id)} onKeyDown={rowKeys(() => onSelect(incident.id))}>
      {tickable && (
        <td className="st-tick" onClick={e => e.stopPropagation()}>
          <input type="checkbox" aria-label={`Select incident ${incident.number}`} checked={ticked} onChange={() => onTick(incident.id)} />
        </td>
      )}
      <td className="st-sevcell"><i className={`st-cellband ${state.severity}`} aria-hidden /><SevChip value={state.severity} /></td>
      {show("number") && <td>{incident.number}</td>}
      <td title={esc ? `${incident.title}\n${esc.tag}${esc.summary ? `: ${esc.summary}` : ""}` : incident.title}>
        <span className="st-row" style={{ gap: 6 }}>
          {isNew && <span className="st-new-mark">New</span>}<span className="st-ellipsis">{incident.title}</span>
        </span>
        {/* Escalated: the rule's title stays, the tag and the analyst's own summary sit under it. */}
        {esc && (
          <span className="st-row" style={{ gap: 6, marginTop: 2 }} data-escalated>
            <span className="st-esc-tag">{esc.tag}</span>{esc.summary && <span className="st-esc-sub" style={{ minWidth: 0 }}><bdi>{esc.summary}</bdi></span>}
          </span>
        )}
      </td>
      {show("alerts") && <td>{incident.alertIds.length}</td>}
      {show("products") && <td title={incident.products.join(", ")}>{incident.products.join(", ")}</td>}
      {show("created") && <td>{fmtShortTime(incident.created)}</td>}
      {show("lastUpdate") && <td>{fmtShortTime(incident.lastUpdate)}</td>}
      {show("owner") && <td title={state.owner ?? "Unassigned"}>{state.owner ?? "Unassigned"}</td>}
      {show("status") && <td><span className="st-row" style={{ gap: 4 }}><StatusIcon status={state.status} size={12} />{state.status}</span></td>}
      {show("tactics") && <td title={incident.tactics.map(tacticLabel).join(", ")}>{incident.tactics.map(tacticLabel).join(", ")}</td>}
    </tr>
  );
});

export function IncidentsPage() {
  const { ws, stateOf, fresh, refresh, ended } = useSentinel();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  // Real default: Closed incidents stay out of the list until asked for.
  const [status, setStatus] = useState<string[]>(["New", "Active"]);
  const [products, setProducts] = useState<string[]>([]);
  const [owners, setOwners] = useState<string[]>([]);
  const [more, setMore] = useState(false);
  const [range, setRange] = useState("24");
  const [sort, setSort] = useState<SortState<SortKey>>({ key: "created", dir: "desc" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [ticked, setTicked] = useState<Set<string>>(() => new Set());
  const [hidden, setHidden] = useState<Set<string>>(() => new Set());
  const [page, setPage] = useState(0);
  const [bulk, setBulk] = useState(false);

  // With Auto-refresh off the list stays as it was until Refresh, so a row never moves under the cursor.
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [held, setHeld] = useState(ws.incidents);
  const latest = useRef(ws.incidents);
  latest.current = ws.incidents;
  const incidents = autoRefresh ? ws.incidents : held;
  const onAuto = (on: boolean) => { if (!on) setHeld(latest.current); setAutoRefresh(on); };
  const onRefresh = () => { setHeld(latest.current); refresh(); };

  const rows = useMemo(() => incidents.map(incident => ({ incident, state: stateOf(incident.id) })), [incidents, stateOf]);
  const open = useMemo(() => rows.filter(r => r.state.status !== "Closed"), [rows]);
  const counts = useMemo(() => ({
    open: open.length,
    new: open.filter(r => r.state.status === "New").length,
    active: open.filter(r => r.state.status === "Active").length,
    bySev: Object.fromEntries(SEVERITIES.map(s => [s, open.filter(r => r.state.severity === s).length])) as Record<string, number>,
  }), [open]);

  const productOptions = useMemo(() => [...new Set(incidents.flatMap(i => i.products))].sort(), [incidents]);
  const ownerOptions = useMemo(() => ["Unassigned", ...[...new Set(rows.map(r => r.state.owner).filter((o): o is string => !!o))].sort()], [rows]);

  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const since = Date.parse(ws.now) - Number(range) * HOUR;
    const list = rows.filter(({ incident: i, state: st }) =>
      Date.parse(i.created) >= since
      && (!sev.length || sev.includes(st.severity))
      && (!status.length || status.includes(st.status))
      && (!products.length || i.products.some(p => products.includes(p)))
      && (!owners.length || owners.includes(st.owner ?? "Unassigned"))
      && (!s || `${i.number} ${i.title} ${st.owner ?? ""} ${i.products.join(" ")} ${(() => { const e = escalationInfo(i); return e ? `${e.tag} ${e.summary}` : ""; })()}`.toLowerCase().includes(s)));
    const dir = sort.dir === "asc" ? 1 : -1;
    const val = (r: (typeof rows)[number]): string | number => {
      switch (sort.key) {
        case "severity": return -SEV_RANK[r.state.severity];
        case "number": return r.incident.number;
        case "title": return r.incident.title.toLowerCase();
        case "alerts": return r.incident.alertIds.length;
        case "products": return r.incident.products.join(", ").toLowerCase();
        case "created": return Date.parse(r.incident.created);
        case "lastUpdate": return Date.parse(r.incident.lastUpdate);
        case "owner": return (r.state.owner ?? "").toLowerCase();
        case "status": return STATUSES.indexOf(r.state.status);
        case "tactics": return r.incident.tactics.join(", ").toLowerCase();
      }
    };
    return [...list].sort((a, b) => {
      const x = val(a); const y = val(b);
      return (x < y ? -1 : x > y ? 1 : 0) * dir || b.incident.number - a.incident.number;
    });
  }, [rows, q, sev, status, products, owners, sort, range, ws.now]);

  useEffect(() => { setPage(0); }, [q, sev, status, products, owners, sort, range]);

  const onTick = useCallback((id: string) => setTicked(t => { const n = new Set(t); if (n.has(id)) n.delete(id); else n.add(id); return n; }), []);
  const pages = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pages - 1);
  const pageRows = shown.slice(safePage * PAGE, safePage * PAGE + PAGE);
  const selected = ws.incidents.find(i => i.id === selectedId) ?? null;
  const allTicked = pageRows.length > 0 && pageRows.every(r => ticked.has(r.incident.id));
  const columns = COLUMNS.filter(c => !hidden.has(c.key));
  const sevTotal = Math.max(1, SEVERITIES.reduce((n, s) => n + counts.bySev[s], 0));

  return (
    <div className="st-page">
      <div className="st-cmdbar st-cmdbar-line" role="toolbar" aria-label="Incidents commands">
        <button type="button" className="st-cmd" onClick={onRefresh}><RotateCw size={14} aria-hidden />Refresh</button>
        <Select label="Time range" value={range} options={RANGES} onChange={setRange} className="st-cmd">
          <Clock3 size={14} aria-hidden />{RANGES.find(r => r.value === range)?.label}<ChevronDown size={12} aria-hidden />
        </Select>
        {!ended && <button type="button" className="st-cmd" disabled={ticked.size === 0} onClick={() => setBulk(true)}><ListChecks size={14} aria-hidden />Actions</button>}
        <ColumnsButton columns={COLUMNS.filter(c => !c.always).map(c => ({ key: c.key, label: c.label }))} hidden={hidden}
          onToggle={k => setHidden(h => { const n = new Set(h); if (n.has(k)) n.delete(k); else n.add(k); return n; })}>
          <Table2 size={14} aria-hidden />Columns
        </ColumnsButton>
      </div>
      <div className="st-kpis">
        <div className="st-kpi"><b><span className="xd-kpi-ico" aria-hidden><Siren size={18} /></span>{fmtCompact(counts.open)}</b><span>Open incidents</span></div>
        <div className="st-kpi"><b><span className="xd-kpi-ico" aria-hidden><CircleDot size={18} /></span>{fmtCompact(counts.new)}</b><span>New incidents</span></div>
        <div className="st-kpi"><b><span className="xd-kpi-ico" aria-hidden><Hourglass size={18} /></span>{fmtCompact(counts.active)}</b><span>Active incidents</span></div>
        <div className="st-sevbar">
          <strong>Open incidents by severity</strong>
          <div className="bar" aria-hidden>
            {SEVERITIES.map(s => counts.bySev[s] > 0 && <i key={s} className={`st-band ${s}`} style={{ width: `${(counts.bySev[s] / sevTotal) * 100}%` }} />)}
          </div>
          <div className="legend">
            {SEVERITIES.map(s => <span key={s}><i className={`st-band ${s}`} aria-hidden />{s} ({counts.bySev[s]})</span>)}
          </div>
        </div>
      </div>
      <div className="st-split">
        <div className="st-split-main">
          <div className="st-filters">
            <label className="st-search" style={{ width: 300 }}><Search size={14} aria-hidden /><span className="st-sr">Search incidents</span>
              <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search by ID, title, tags, owner or product" />
            </label>
            <span className="st-cmdsep" aria-hidden />
            <FilterPill label="Severity" options={SEVERITIES} selected={sev} onChange={setSev} />
            <FilterPill label="Status" options={STATUSES} selected={status} onChange={setStatus} />
            {more && <FilterPill label="Product name" options={productOptions} selected={products} onChange={setProducts} />}
            {more && <FilterPill label="Owner" options={ownerOptions} selected={owners} onChange={setOwners} />}
            <button type="button" className="st-link st-morebtn" aria-expanded={more} onClick={() => setMore(m => !m)}>
              {more ? <ChevronUp size={13} aria-hidden /> : <ChevronDown size={13} aria-hidden />}{more ? "Less" : "More (2)"}
            </button>
          </div>
          <div className="st-autorefresh"><Switch label="Auto-refresh incidents" checked={autoRefresh} onChange={onAuto} /></div>
          <div className="st-page-scroll">
            <table className="st-table st-igrid" aria-label="Incidents" style={{ minWidth: columns.reduce((n, c) => n + c.width, ended ? 0 : 32) }}>
              <thead><tr>
                {!ended && (
                  <th scope="col" className="st-tick">
                    <input type="checkbox" aria-label="Select all incidents" checked={allTicked}
                      onChange={() => setTicked(allTicked ? new Set() : new Set(pageRows.map(r => r.incident.id)))} />
                  </th>
                )}
                {columns.map(c => <SortTh key={c.key} k={c.key} sort={sort} onSort={setSort} style={{ width: c.width }}>{c.label}</SortTh>)}
              </tr></thead>
              <tbody>
                {pageRows.map(r => (
                  <IncidentRow key={r.incident.id} incident={r.incident} state={r.state} selected={r.incident.id === selectedId} ticked={ticked.has(r.incident.id)} tickable={!ended}
                    isNew={fresh.has(r.incident.id)} hidden={hidden} onSelect={setSelectedId} onTick={onTick} />
                ))}
              </tbody>
            </table>
            {shown.length === 0 && (
              <Empty icon={<FolderOpen size={30} aria-hidden />} title={incidents.length ? "No incident matches the filters" : "No incidents yet"}>
                {incidents.length ? "Change the filters or the search text." : "Incidents appear here as analytics rules fire."}
              </Empty>
            )}
          </div>
          <SimplePager page={safePage} pages={pages} from={shown.length ? safePage * PAGE + 1 : 0} to={Math.min(shown.length, (safePage + 1) * PAGE)} onPage={setPage} />
        </div>
        {selected && <IncidentPreview incident={selected} onClose={() => setSelectedId(null)} />}
      </div>
      {bulk && <BulkActions ids={[...ticked]} onClose={() => { setBulk(false); setTicked(new Set()); }} />}
    </div>
  );
}
