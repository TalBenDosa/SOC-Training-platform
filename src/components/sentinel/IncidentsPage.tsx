"use client";
import { memo, useEffect, useMemo, useState } from "react";
import { ChevronDown, FolderOpen, RefreshCw, Search, X } from "lucide-react";
import type { IncidentState, SentinelIncident } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { alertsOf, entitiesOf, fmtDateTime, SEV_RANK, SEVERITIES, STATUSES } from "./helpers";
import { FieldStack } from "./IncidentFields";
import {
  BladeTitle, ButtonMenu, Empty, EntityIcon, FilterPill, rowKeys, Severity, SimplePager, SortTh, StatusIcon, type SortState,
} from "./ui";

type SortKey = "severity" | "number" | "title" | "alerts" | "products" | "created" | "lastUpdate" | "owner" | "status" | "tactics";
const PAGE = 50;

export function IncidentPreview({ incident, onClose }: { incident: SentinelIncident; onClose: () => void }) {
  const { ws, stateOf, openIncident, openInvestigation, openPlaybook, openLogs, ended } = useSentinel();
  const state = stateOf(incident.id);
  const alerts = useMemo(() => alertsOf(incident, ws), [incident, ws]);
  const entities = useMemo(() => entitiesOf(incident, ws), [incident, ws]);
  const items = [
    { label: "Investigate", onSelect: () => openInvestigation(incident.id) },
    ...(ended ? [] : [{ label: "Run playbook", onSelect: () => openPlaybook({ incidentId: incident.id }) }]),
  ];
  return (
    <aside className="st-preview" aria-label={`Incident ${incident.number} preview`}>
      <div className="st-preview-head">
        <Severity value={state.severity} />
        <span className="st-grow" />
        <button type="button" className="st-icon-btn" aria-label="Close preview" onClick={onClose}><X size={16} aria-hidden /></button>
      </div>
      <div className="st-preview-body">
        <h2 style={{ fontSize: 16, lineHeight: 1.3 }}>{incident.title}</h2>
        <div className="st-small st-muted">Incident ID {incident.number}</div>
        <div style={{ marginTop: 10 }}><FieldStack incident={incident} state={state} /></div>
        <div className="st-field"><div className="k">Description</div><div className="v">{incident.description || "--"}</div></div>
        <div className="st-2col st-field">
          <div><div className="st-k">Creation time</div>{fmtDateTime(incident.created)}</div>
          <div><div className="st-k">Last update time</div>{fmtDateTime(incident.lastUpdate)}</div>
        </div>
        <div className="st-field"><div className="k">Alerts ({alerts.length})</div>
          <ul>
            {alerts.slice(0, 8).map(a => (
              <li key={a.id} className="st-row" style={{ alignItems: "stretch", marginTop: 3 }}>
                <i className={`st-band ${a.severity}`} aria-hidden />
                <button type="button" className="st-link st-ellipsis" title={a.name} onClick={() => openLogs({ query: a.query, run: true })}>{a.name}</button>
              </li>
            ))}
          </ul>
          {alerts.length > 8 && <div className="st-small st-muted">and {alerts.length - 8} more</div>}
        </div>
        <div className="st-field"><div className="k">Entities ({entities.length})</div>
          <ul>
            {entities.slice(0, 8).map(e => (
              <li key={e.id} className="st-row" style={{ marginTop: 3 }}>
                <EntityIcon kind={e.kind} size={12} />
                <button type="button" className="st-link st-ellipsis" title={e.name} onClick={() => openIncident(incident.id, { entityId: e.id })}>{e.name}</button>
              </li>
            ))}
          </ul>
          {entities.length > 8 && <div className="st-small st-muted">and {entities.length - 8} more</div>}
        </div>
        <div className="st-field"><div className="k">Tactics</div><div className="v">{incident.tactics.join(", ") || "--"}</div></div>
      </div>
      <div className="st-preview-foot">
        <button type="button" className="st-btn primary" onClick={() => openIncident(incident.id)}>View full details</button>
        <ButtonMenu label="Actions" className="st-btn" items={items}>Actions<ChevronDown size={12} aria-hidden /></ButtonMenu>
      </div>
    </aside>
  );
}

const IncidentRow = memo(function IncidentRow({ incident, state, selected, isNew, onSelect }: {
  incident: SentinelIncident; state: IncidentState; selected: boolean; isNew: boolean; onSelect: (id: string) => void;
}) {
  return (
    <tr className={selected ? "selected" : undefined} tabIndex={0} aria-current={selected ? "true" : undefined} onClick={() => onSelect(incident.id)} onKeyDown={rowKeys(() => onSelect(incident.id))}>
      <td><Severity value={state.severity} /></td>
      <td>{incident.number}</td>
      <td title={incident.title}>
        <span className="st-row" style={{ gap: 6 }}>
          {isNew && <span className="st-new-mark">New</span>}<span className="st-ellipsis">{incident.title}</span>
        </span>
      </td>
      <td>{incident.alertIds.length}</td>
      <td title={incident.products.join(", ")}>{incident.products.join(", ")}</td>
      <td>{fmtDateTime(incident.created)}</td>
      <td>{fmtDateTime(incident.lastUpdate)}</td>
      <td title={state.owner ?? "Unassigned"}>{state.owner ?? "Unassigned"}</td>
      <td><span className="st-row" style={{ gap: 4 }}><StatusIcon status={state.status} size={12} />{state.status}</span></td>
      <td title={incident.tactics.join(", ")}>{incident.tactics.join(", ")}</td>
    </tr>
  );
});

export function IncidentsPage() {
  const { ws, stateOf, fresh, refresh } = useSentinel();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string[]>([]);
  // Real default: Closed incidents stay out of the list until asked for.
  const [status, setStatus] = useState<string[]>(["New", "Active"]);
  const [products, setProducts] = useState<string[]>([]);
  const [owners, setOwners] = useState<string[]>([]);
  const [sort, setSort] = useState<SortState<SortKey>>({ key: "created", dir: "desc" });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [page, setPage] = useState(0);

  const rows = useMemo(() => ws.incidents.map(incident => ({ incident, state: stateOf(incident.id) })), [ws.incidents, stateOf]);

  const open = useMemo(() => rows.filter(r => r.state.status !== "Closed"), [rows]);
  const counts = useMemo(() => ({
    open: open.length,
    new: open.filter(r => r.state.status === "New").length,
    active: open.filter(r => r.state.status === "Active").length,
    bySev: Object.fromEntries(SEVERITIES.map(s => [s, open.filter(r => r.state.severity === s).length])) as Record<string, number>,
  }), [open]);

  const productOptions = useMemo(() => [...new Set(ws.incidents.flatMap(i => i.products))].sort(), [ws.incidents]);
  const ownerOptions = useMemo(() => ["Unassigned", ...[...new Set(rows.map(r => r.state.owner).filter((o): o is string => !!o))].sort()], [rows]);

  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = rows.filter(({ incident: i, state: st }) =>
      (!sev.length || sev.includes(st.severity))
      && (!status.length || status.includes(st.status))
      && (!products.length || i.products.some(p => products.includes(p)))
      && (!owners.length || owners.includes(st.owner ?? "Unassigned"))
      && (!s || `${i.number} ${i.title} ${st.owner ?? ""} ${i.products.join(" ")}`.toLowerCase().includes(s)));
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
  }, [rows, q, sev, status, products, owners, sort]);

  useEffect(() => { setPage(0); }, [q, sev, status, products, owners, sort]);

  const pages = Math.max(1, Math.ceil(shown.length / PAGE));
  const safePage = Math.min(page, pages - 1);
  const pageRows = shown.slice(safePage * PAGE, safePage * PAGE + PAGE);
  const selected = ws.incidents.find(i => i.id === selectedId) ?? null;
  const maxSev = Math.max(1, ...SEVERITIES.map(s => counts.bySev[s]));

  return (
    <div className="st-page">
      <BladeTitle title="Sentinel | Incidents" sub={`Selected workspace: '${ws.name}'`} crumbs={[{ label: "Home" }, { label: "Sentinel" }]} />
      <div className="st-cmdbar" role="toolbar" aria-label="Incidents commands" style={{ paddingLeft: 8 }}>
        <button type="button" className="st-cmd" onClick={refresh}><RefreshCw size={14} aria-hidden />Refresh</button>
        <span className="st-small st-muted" style={{ marginLeft: 8 }}>Auto-refresh incidents is on.</span>
      </div>
      <div className="st-kpis">
        <div className="st-kpi"><b>{counts.open}</b><span>Open incidents</span></div>
        <div className="st-kpi"><b>{counts.new}</b><span>New incidents</span></div>
        <div className="st-kpi"><b>{counts.active}</b><span>Active incidents</span></div>
        <div className="st-kpi" style={{ border: 0 }}>
          <div className="st-sevbar" aria-label="Open incidents by severity">
            {SEVERITIES.map(s => (
              <div key={s} className="st-sevbar-row">
                <span>{s}</span>
                <span className="st-sevbar-track"><span className={`st-band ${s} st-sevbar-fill`} style={{ display: "block", width: `${(counts.bySev[s] / maxSev) * 100}%` }} /></span>
                <span>{counts.bySev[s]}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="st-split">
        <div className="st-split-main">
          <div className="st-filters">
            <label className="st-search" style={{ width: 240 }}><Search size={14} aria-hidden /><span className="st-sr">Search incidents</span>
              <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search by ID, title, owner or product" />
            </label>
            <FilterPill label="Severity" options={SEVERITIES} selected={sev} onChange={setSev} />
            <FilterPill label="Status" options={STATUSES} selected={status} onChange={setStatus} />
            <FilterPill label="Product name" options={productOptions} selected={products} onChange={setProducts} />
            <FilterPill label="Owner" options={ownerOptions} selected={owners} onChange={setOwners} />
          </div>
          <div className="st-page-scroll">
            <table className="st-table" aria-label="Incidents" style={{ minWidth: 1120 }}>
              <thead><tr>
                <SortTh k="severity" sort={sort} onSort={setSort} style={{ width: 110 }}>Severity</SortTh>
                <SortTh k="number" sort={sort} onSort={setSort} style={{ width: 124 }}>Incident number</SortTh>
                <SortTh k="title" sort={sort} onSort={setSort} style={{ width: 300 }}>Title</SortTh>
                <SortTh k="alerts" sort={sort} onSort={setSort} style={{ width: 60 }}>Alerts</SortTh>
                <SortTh k="products" sort={sort} onSort={setSort} style={{ width: 170 }}>Product names</SortTh>
                <SortTh k="created" sort={sort} onSort={setSort} style={{ width: 160 }}>Created time</SortTh>
                <SortTh k="lastUpdate" sort={sort} onSort={setSort} style={{ width: 160 }}>Last update time</SortTh>
                <SortTh k="owner" sort={sort} onSort={setSort} style={{ width: 120 }}>Owner</SortTh>
                <SortTh k="status" sort={sort} onSort={setSort} style={{ width: 84 }}>Status</SortTh>
                <SortTh k="tactics" sort={sort} onSort={setSort} style={{ width: 170 }}>Tactics</SortTh>
              </tr></thead>
              <tbody>
                {pageRows.map(r => (
                  <IncidentRow key={r.incident.id} incident={r.incident} state={r.state} selected={r.incident.id === selectedId} isNew={fresh.has(r.incident.id)} onSelect={setSelectedId} />
                ))}
              </tbody>
            </table>
            {shown.length === 0 && (
              <Empty icon={<FolderOpen size={30} aria-hidden />} title={ws.incidents.length ? "No incident matches the filters" : "No incidents yet"}>
                {ws.incidents.length ? "Change the filters or the search text." : "Incidents appear here as analytics rules fire."}
              </Empty>
            )}
          </div>
          {shown.length > PAGE && <SimplePager page={safePage} pages={pages} from={safePage * PAGE + 1} to={Math.min(shown.length, (safePage + 1) * PAGE)} total={shown.length} onPage={setPage} />}
        </div>
        {selected && <IncidentPreview incident={selected} onClose={() => setSelectedId(null)} />}
      </div>
    </div>
  );
}
