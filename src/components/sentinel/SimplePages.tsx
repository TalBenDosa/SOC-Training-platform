"use client";
// Search, Hunts, Entities, Intel, Detections and Playbooks: XDR's own words and arrangement
// (owner, 2026-11-08): a search card, segmented views instead of single portal tabs, count cards,
// XDR's grid, and playbooks as action cards.
import { useCallback, useMemo, useState } from "react";
import { Bell, Bookmark, Bot, ChartSpline, Play, Radar, Rss, Search, ShieldCheck, UserRoundSearch, X } from "lucide-react";
import type { AnalyticsRule, EntityKind, HuntingQuery, SentinelBookmark, SentinelEntity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, EntityTimelineCard } from "./EntityCards";
import { runQuery } from "./engine";
import { fmtCount, fmtDateTime, KIND_LABEL, kqlString, SEV_RANK, tiIndicators } from "./helpers";
import { deviceOption, deviceState, IsolationReason, PLAYBOOKS, PlaybookHistory, RunResult } from "./IncidentPanes";
import { Empty, EntityIcon, rowKeys, SortTh, type SortState } from "./ui";
import { EntityTile, SevChip } from "./XdrParts";

function Pre({ text }: { text: string }) {
  return <pre className="st-mono st-small xd-pre">{text}</pre>;
}

/** A row of toggle buttons: one view or filter at a time. */
function Seg<T extends string>({ label, value, options, onChange }: { label: string; value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="xd-seg" role="group" aria-label={label}>
      {options.map(o => <button key={o.value} type="button" className="xd-seg-btn" aria-pressed={value === o.value} onClick={() => onChange(o.value)}>{o.label}</button>)}
    </div>
  );
}

/* ---------------------------------------------- search -------------------------------------------- */

export function SearchPage() {
  const { tables, openLogs } = useSentinel();
  const [term, setTerm] = useState("");
  const [recent, setRecent] = useState<string[]>([]);
  const [scope, setScope] = useState("");
  const populated = useMemo(() => Object.values(tables).filter(t => t.rows.length > 0).map(t => t.name).sort(), [tables]);
  const queryFor = (t: string) => (scope ? `search in (${scope}) ${kqlString(t)}` : `search ${kqlString(t)}`);
  const go = (t: string) => {
    const s = t.trim();
    if (!s) return;
    setRecent(r => [s, ...r.filter(x => x !== s)].slice(0, 8));
    openLogs({ query: queryFor(s), run: true });
  };
  return (
    <div className="st-page">
      <div className="st-page-scroll xd-pagepad">
        <section className="xd-card xd-searchcard" aria-label="Search the workspace">
          <h2 className="xd-card-title">Find anything in the workspace</h2>
          <p className="st-small st-muted">An IP, an account, a host, a hash or any text. XDR runs a search statement over the data sources and opens the rows in Query.</p>
          <form className="st-row" style={{ marginTop: 12, flexWrap: "wrap" }} onSubmit={e => { e.preventDefault(); go(term); }}>
            <label className="st-search st-grow" style={{ minWidth: 260 }}><Search size={14} aria-hidden /><span className="st-sr">Search across data sources</span>
              <input className="st-input xd-bigin" value={term} onChange={e => setTerm(e.target.value)} placeholder="Search for an IP, a user, a host or any text" />
            </label>
            <label><span className="st-sr">Data source</span>
              <select className="st-input xd-bigin" style={{ width: 210 }} value={scope} onChange={e => setScope(e.target.value)}>
                <option value="">All data sources</option>
                {populated.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <button type="submit" className="st-btn primary xd-bigbtn" disabled={!term.trim()}>Search</button>
          </form>
          {term.trim() && <div style={{ marginTop: 12 }}><div className="xd-eyebrow">KQL that will run</div><Pre text={queryFor(term.trim())} /></div>}
        </section>
        {recent.length > 0 && (
          <section className="xd-card" style={{ marginTop: 12, maxWidth: 760 }} aria-label="Recent searches">
            <h3 className="xd-eyebrow">Recent searches</h3>
            <ul className="xd-chiplist">{recent.map(r => <li key={r}><button type="button" className="xd-qchip" onClick={() => go(r)}><Search size={12} aria-hidden />{r}</button></li>)}</ul>
          </section>
        )}
      </div>
    </div>
  );
}

/* ---------------------------------------------- hunts --------------------------------------------- */

function HuntingQueries() {
  const { ws, tables, openLogs, actions } = useSentinel();
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const [counts, setCounts] = useState<Record<string, number | string>>({});
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return ws.hunting.filter(h => !s || `${h.name} ${h.description} ${h.tactics.join(" ")}`.toLowerCase().includes(s));
  }, [ws.hunting, q]);
  const run = useCallback((h: HuntingQuery) => {
    const r = runQuery(h.query, tables, ws.now);
    setCounts(c => ({ ...c, [h.id]: r.ok ? r.rows.length : "Query failed" }));
    try { actions.queryRan({ query: h.query, ok: r.ok, rows: r.ok ? r.rows.length : 0 }); } catch { /* telemetry never blocks */ }
  }, [actions, tables, ws.now]);
  const sel = ws.hunting.find(h => h.id === selected) ?? null;
  return (
    <div className="st-split">
      <div className="st-split-main">
        <div className="st-filters xd-filters">
          <label className="st-search" style={{ width: 280 }}><Search size={14} aria-hidden /><span className="st-sr">Search hunts</span>
            <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search hunts" />
          </label>
          <span className="st-grow" />
          <span className="st-small st-muted">{ws.hunting.length} hunts</span>
          <button type="button" className="st-btn" disabled={!shown.length} onClick={() => shown.forEach(run)}><Play size={13} aria-hidden />Run all hunts</button>
        </div>
        <div className="st-page-scroll xd-gridwrap">
          <table className="st-table xd-grid" aria-label="Hunt queries" style={{ minWidth: 760 }}>
            <thead><tr>
              <th scope="col" style={{ width: "36%" }}>Hunt</th><th scope="col" style={{ width: 90 }}>Hits</th><th scope="col">Data sources</th><th scope="col">Tactics</th><th scope="col" style={{ width: 120 }}>Techniques</th>
            </tr></thead>
            <tbody>
              {shown.map(h => (
                <tr key={h.id} tabIndex={0} className={h.id === selected ? "selected" : undefined} aria-current={h.id === selected ? "true" : undefined} onClick={() => setSelected(h.id)} onKeyDown={rowKeys(() => setSelected(h.id))}>
                  <td title={h.name} className="xd-cell-title">{h.name}</td>
                  <td>{counts[h.id] === undefined ? "-" : typeof counts[h.id] === "number" ? fmtCount(counts[h.id] as number) : counts[h.id]}</td>
                  <td title={h.dataSources.join(", ")}>{h.dataSources.join(", ")}</td>
                  <td title={h.tactics.join(", ")}>{h.tactics.join(", ")}</td>
                  <td title={h.techniques.join(", ")}>{h.techniques.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <Empty icon={<Radar size={28} aria-hidden />} title="No hunt matches" />}
        </div>
      </div>
      {sel && (
        <aside className="st-preview xd-preview" aria-label="Hunt details">
          <div className="st-preview-head xd-preview-head"><div className="st-grow" style={{ minWidth: 0 }}><div className="xd-eyebrow">Hunt</div><h2 className="st-wrap">{sel.name}</h2></div><button type="button" className="st-icon-btn" aria-label="Close hunt details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
          <div className="st-preview-body">
            <div className="st-field" style={{ marginTop: 0 }}><div className="k">Description</div><div className="v">{sel.description}</div></div>
            <div className="st-field"><div className="k">Hits</div><div className="v">{counts[sel.id] === undefined ? "Not run yet" : String(counts[sel.id])}</div></div>
            <div className="st-field"><div className="k">Tactics</div><div className="v">{sel.tactics.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Techniques</div><div className="v">{sel.techniques.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Data sources</div><div className="v">{sel.dataSources.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Query</div><Pre text={sel.query} /></div>
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => run(sel)}><Play size={13} aria-hidden />Run hunt</button>
            <button type="button" className="st-btn" onClick={() => openLogs({ query: sel.query, run: true })}>Open in Query</button>
          </div>
        </aside>
      )}
    </div>
  );
}

function HuntingBookmarks() {
  const { ws, bookmarks, openLogs, openIncident } = useSentinel();
  const [selected, setSelected] = useState<string | null>(null);
  const sel: SentinelBookmark | null = bookmarks.find(b => b.id === selected) ?? null;
  const incidentOf = (b: SentinelBookmark) => ws.incidents.find(i => i.id === b.incidentId);
  if (!bookmarks.length) return <Empty icon={<Bookmark size={28} aria-hidden />} title="No bookmarks yet">Select rows in Query and choose Add bookmark.</Empty>;
  return (
    <div className="st-split">
      <div className="st-split-main">
        <div className="st-page-scroll xd-gridwrap" style={{ paddingTop: 8 }}>
          <table className="st-table xd-grid" aria-label="Bookmarks" style={{ minWidth: 720 }}>
            <thead><tr><th scope="col">Name</th><th scope="col" style={{ width: 170 }}>Created</th><th scope="col" style={{ width: 130 }}>By</th><th scope="col" style={{ width: 170 }}>Incident</th><th scope="col">Notes</th></tr></thead>
            <tbody>
              {bookmarks.map(b => {
                const inc = incidentOf(b);
                return (
                  <tr key={b.id} tabIndex={0} className={b.id === selected ? "selected" : undefined} aria-current={b.id === selected ? "true" : undefined} onClick={() => setSelected(b.id)} onKeyDown={rowKeys(() => setSelected(b.id))}>
                    <td title={b.name} className="xd-cell-title">{b.name}</td><td>{fmtDateTime(b.at)}</td><td>{b.author}</td>
                    <td title={inc?.title}>{inc ? `#${inc.number} ${inc.title}` : "-"}</td><td title={b.notes}>{b.notes || "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      {sel && (
        <aside className="st-preview xd-preview" aria-label="Bookmark details">
          <div className="st-preview-head xd-preview-head"><div className="st-grow" style={{ minWidth: 0 }}><div className="xd-eyebrow">Bookmark</div><h2 className="st-wrap">{sel.name}</h2></div><button type="button" className="st-icon-btn" aria-label="Close bookmark details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
          <div className="st-preview-body">
            <div className="st-field" style={{ marginTop: 0 }}><div className="k">Created by</div><div className="v">{sel.author}, {fmtDateTime(sel.at)}</div></div>
            <div className="st-field"><div className="k">Notes</div><div className="v">{sel.notes || "--"}</div></div>
            <div className="st-field"><div className="k">Entities</div>
              <ul>{sel.entityIds.map(id => <li key={id}>{ws.entities[id]?.name ?? id}</li>)}{sel.entityIds.length === 0 && <li>--</li>}</ul>
            </div>
            <div className="st-field"><div className="k">Query</div><Pre text={sel.query} /></div>
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => openLogs({ query: sel.query, run: true, incidentId: sel.incidentId })}>Open in Query</button>
            {incidentOf(sel) && <button type="button" className="st-btn" onClick={() => openIncident(sel.incidentId as string)}>Open incident</button>}
          </div>
        </aside>
      )}
    </div>
  );
}

export function HuntingPage() {
  const { ws, bookmarks } = useSentinel();
  const [tab, setTab] = useState<"queries" | "bookmarks">("queries");
  return (
    <div className="st-page">
      <div className="xd-subbar">
        <Seg label="Hunts view" value={tab} onChange={setTab} options={[{ value: "queries", label: `Hunt queries (${ws.hunting.length})` }, { value: "bookmarks", label: `Bookmarks (${bookmarks.length})` }]} />
      </div>
      {tab === "queries" ? <HuntingQueries /> : <HuntingBookmarks />}
    </div>
  );
}

/* --------------------------------------------- entities ------------------------------------------- */

const KIND_FILTERS: { value: "all" | "account" | "host" | "network" | "other"; label: string; kinds?: EntityKind[] }[] = [
  { value: "all", label: "All" },
  { value: "account", label: "Accounts", kinds: ["account", "mailbox"] },
  { value: "host", label: "Devices", kinds: ["host", "process", "file", "registry"] },
  { value: "network", label: "Network", kinds: ["ip", "url", "domain"] },
  { value: "other", label: "Cloud and other", kinds: ["cloudapp", "azureresource"] },
];

export function EntityBehaviorPage({ focus, onFocus }: { focus: string | null; onFocus: (id: string | null) => void }) {
  const { ws } = useSentinel();
  const [q, setQ] = useState("");
  const [kindFilter, setKindFilter] = useState<(typeof KIND_FILTERS)[number]["value"]>("all");
  const list = useMemo(() => {
    const alertsPer = new Map<string, number>();
    for (const a of ws.alerts) for (const id of a.entityIds) alertsPer.set(id, (alertsPer.get(id) ?? 0) + 1);
    const s = q.trim().toLowerCase();
    const kinds = KIND_FILTERS.find(k => k.value === kindFilter)?.kinds;
    return Object.values(ws.entities)
      .filter(e => (!s || e.name.toLowerCase().includes(s)) && (!kinds || kinds.includes(e.kind)))
      .map(e => ({ e, alerts: alertsPer.get(e.id) ?? 0 }))
      .sort((a, b) => b.alerts - a.alerts || a.e.name.localeCompare(b.e.name))
      .slice(0, 50);
  }, [ws, q, kindFilter]);
  const entity: SentinelEntity | null = (focus && ws.entities[focus]) || null;
  return (
    <div className="st-page">
      {entity ? (
        <div className="st-entity-page">
          <section className="st-widget" aria-label="Info"><h3><EntityIcon kind={entity.kind} size={13} />{entity.name}</h3><div className="st-wscroll"><EntityInfoCard entity={entity} /></div></section>
          <section className="st-widget" aria-label="Timeline"><h3>Timeline</h3><div className="st-wscroll"><EntityTimelineCard entity={entity} /></div></section>
          <section className="st-widget" aria-label="Insights"><h3>Insights</h3><div className="st-wscroll"><EntityInsightsCard entity={entity} /></div></section>
        </div>
      ) : (
        <div className="st-page-scroll xd-pagepad">
          <div className="st-row" style={{ flexWrap: "wrap", gap: 10 }}>
            <label className="st-search" style={{ width: 360, maxWidth: "100%" }}><Search size={14} aria-hidden /><span className="st-sr">Search entities</span>
              <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search for an account, a host, an IP or any entity" />
            </label>
            <Seg label="Entity type" value={kindFilter} onChange={setKindFilter} options={KIND_FILTERS.map(k => ({ value: k.value, label: k.label }))} />
          </div>
          {list.length === 0 && <Empty icon={<UserRoundSearch size={28} aria-hidden />} title={Object.keys(ws.entities).length ? "No entity matches" : "No entities yet"} />}
          {list.length > 0 && (
            <table className="st-table xd-grid" aria-label="Entities" style={{ marginTop: 12, maxWidth: 820 }}>
              <thead><tr><th scope="col">Entity</th><th scope="col" style={{ width: 170 }}>Type</th><th scope="col" style={{ width: 110 }}>Alerts</th></tr></thead>
              <tbody>
                {list.map(({ e, alerts }) => (
                  <tr key={e.id} tabIndex={0} onClick={() => onFocus(e.id)} onKeyDown={rowKeys(() => onFocus(e.id))}>
                    <td title={e.name}><span className="st-row" style={{ gap: 10 }}><EntityTile kind={e.kind} size={22} /><span className="st-ellipsis xd-cell-title">{e.name}</span></span></td>
                    <td>{KIND_LABEL[e.kind]}</td><td>{alerts ? <span className="xd-ebadge">{alerts} {alerts === 1 ? "alert" : "alerts"}</span> : <span className="st-muted">None</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

/* ----------------------------------------------- intel -------------------------------------------- */

export function ThreatIntelPage() {
  const { ws, states, openIncident } = useSentinel();
  const list = useMemo(() => tiIndicators(states), [states]);
  return (
    <div className="st-page">
      {list.length === 0
        ? <Empty icon={<Rss size={28} aria-hidden />} title="No indicators yet">Choose Add to Intel on an IP, domain, URL or file entity of an incident.</Empty>
        : (
          <div className="st-page-scroll xd-pagepad">
            <div className="xd-kpis flat"><div className="st-kpi xd-kpi"><span>Indicators</span><b><span className="xd-kpi-ico" aria-hidden><Rss size={15} /></span>{list.length}</b></div></div>
            <table className="st-table xd-grid" aria-label="Threat indicators" style={{ minWidth: 640, marginTop: 12 }}>
              <thead><tr><th scope="col">Indicator</th><th scope="col" style={{ width: 130 }}>Type</th><th scope="col" style={{ width: 130 }}>Added by</th><th scope="col" style={{ width: 170 }}>Added</th><th scope="col" style={{ width: 100 }}>Incident</th></tr></thead>
              <tbody>
                {list.map(i => {
                  const inc = ws.incidents.find(x => x.id === i.incidentId);
                  return (
                    <tr key={i.id}>
                      <td title={i.name}><span className="st-row" style={{ gap: 10 }}><EntityTile kind={i.kind} size={22} /><span className="st-ellipsis st-mono">{i.name}</span></span></td>
                      <td>{KIND_LABEL[i.kind]}</td><td>{i.addedBy}</td><td>{fmtDateTime(i.at)}</td>
                      <td>{inc ? <button type="button" className="st-link" onClick={() => openIncident(inc.id)}>#{inc.number}</button> : "-"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
    </div>
  );
}

/* --------------------------------------------- detections ----------------------------------------- */

type RuleSort = "severity" | "name" | "alerts";

export function AnalyticsPage() {
  const { ws, openLogs } = useSentinel();
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<SortState<RuleSort>>({ key: "severity", dir: "desc" });
  const [selected, setSelected] = useState<string | null>(null);
  const alertCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const a of ws.alerts) if (a.ruleId) m.set(a.ruleId, (m.get(a.ruleId) ?? 0) + 1);
    return m;
  }, [ws.alerts]);
  const fired = useMemo(() => ws.rules.filter(r => (alertCount.get(r.id) ?? 0) > 0).length, [ws.rules, alertCount]);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    const list = ws.rules.filter(r => !s || `${r.name} ${r.tactics.join(" ")}`.toLowerCase().includes(s));
    const dir = sort.dir === "asc" ? 1 : -1;
    const val = (r: AnalyticsRule) => (sort.key === "severity" ? -SEV_RANK[r.severity] : sort.key === "alerts" ? alertCount.get(r.id) ?? 0 : r.name.toLowerCase());
    return [...list].sort((a, b) => { const x = val(a); const y = val(b); return (x < y ? -1 : x > y ? 1 : 0) * dir; });
  }, [ws.rules, q, sort, alertCount]);
  const sel = ws.rules.find(r => r.id === selected) ?? null;
  return (
    <div className="st-page">
      <div className="xd-kpis">
        <div className="st-kpi xd-kpi"><span>Detection rules</span><b><span className="xd-kpi-ico" aria-hidden><ChartSpline size={15} /></span>{ws.rules.length}</b></div>
        <div className="st-kpi xd-kpi"><span>Rules that fired</span><b><span className="xd-kpi-ico" aria-hidden><ShieldCheck size={15} /></span>{fired}</b></div>
        <div className="st-kpi xd-kpi"><span>Alerts raised</span><b><span className="xd-kpi-ico" aria-hidden><Bell size={15} /></span>{fmtCount(ws.alerts.length)}</b></div>
      </div>
      <div className="st-split">
        <div className="st-split-main">
          <div className="st-filters xd-filters">
            <label className="st-search" style={{ width: 280 }}><Search size={14} aria-hidden /><span className="st-sr">Search rules</span>
              <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search by name or tactic" />
            </label>
            <span className="st-grow" />
            <span className="st-small st-muted">All rules run on a schedule and are on.</span>
          </div>
          <div className="st-page-scroll xd-gridwrap">
            <table className="st-table xd-grid" aria-label="Detection rules" style={{ minWidth: 820 }}>
              <thead><tr>
                <SortTh k="severity" sort={sort} onSort={setSort} style={{ width: 118 }}>Severity</SortTh>
                <SortTh k="name" sort={sort} onSort={setSort} style={{ width: "38%" }}>Rule</SortTh>
                <th scope="col" style={{ width: 120 }}>Runs every</th><th scope="col" style={{ width: 80 }}>State</th><th scope="col">Tactics</th><th scope="col" style={{ width: 120 }}>Techniques</th>
                <SortTh k="alerts" sort={sort} onSort={setSort} style={{ width: 84 }}>Alerts</SortTh>
              </tr></thead>
              <tbody>
                {shown.map(r => (
                  <tr key={r.id} tabIndex={0} className={r.id === selected ? "selected" : undefined} aria-current={r.id === selected ? "true" : undefined} onClick={() => setSelected(r.id)} onKeyDown={rowKeys(() => setSelected(r.id))}>
                    <td><SevChip value={r.severity} /></td><td title={r.name} className="xd-cell-title">{r.name}</td><td>{r.frequency}</td><td><span className="xd-status on">On</span></td>
                    <td title={r.tactics.join(", ")}>{r.tactics.join(", ")}</td><td title={r.techniques.join(", ")}>{r.techniques.join(", ")}</td><td>{alertCount.get(r.id) ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <Empty title="No rule matches" />}
          </div>
        </div>
        {sel && (
          <aside className="st-preview xd-preview" aria-label="Rule details">
            <div className={`st-preview-head xd-preview-head ${sel.severity}`}><div className="st-grow" style={{ minWidth: 0 }}><div className="xd-eyebrow">Detection rule</div><h2 className="st-wrap">{sel.name}</h2><div style={{ marginTop: 6 }}><SevChip value={sel.severity} /></div></div><button type="button" className="st-icon-btn" aria-label="Close rule details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
            <div className="st-preview-body">
              <div className="st-field" style={{ marginTop: 0 }}><div className="k">Description</div><div className="v">{sel.description}</div></div>
              <div className="st-field"><div className="k">Tactics</div><div className="v">{sel.tactics.join(", ") || "--"}</div></div>
              <div className="st-field"><div className="k">Techniques</div><div className="v">{sel.techniques.join(", ") || "--"}</div></div>
              <div className="st-2col st-field"><div><div className="st-k">Runs every</div>{sel.frequency}</div><div><div className="st-k">Looks back over</div>{sel.lookback}</div></div>
              <div className="st-field"><div className="k">Data sources</div><div className="v">{sel.dataSources.join(", ") || "--"}</div></div>
              {sel.falsePositives.length > 0 && <div className="st-field"><div className="k">Known false positives</div><ul style={{ listStyle: "disc", paddingLeft: 18 }}>{sel.falsePositives.map(f => <li key={f}>{f}</li>)}</ul></div>}
              <div className="st-field"><div className="k">Rule query</div><Pre text={sel.query} /></div>
            </div>
            <div className="st-preview-foot"><button type="button" className="st-btn primary" onClick={() => openLogs({ query: sel.query, run: true })}>Open in Query</button></div>
          </aside>
        )}
      </div>
    </div>
  );
}

/* --------------------------------------------- playbooks ------------------------------------------ */

export function AutomationPage() {
  const { ws, actions, runPlaybook, runs, ended } = useSentinel();
  const hosts = useMemo(() => [...new Set(Object.values(ws.entities).filter(e => e.kind === "host").map(e => e.name))].sort((a, b) => a.localeCompare(b)), [ws.entities]);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [reason, setReason] = useState("");
  const [reasonErr, setReasonErr] = useState<string | null>(null);
  const asks = !!actions.requestIsolation;
  const host = target || hosts[0] || "";
  const state = host ? deviceState(actions, host) : null;
  const last = runs[0];
  const run = async (name: "Isolate device" | "Release device") => {
    // In a team session "Isolate device" asks the senior on shift (2026-11-07), with a reason.
    if (name === "Isolate device" && asks && !reason.trim()) { setReasonErr("Say in a few words why this device should be isolated."); return; }
    setBusy(true); setReasonErr(null);
    const r = await runPlaybook(name, host, undefined, reason.trim());
    setBusy(false);
    if (r.ok && name === "Isolate device") setReason("");
  };
  return (
    <div className="st-page">
      <div className="st-page-scroll xd-pagepad">
        {hosts.length === 0
          ? <Empty icon={<Bot size={28} aria-hidden />} title="No device to act on yet">Playbooks here act on devices. Devices appear once they are seen in the logs.</Empty>
          : (
            <div className="xd-pb-layout">
              <section className="xd-card" aria-label="Target device">
                <h2 className="xd-eyebrow">1. Choose the device</h2>
                <label style={{ display: "block", marginTop: 6 }}><span className="st-sr">Device</span>
                  <select className="st-input" value={host} onChange={e => setTarget(e.target.value)}>{hosts.map(h => <option key={h} value={h}>{deviceOption(actions, h)}</option>)}</select>
                </label>
                {state && <p className="st-small st-muted" role="status" style={{ marginTop: 8 }}>Current state: {state.label}</p>}
                {asks && <div style={{ marginTop: 10 }}><IsolationReason id="auto-reason" value={reason} onChange={v => { setReason(v); if (reasonErr) setReasonErr(null); }} error={reasonErr} /></div>}
              </section>
              <section className="xd-card" aria-label="Available playbooks">
                <h2 className="xd-eyebrow">2. Run a playbook</h2>
                {last && <div style={{ margin: "6px 0 8px" }}><RunResult run={last} /></div>}
                <ul className="xd-pb-cards" aria-label="Playbooks">
                  {PLAYBOOKS.map(p => (
                    <li key={p.name} className="xd-pb-card">
                      <span className="xd-pb-ico" aria-hidden><Bot size={16} /></span>
                      <div className="st-grow" style={{ minWidth: 0 }}>
                        <strong>{p.name}</strong>
                        <div className="st-small st-muted">{p.description}</div>
                        <div className="xd-ac-chips" style={{ marginTop: 5 }}><span className="xd-chip prod">On</span><span className="xd-chip prod">Runs on a device</span></div>
                      </div>
                      <button type="button" className="st-btn" disabled={ended || busy || !host || (p.name === "Isolate device" && !!(state?.isolated || state?.pending))} aria-label={p.name === "Isolate device" && asks ? "Request isolation" : `Run ${p.name}`} onClick={() => void run(p.name)}><Play size={12} aria-hidden />{p.name === "Isolate device" && asks ? "Request" : "Run"}</button>
                    </li>
                  ))}
                </ul>
              </section>
            </div>
          )}
        {(runs.length > 0 || (actions.isolationRequests ?? []).some(r => r.mine)) && (
          <section style={{ marginTop: 18 }} aria-label="Runs in this session">
            <h3 className="xd-eyebrow" style={{ marginBottom: 6 }}>Runs in this session</h3>
            <PlaybookHistory runs={runs} actions={actions} />
          </section>
        )}
      </div>
    </div>
  );
}
