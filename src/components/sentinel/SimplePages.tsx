"use client";
// Search, Hunting, Entity behavior, Threat intelligence, Analytics and Automation.
import { useCallback, useMemo, useState } from "react";
import { Bookmark, Crosshair, Fingerprint, Play, Search, ShieldCheck, Workflow, X } from "lucide-react";
import type { AnalyticsRule, HuntingQuery, SentinelBookmark, SentinelEntity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { EntityInfoCard, EntityInsightsCard, EntityTimelineCard } from "./EntityCards";
import { runQuery } from "./engine";
import { fmtCount, fmtDateTime, KIND_LABEL, kqlString, SEV_RANK, tiIndicators } from "./helpers";
import { hostIsolated, PLAYBOOKS, RunResult } from "./IncidentPanes";
import { Empty, EntityIcon, rowKeys, Severity, SortTh, Tabs, type SortState } from "./ui";

function Pre({ text }: { text: string }) {
  return <pre className="st-mono st-small" style={{ margin: "4px 0 0", padding: 8, background: "var(--st-canvas)", border: "1px solid var(--st-border)", whiteSpace: "pre-wrap", wordBreak: "break-word", maxHeight: 240, overflow: "auto" }}>{text}</pre>;
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
      <div style={{ padding: "8px 16px", maxWidth: 720 }}>
        <form className="st-row" onSubmit={e => { e.preventDefault(); go(term); }}>
          <label className="st-search st-grow"><Search size={14} aria-hidden /><span className="st-sr">Search across tables</span>
            <input className="st-input" value={term} onChange={e => setTerm(e.target.value)} placeholder="Search for an IP, a user, a host or any text" />
          </label>
          <label><span className="st-sr">Table</span>
            <select className="st-input" style={{ width: 200 }} value={scope} onChange={e => setScope(e.target.value)}>
              <option value="">All tables</option>
              {populated.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <button type="submit" className="st-btn primary" disabled={!term.trim()}>Search</button>
        </form>
        <p className="st-small st-muted" style={{ marginTop: 8 }}>Runs a search statement over the workspace and opens the results in Logs.</p>
        {term.trim() && <div style={{ marginTop: 8 }}><span className="st-small st-muted">Query</span><Pre text={queryFor(term.trim())} /></div>}
        {recent.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <h3 style={{ fontSize: 13, marginBottom: 4 }}>Recent searches</h3>
            <ul>{recent.map(r => <li key={r}><button type="button" className="st-link" onClick={() => go(r)}>{r}</button></li>)}</ul>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------------------------------------------- hunting ------------------------------------------- */

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
        <div className="st-filters">
          <label className="st-search" style={{ width: 280 }}><Search size={14} aria-hidden /><span className="st-sr">Search queries</span>
            <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search queries" />
          </label>
          <button type="button" className="st-btn" disabled={!shown.length} onClick={() => shown.forEach(run)}><Play size={13} aria-hidden />Run all queries</button>
          <span className="st-small st-muted">{ws.hunting.length} queries</span>
        </div>
        <div className="st-page-scroll">
          <table className="st-table" aria-label="Hunting queries" style={{ minWidth: 760 }}>
            <thead><tr>
              <th scope="col" style={{ width: "36%" }}>Query</th><th scope="col" style={{ width: 90 }}>Results</th><th scope="col">Data sources</th><th scope="col">Tactics</th><th scope="col" style={{ width: 120 }}>Techniques</th>
            </tr></thead>
            <tbody>
              {shown.map(h => (
                <tr key={h.id} tabIndex={0} className={h.id === selected ? "selected" : undefined} aria-current={h.id === selected ? "true" : undefined} onClick={() => setSelected(h.id)} onKeyDown={rowKeys(() => setSelected(h.id))}>
                  <td title={h.name}>{h.name}</td>
                  <td>{counts[h.id] === undefined ? "-" : typeof counts[h.id] === "number" ? fmtCount(counts[h.id] as number) : counts[h.id]}</td>
                  <td title={h.dataSources.join(", ")}>{h.dataSources.join(", ")}</td>
                  <td title={h.tactics.join(", ")}>{h.tactics.join(", ")}</td>
                  <td title={h.techniques.join(", ")}>{h.techniques.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length === 0 && <Empty icon={<Crosshair size={28} aria-hidden />} title="No queries match" />}
        </div>
      </div>
      {sel && (
        <aside className="st-preview" aria-label="Query details">
          <div className="st-preview-head"><h2 className="st-grow">{sel.name}</h2><button type="button" className="st-icon-btn" aria-label="Close query details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
          <div className="st-preview-body">
            <div className="st-field" style={{ marginTop: 0 }}><div className="k">Description</div><div className="v">{sel.description}</div></div>
            <div className="st-field"><div className="k">Results</div><div className="v">{counts[sel.id] === undefined ? "Not run yet" : String(counts[sel.id])}</div></div>
            <div className="st-field"><div className="k">Tactics</div><div className="v">{sel.tactics.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Techniques</div><div className="v">{sel.techniques.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Data sources</div><div className="v">{sel.dataSources.join(", ") || "--"}</div></div>
            <div className="st-field"><div className="k">Query</div><Pre text={sel.query} /></div>
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => run(sel)}><Play size={13} aria-hidden />Run query</button>
            <button type="button" className="st-btn" onClick={() => openLogs({ query: sel.query, run: true })}>View results</button>
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
  if (!bookmarks.length) return <Empty icon={<Bookmark size={28} aria-hidden />} title="No bookmarks yet">Select rows in Logs and choose Add bookmark.</Empty>;
  return (
    <div className="st-split">
      <div className="st-split-main">
        <div className="st-page-scroll">
          <table className="st-table" aria-label="Bookmarks" style={{ minWidth: 720 }}>
            <thead><tr><th scope="col">Name</th><th scope="col" style={{ width: 170 }}>Created time</th><th scope="col" style={{ width: 130 }}>Created by</th><th scope="col" style={{ width: 170 }}>Incident</th><th scope="col">Notes</th></tr></thead>
            <tbody>
              {bookmarks.map(b => {
                const inc = incidentOf(b);
                return (
                  <tr key={b.id} tabIndex={0} className={b.id === selected ? "selected" : undefined} aria-current={b.id === selected ? "true" : undefined} onClick={() => setSelected(b.id)} onKeyDown={rowKeys(() => setSelected(b.id))}>
                    <td title={b.name}>{b.name}</td><td>{fmtDateTime(b.at)}</td><td>{b.author}</td>
                    <td title={inc?.title}>{inc ? `${inc.number}: ${inc.title}` : "-"}</td><td title={b.notes}>{b.notes || "-"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
      {sel && (
        <aside className="st-preview" aria-label="Bookmark details">
          <div className="st-preview-head"><h2 className="st-grow">{sel.name}</h2><button type="button" className="st-icon-btn" aria-label="Close bookmark details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
          <div className="st-preview-body">
            <div className="st-field" style={{ marginTop: 0 }}><div className="k">Created by</div><div className="v">{sel.author}, {fmtDateTime(sel.at)}</div></div>
            <div className="st-field"><div className="k">Notes</div><div className="v">{sel.notes || "--"}</div></div>
            <div className="st-field"><div className="k">Entities</div>
              <ul>{sel.entityIds.map(id => <li key={id}>{ws.entities[id]?.name ?? id}</li>)}{sel.entityIds.length === 0 && <li>--</li>}</ul>
            </div>
            <div className="st-field"><div className="k">Query</div><Pre text={sel.query} /></div>
          </div>
          <div className="st-preview-foot">
            <button type="button" className="st-btn primary" onClick={() => openLogs({ query: sel.query, run: true, incidentId: sel.incidentId })}>View in Logs</button>
            {incidentOf(sel) && <button type="button" className="st-btn" onClick={() => openIncident(sel.incidentId as string)}>Open incident</button>}
          </div>
        </aside>
      )}
    </div>
  );
}

export function HuntingPage() {
  const { bookmarks } = useSentinel();
  const [tab, setTab] = useState<"queries" | "bookmarks">("queries");
  return (
    <div className="st-page">
      <div style={{ padding: "0 16px 6px" }}>
        <Tabs label="Hunting" value={tab} onChange={setTab} tabs={[{ value: "queries", label: "Queries" }, { value: "bookmarks", label: `Bookmarks (${bookmarks.length})` }]} />
      </div>
      {tab === "queries" ? <HuntingQueries /> : <HuntingBookmarks />}
    </div>
  );
}

/* ------------------------------------------ entity behavior --------------------------------------- */

export function EntityBehaviorPage({ focus, onFocus }: { focus: string | null; onFocus: (id: string | null) => void }) {
  const { ws } = useSentinel();
  const [q, setQ] = useState("");
  const list = useMemo(() => {
    const alertsPer = new Map<string, number>();
    for (const a of ws.alerts) for (const id of a.entityIds) alertsPer.set(id, (alertsPer.get(id) ?? 0) + 1);
    const s = q.trim().toLowerCase();
    return Object.values(ws.entities)
      .filter(e => !s || e.name.toLowerCase().includes(s))
      .map(e => ({ e, alerts: alertsPer.get(e.id) ?? 0 }))
      .sort((a, b) => b.alerts - a.alerts || a.e.name.localeCompare(b.e.name))
      .slice(0, 50);
  }, [ws, q]);
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
        <div className="st-page-scroll" style={{ padding: "4px 16px 16px" }}>
          <label className="st-search" style={{ maxWidth: 420 }}><Search size={14} aria-hidden /><span className="st-sr">Search entities</span>
            <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search for an account, a host, an IP or any entity" />
          </label>
          {list.length === 0 && <Empty icon={<Fingerprint size={28} aria-hidden />} title={Object.keys(ws.entities).length ? "No entity matches" : "No entities yet"} />}
          {list.length > 0 && (
            <table className="st-table" aria-label="Entities" style={{ marginTop: 10, maxWidth: 760 }}>
              <thead><tr><th scope="col">Name</th><th scope="col" style={{ width: 160 }}>Type</th><th scope="col" style={{ width: 80 }}>Alerts</th></tr></thead>
              <tbody>
                {list.map(({ e, alerts }) => (
                  <tr key={e.id} tabIndex={0} onClick={() => onFocus(e.id)} onKeyDown={rowKeys(() => onFocus(e.id))}>
                    <td title={e.name}><span className="st-row"><EntityIcon kind={e.kind} size={12} /><span className="st-ellipsis">{e.name}</span></span></td>
                    <td>{KIND_LABEL[e.kind]}</td><td>{alerts}</td>
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

/* ---------------------------------------- threat intelligence ------------------------------------- */

export function ThreatIntelPage() {
  const { ws, states, openIncident } = useSentinel();
  const list = useMemo(() => tiIndicators(states), [states]);
  return (
    <div className="st-page">
      {list.length === 0
        ? <Empty icon={<ShieldCheck size={28} aria-hidden />} title="No indicators yet">Choose Add to TI on an IP, domain, URL or file entity of an incident.</Empty>
        : (
          <div className="st-page-scroll" style={{ padding: "0 16px 16px" }}>
            <table className="st-table" aria-label="Threat indicators" style={{ minWidth: 640 }}>
              <thead><tr><th scope="col">Name</th><th scope="col" style={{ width: 130 }}>Type</th><th scope="col" style={{ width: 130 }}>Added by</th><th scope="col" style={{ width: 170 }}>Created time</th><th scope="col" style={{ width: 100 }}>Incident</th></tr></thead>
              <tbody>
                {list.map(i => {
                  const inc = ws.incidents.find(x => x.id === i.incidentId);
                  return (
                    <tr key={i.id}>
                      <td title={i.name}><span className="st-row"><EntityIcon kind={i.kind} size={12} /><span className="st-ellipsis">{i.name}</span></span></td>
                      <td>{KIND_LABEL[i.kind]}</td><td>{i.addedBy}</td><td>{fmtDateTime(i.at)}</td>
                      <td>{inc ? <button type="button" className="st-link" onClick={() => openIncident(inc.id)}>{inc.number}</button> : "-"}</td>
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

/* --------------------------------------------- analytics ------------------------------------------ */

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
      <div className="st-kpis"><div className="st-kpi"><b>{ws.rules.length}</b><span>Active rules</span></div><div className="st-kpi"><b>{fmtCount(ws.alerts.length)}</b><span>Alerts raised</span></div></div>
      <div style={{ padding: "0 16px 6px" }}><Tabs label="Analytics" value="active" onChange={() => undefined} tabs={[{ value: "active", label: "Active rules" }]} /></div>
      <div className="st-split">
        <div className="st-split-main">
          <div className="st-filters">
            <label className="st-search" style={{ width: 280 }}><Search size={14} aria-hidden /><span className="st-sr">Search rules</span>
              <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search by name or tactic" />
            </label>
          </div>
          <div className="st-page-scroll">
            <table className="st-table" aria-label="Active rules" style={{ minWidth: 820 }}>
              <thead><tr>
                <SortTh k="severity" sort={sort} onSort={setSort} style={{ width: 110 }}>Severity</SortTh>
                <SortTh k="name" sort={sort} onSort={setSort} style={{ width: "38%" }}>Name</SortTh>
                <th scope="col" style={{ width: 90 }}>Rule type</th><th scope="col" style={{ width: 80 }}>Status</th><th scope="col">Tactics</th><th scope="col" style={{ width: 120 }}>Techniques</th>
                <SortTh k="alerts" sort={sort} onSort={setSort} style={{ width: 70 }}>Alerts</SortTh>
              </tr></thead>
              <tbody>
                {shown.map(r => (
                  <tr key={r.id} tabIndex={0} className={r.id === selected ? "selected" : undefined} aria-current={r.id === selected ? "true" : undefined} onClick={() => setSelected(r.id)} onKeyDown={rowKeys(() => setSelected(r.id))}>
                    <td><Severity value={r.severity} /></td><td title={r.name}>{r.name}</td><td>Scheduled</td><td>Enabled</td>
                    <td title={r.tactics.join(", ")}>{r.tactics.join(", ")}</td><td title={r.techniques.join(", ")}>{r.techniques.join(", ")}</td><td>{alertCount.get(r.id) ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {shown.length === 0 && <Empty title="No rule matches" />}
          </div>
        </div>
        {sel && (
          <aside className="st-preview" aria-label="Rule details">
            <div className="st-preview-head"><div className="st-grow"><Severity value={sel.severity} /><h2 style={{ marginTop: 6 }}>{sel.name}</h2></div><button type="button" className="st-icon-btn" aria-label="Close rule details" onClick={() => setSelected(null)}><X size={16} aria-hidden /></button></div>
            <div className="st-preview-body">
              <div className="st-field" style={{ marginTop: 0 }}><div className="k">Description</div><div className="v">{sel.description}</div></div>
              <div className="st-field"><div className="k">Tactics</div><div className="v">{sel.tactics.join(", ") || "--"}</div></div>
              <div className="st-field"><div className="k">Techniques</div><div className="v">{sel.techniques.join(", ") || "--"}</div></div>
              <div className="st-2col st-field"><div><div className="st-k">Run query every</div>{sel.frequency}</div><div><div className="st-k">Lookup data from the last</div>{sel.lookback}</div></div>
              <div className="st-field"><div className="k">Data sources</div><div className="v">{sel.dataSources.join(", ") || "--"}</div></div>
              {sel.falsePositives.length > 0 && <div className="st-field"><div className="k">Known false positives</div><ul style={{ listStyle: "disc", paddingLeft: 18 }}>{sel.falsePositives.map(f => <li key={f}>{f}</li>)}</ul></div>}
              <div className="st-field"><div className="k">Rule query</div><Pre text={sel.query} /></div>
            </div>
            <div className="st-preview-foot"><button type="button" className="st-btn primary" onClick={() => openLogs({ query: sel.query, run: true })}>Open in Logs</button></div>
          </aside>
        )}
      </div>
    </div>
  );
}

/* --------------------------------------------- automation ----------------------------------------- */

export function AutomationPage() {
  const { ws, actions, runPlaybook, runs, ended } = useSentinel();
  const hosts = useMemo(() => [...new Set(Object.values(ws.entities).filter(e => e.kind === "host").map(e => e.name))].sort((a, b) => a.localeCompare(b)), [ws.entities]);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const host = target || hosts[0] || "";
  const last = runs[0];
  const run = async (name: "Isolate device" | "Release device") => {
    setBusy(true);
    await runPlaybook(name, host);
    setBusy(false);
  };
  return (
    <div className="st-page">
      <div className="st-page-scroll" style={{ padding: "0 16px 16px" }}>
        <div style={{ marginBottom: 6 }}><Tabs label="Automation" value="playbooks" onChange={() => undefined} tabs={[{ value: "playbooks", label: "Active playbooks" }]} /></div>
        {hosts.length === 0
          ? <Empty icon={<Workflow size={28} aria-hidden />} title="No device to act on yet">Playbooks here act on devices. Devices appear once they are seen in the logs.</Empty>
          : (
            <>
              <label className="st-row" style={{ margin: "8px 0", maxWidth: 420 }}>
                <span style={{ flex: "none", fontWeight: 600, fontSize: 12 }}>Device</span>
                <select className="st-input" value={host} onChange={e => setTarget(e.target.value)}>{hosts.map(h => <option key={h} value={h}>{h}</option>)}</select>
                <span className="st-small st-muted" style={{ flex: "none" }}>{hostIsolated(actions.isolatedHosts, host) ? "Isolated" : "Not isolated"}</span>
              </label>
              {last && <div style={{ margin: "8px 0", maxWidth: 720 }}><RunResult run={last} /></div>}
              <table className="st-table" aria-label="Playbooks" style={{ maxWidth: 900 }}>
                <thead><tr><th scope="col" style={{ width: 170 }}>Name</th><th scope="col">Description</th><th scope="col" style={{ width: 80 }}>Status</th><th scope="col" style={{ width: 150 }}>Trigger kind</th><th scope="col" style={{ width: 90 }}><span className="st-sr">Run</span></th></tr></thead>
                <tbody>
                  {PLAYBOOKS.map(p => (
                    <tr key={p.name}>
                      <td><strong>{p.name}</strong></td><td title={p.description}>{p.description}</td><td>Enabled</td><td>Entity</td>
                      <td><button type="button" className="st-btn" disabled={ended || busy || !host} onClick={() => void run(p.name)}><Play size={12} aria-hidden />Run</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        {runs.length > 0 && (
          <div style={{ marginTop: 18 }}>
            <h3 style={{ fontSize: 13, marginBottom: 4 }}>Runs in this session</h3>
            <table className="st-table" aria-label="Playbook runs" style={{ maxWidth: 900 }}>
              <thead><tr><th scope="col" style={{ width: 170 }}>Time</th><th scope="col" style={{ width: 130 }}>Playbook</th><th scope="col" style={{ width: 150 }}>Device</th><th scope="col" style={{ width: 90 }}>Result</th><th scope="col">Details</th></tr></thead>
              <tbody>
                {runs.map(r => <tr key={r.id}><td>{fmtDateTime(r.at)}</td><td>{r.playbook}</td><td>{r.host}</td><td>{r.ok ? "Succeeded" : "Refused"}</td><td title={r.message}>{r.message}</td></tr>)}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
