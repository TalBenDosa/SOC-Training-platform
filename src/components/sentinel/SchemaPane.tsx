"use client";
// The Query lab's side pane (owner, 2026-11-08: XDR's own, not the portal's "Tables" tree): Data
// sources grouped by where the data comes from, each with an icon and its table count, every table
// with its row count; and Saved queries. Table and column names stay exact: they are KQL identifiers.
import { memo, useMemo, useState } from "react";
import {
  ChevronDown, ChevronRight, ChevronsLeft, Cloud, Database, FileCode2, Laptop, Mail, Network, Play, Search, ShieldAlert, UserRound, type LucideIcon,
} from "lucide-react";
import type { KqlColumn, KqlTable } from "@/lib/kql/types";
import { useSentinel } from "./context";
import { fmtCompact } from "./helpers";
import { Tabs } from "./ui";

export type SchemaTab = "tables" | "queries";
type Arrange = "source" | "az";

/** A column's type as a short badge. */
const TYPE_BADGE: Record<KqlColumn["type"], string> = { string: "str", int: "int", long: "long", real: "real", bool: "bool", datetime: "date", timespan: "span", dynamic: "dyn", guid: "guid" };

/** Where a table's data comes from, in the order the pane lists them. */
const SOURCES: { name: string; icon: LucideIcon; test: RegExp }[] = [
  { name: "Alerts and incidents", icon: ShieldAlert, test: /^(SecurityAlert|SecurityIncident|AlertInfo|AlertEvidence|GraphSecurityAlerts_CL|HuntingBookmark|ThreatIntelligenceIndicator|ThreatIntelIndicators|BehaviorAnalytics|Anomalies|Watchlist|SentinelHealth|SentinelAudit|ThinkstCanary\w*)$/ },
  { name: "Endpoints", icon: Laptop, test: /^(Device\w*|ASim(Process|File|Registry)EventLogs|SecurityEvent|Event|SentinelOne\w*|Sophos\w*)$/ },
  { name: "Identity", icon: UserRound, test: /^(SigninLogs|AuditLogs|IdentityInfo|Identity(Logon|Directory|Query)Events|AADNonInteractiveUserSignInLogs|Okta\w*)$/ },
  { name: "Email and collaboration", icon: Mail, test: /^(Email\w*|UrlClickEvents|OfficeActivity|GoogleWorkspaceReports)$/ },
  { name: "Network", icon: Network, test: /^(CommonSecurityLog|Syslog|DnsEvents|ASim(NetworkSession|DnsActivity)Logs|AWSVPCFlow|ZPA_CL)$/ },
  { name: "Cloud", icon: Cloud, test: /^(AzureActivity|AWS\w*|GCP\w*|AKSAudit|GitHub\w*|BV_\w*)$/ },
];
const OTHER = { name: "Other sources", icon: Database };
export const sourceOf = (table: string) => SOURCES.find(s => s.test.test(table)) ?? OTHER;

/** A pair of double-click and Enter, so inserting works by mouse and by keyboard alike. */
const activates = (fn: () => void) => ({
  onDoubleClick: fn,
  onKeyDown: (e: React.KeyboardEvent) => { if (e.key === "Enter") { e.preventDefault(); e.stopPropagation(); fn(); } },
});

const TableNode = memo(function TableNode({ table, onInsert, onPreview, filter }: { table: KqlTable; onInsert: (s: string) => void; onPreview: (t: string) => void; filter: string }) {
  const [open, setOpen] = useState(false);
  const columns = filter ? table.columns.filter(c => c.name.toLowerCase().includes(filter)) : table.columns;
  const showColumns = open || (filter !== "" && !table.name.toLowerCase().includes(filter));
  return (
    <li>
      <div className="st-schema-row xd-src-row">
        <button type="button" className="st-row" style={{ gap: 6, flex: "1 1 auto", minWidth: 0 }} aria-expanded={showColumns} aria-label={`${table.name}, table, ${table.rows.length} rows. Press Enter to insert, Space to expand.`}
          title="Click to show columns, double-click to insert" onClick={() => setOpen(o => !o)} {...activates(() => onInsert(table.name))}>
          {showColumns ? <ChevronDown size={13} aria-hidden className="xd-chev" /> : <ChevronRight size={13} aria-hidden className="xd-chev" />}
          <span className="st-ellipsis st-mono xd-tname">{table.name}</span>
          <span className="xd-rows" aria-hidden>{table.rows.length ? fmtCompact(table.rows.length) : "empty"}</span>
        </button>
        <span className="actions">
          <button type="button" className="st-link st-small" style={{ marginRight: 6 }} onClick={() => onInsert(table.name)}>Insert</button>
          <button type="button" className="st-icon-btn" style={{ width: 22, height: 22 }} aria-label={`Run ${table.name}`} title="Run" onClick={() => onPreview(table.name)}><Play size={12} aria-hidden /></button>
        </span>
      </div>
      {showColumns && (
        <ul className="xd-cols">
          {columns.map(c => (
            <li key={c.name}>
              <button type="button" className="st-schema-col" title="Double-click to insert" aria-label={`${c.name}, ${c.type}. Press Enter to insert.`} {...activates(() => onInsert(c.name))}>
                <span className="st-ellipsis st-mono">{c.name}</span>
                <span className="xd-typebadge" aria-hidden>{TYPE_BADGE[c.type]}</span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
});

export function SchemaPane({ tab, onTab, onInsert, onLoad, onPreview, onCollapse }: {
  tab: SchemaTab; onTab: (t: SchemaTab) => void; onInsert: (text: string) => void; onLoad: (query: string) => void; onPreview: (table: string) => void; onCollapse: () => void;
}) {
  const { tables, ws } = useSentinel();
  const [arrange, setArrange] = useState<Arrange>("source");
  const [q, setQ] = useState("");
  const [closed, setClosed] = useState<Set<string>>(() => new Set());
  const [showEmpty, setShowEmpty] = useState(false);
  const s = q.trim().toLowerCase();

  const groups = useMemo(() => {
    const map = new Map<string, { icon: LucideIcon; list: KqlTable[]; order: number }>();
    for (const t of Object.values(tables)) {
      if (!showEmpty && !t.rows.length) continue;
      if (s && !t.name.toLowerCase().includes(s) && !t.columns.some(c => c.name.toLowerCase().includes(s))) continue;
      const src = arrange === "source" ? sourceOf(t.name) : { name: "All data sources", icon: Database };
      const order = arrange === "source" ? (SOURCES.findIndex(x => x.name === src.name) + SOURCES.length + 1) % (SOURCES.length + 1) : 0;
      const g = map.get(src.name) ?? { icon: src.icon, list: [], order };
      g.list.push(t);
      map.set(src.name, g);
    }
    return [...map].sort((a, b) => a[1].order - b[1].order || a[0].localeCompare(b[0]))
      .map(([name, g]) => ({ name, icon: g.icon, list: g.list.sort((x, y) => x.name.localeCompare(y.name)) }));
  }, [tables, s, showEmpty, arrange]);
  const emptyCount = useMemo(() => Object.values(tables).filter(t => !t.rows.length).length, [tables]);

  const queryGroups = useMemo(() => {
    const match = (name: string, text: string) => !s || name.toLowerCase().includes(s) || text.toLowerCase().includes(s);
    return [
      { name: "Hunts", list: ws.hunting.filter(h => match(h.name, h.description)).map(h => ({ id: h.id, name: h.name, query: h.query })) },
      { name: "Detection rules", list: ws.rules.filter(r => match(r.name, r.description)).map(r => ({ id: r.id, name: r.name, query: r.query })) },
    ].filter(g => g.list.length);
  }, [ws.hunting, ws.rules, s]);

  const toggleGroup = (g: string) => setClosed(c => { const n = new Set(c); if (n.has(g)) n.delete(g); else n.add(g); return n; });

  return (
    <aside className="st-schema xd-schema" aria-label="Data sources and saved queries">
      <div className="st-row" style={{ padding: "6px 8px 0 12px" }}>
        <Tabs label="Side pane" value={tab} onChange={onTab} className="st-tabs xd-seg" tabClass="st-tab xd-seg-btn" tabs={[{ value: "tables", label: "Data sources" }, { value: "queries", label: "Saved queries" }]} />
        <span className="st-grow" />
        <button type="button" className="st-icon-btn" aria-label="Collapse data sources pane" title="Collapse" onClick={onCollapse}><ChevronsLeft size={15} aria-hidden /></button>
      </div>
      <div style={{ padding: "8px 12px 4px" }}>
        <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">{tab === "tables" ? "Filter data sources and columns" : "Filter saved queries"}</span>
          <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder={tab === "tables" ? "Filter tables and columns" : "Filter queries"} />
        </label>
      </div>
      {tab === "tables" && (
        <div className="xd-arrange">
          <span className="st-small st-muted">Arrange</span>
          <div className="xd-seg mini" role="group" aria-label="Arrange data sources">
            <button type="button" className="xd-seg-btn" aria-pressed={arrange === "source"} onClick={() => setArrange("source")}>By source</button>
            <button type="button" className="xd-seg-btn" aria-pressed={arrange === "az"} onClick={() => setArrange("az")}>A to Z</button>
          </div>
        </div>
      )}
      <div className="st-schema-list">
        {tab === "tables" && groups.map(g => {
          const on = !closed.has(g.name);
          return (
            <div key={g.name} className="xd-src">
              <button type="button" className="st-schema-group xd-src-head" aria-expanded={on} onClick={() => toggleGroup(g.name)}>
                <span className="xd-src-ico" aria-hidden><g.icon size={14} /></span>
                <span className="st-grow st-ellipsis">{g.name}</span>
                <span className="xd-count" aria-label={`${g.list.length} tables`}>{g.list.length}</span>
                {on ? <ChevronDown size={14} aria-hidden className="xd-chev" /> : <ChevronRight size={14} aria-hidden className="xd-chev" />}
              </button>
              {on && <ul>{g.list.map(t => <TableNode key={t.name} table={t} onInsert={onInsert} onPreview={onPreview} filter={s} />)}</ul>}
            </div>
          );
        })}
        {tab === "tables" && groups.length === 0 && <p className="st-muted st-small" style={{ padding: "8px 12px" }}>No table matches.</p>}
        {tab === "tables" && emptyCount > 0 && (
          <button type="button" className="st-link st-small" style={{ padding: "8px 12px" }} onClick={() => setShowEmpty(v => !v)}>
            {showEmpty ? "Hide tables with no rows" : `Show ${emptyCount} tables with no rows yet`}
          </button>
        )}
        {tab === "queries" && queryGroups.map(g => {
          const on = !closed.has(g.name);
          return (
            <div key={g.name} className="xd-src">
              <button type="button" className="st-schema-group xd-src-head" aria-expanded={on} onClick={() => toggleGroup(g.name)}>
                <span className="xd-src-ico" aria-hidden><FileCode2 size={14} /></span>
                <span className="st-grow st-ellipsis">{g.name}</span>
                <span className="xd-count" aria-label={`${g.list.length} queries`}>{g.list.length}</span>
                {on ? <ChevronDown size={14} aria-hidden className="xd-chev" /> : <ChevronRight size={14} aria-hidden className="xd-chev" />}
              </button>
              {on && (
                <ul>
                  {g.list.map(item => (
                    <li key={item.id}>
                      <div className="st-schema-row xd-src-row">
                        <button type="button" className="st-row" style={{ gap: 6, flex: "1 1 auto", minWidth: 0 }} title="Double-click to load to editor"
                          aria-label={`${item.name}. Press Enter to load to editor.`} {...activates(() => onLoad(item.query))}>
                          <span className="st-ellipsis">{item.name}</span>
                        </button>
                        <span className="actions"><button type="button" className="st-link st-small" onClick={() => onLoad(item.query)}>Load to editor</button></span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          );
        })}
        {tab === "queries" && queryGroups.length === 0 && <p className="st-muted st-small" style={{ padding: "8px 12px" }}>No query matches.</p>}
      </div>
    </aside>
  );
}
