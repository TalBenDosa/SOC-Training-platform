"use client";
import { memo, useMemo, useState } from "react";
import { ChevronsLeft, FileCode2, Play, Search, Table2 } from "lucide-react";
import type { KqlColumn, KqlTable } from "@/lib/kql/types";
import { useSentinel } from "./context";
import { Select, Tabs } from "./ui";

export type SchemaTab = "tables" | "queries";
const GROUPS = [{ value: "solution", label: "Solution" }, { value: "none", label: "None" }] as const;
type GroupBy = (typeof GROUPS)[number]["value"];

/** The filled triangle the schema tree uses. */
const Caret = ({ open }: { open: boolean }) => <i className={`st-caret${open ? " open" : ""}`} aria-hidden />;

const TYPE_GLYPH: Record<KqlColumn["type"], string> = { string: "t", int: "#", long: "#", real: "#", bool: "b", datetime: "d", timespan: "s", dynamic: "{}", guid: "g" };

function groupOf(name: string): string {
  if (/^(SecurityAlert|SecurityIncident|ThreatIntelligenceIndicator|ThreatIntelIndicators|HuntingBookmark|BehaviorAnalytics|IdentityInfo|Anomalies|Watchlist|SentinelHealth|SentinelAudit)$/.test(name)) return "XDR";
  if (/^(Device|Email|Cloud|Identity(Logon|Directory|Query)|Alert(Info|Evidence)|UrlClick)/.test(name)) return "Microsoft Defender XDR";
  return "Log management";
}

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
      <div className="st-schema-row">
        <button type="button" className="st-row" style={{ gap: 4, flex: "1 1 auto", minWidth: 0 }} aria-expanded={showColumns} aria-label={`${table.name}, table, ${table.rows.length} rows. Press Enter to insert, Space to expand.`}
          title="Click to expand, double-click to insert" onClick={() => setOpen(o => !o)} {...activates(() => onInsert(table.name))}>
          <Caret open={showColumns} />
          <Table2 size={13} aria-hidden color="#605e5c" />
          <span className="st-ellipsis">{table.name}</span>
        </button>
        <span className="actions">
          <button type="button" className="st-link st-small" style={{ marginRight: 8 }} onClick={() => onInsert(table.name)}>Use in editor</button>
          <button type="button" className="st-icon-btn" style={{ width: 20, height: 20 }} aria-label={`Run ${table.name}`} title="Run" onClick={() => onPreview(table.name)}><Play size={12} aria-hidden /></button>
        </span>
      </div>
      {showColumns && (
        <ul>
          {columns.map(c => (
            <li key={c.name}>
              <button type="button" className="st-schema-col" title="Double-click to insert" aria-label={`${c.name}, ${c.type}. Press Enter to insert.`} {...activates(() => onInsert(c.name))}>
                <span className="st-typeglyph" aria-hidden>{TYPE_GLYPH[c.type]}</span>
                <span className="st-ellipsis">{c.name} ({c.type})</span>
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
  const [groupBy, setGroupBy] = useState<GroupBy>("solution");
  const [q, setQ] = useState("");
  const [closed, setClosed] = useState<Set<string>>(() => new Set());
  const [showEmpty, setShowEmpty] = useState(false);
  const s = q.trim().toLowerCase();

  const groups = useMemo(() => {
    const map = new Map<string, KqlTable[]>();
    for (const t of Object.values(tables)) {
      if (!showEmpty && !t.rows.length) continue;
      if (s && !t.name.toLowerCase().includes(s) && !t.columns.some(c => c.name.toLowerCase().includes(s))) continue;
      const g = groupBy === "solution" ? groupOf(t.name) : "Tables";
      map.set(g, [...(map.get(g) ?? []), t]);
    }
    return [...map].sort((a, b) => a[0].localeCompare(b[0])).map(([name, list]) => ({ name, list: list.sort((x, y) => x.name.localeCompare(y.name)) }));
  }, [tables, s, showEmpty, groupBy]);
  const emptyCount = useMemo(() => Object.values(tables).filter(t => !t.rows.length).length, [tables]);

  const queryGroups = useMemo(() => {
    const match = (name: string, text: string) => !s || name.toLowerCase().includes(s) || text.toLowerCase().includes(s);
    return [
      { name: "Hunting queries", list: ws.hunting.filter(h => match(h.name, h.description)).map(h => ({ id: h.id, name: h.name, query: h.query })) },
      { name: "Analytics rules", list: ws.rules.filter(r => match(r.name, r.description)).map(r => ({ id: r.id, name: r.name, query: r.query })) },
    ].filter(g => g.list.length);
  }, [ws.hunting, ws.rules, s]);

  const toggleGroup = (g: string) => setClosed(c => { const n = new Set(c); if (n.has(g)) n.delete(g); else n.add(g); return n; });

  return (
    <aside className="st-schema" aria-label="Schema">
      <div className="st-row" style={{ padding: "2px 8px 0 12px" }}>
        <Tabs label="Schema" value={tab} onChange={onTab} tabs={[{ value: "tables", label: "Tables" }, { value: "queries", label: "Queries" }]} />
        <span className="st-grow" />
        <button type="button" className="st-icon-btn" aria-label="Collapse schema pane" title="Collapse" onClick={onCollapse}><ChevronsLeft size={15} aria-hidden /></button>
      </div>
      <div style={{ padding: "8px 12px 4px" }}>
        <label className="st-search"><Search size={14} aria-hidden /><span className="st-sr">Search {tab}</span>
          <input className="st-input" value={q} onChange={e => setQ(e.target.value)} placeholder="Search" />
        </label>
      </div>
      {tab === "tables" && (
        <div className="st-groupby"><strong>Group by:</strong>
          <Select label="Group by" value={groupBy} options={[...GROUPS]} onChange={setGroupBy} className="st-link">{GROUPS.find(g => g.value === groupBy)?.label}</Select>
        </div>
      )}
      <div className="st-schema-list">
        {tab === "tables" && groups.map(g => (
          <div key={g.name}>
            <button type="button" className="st-schema-group" aria-expanded={!closed.has(g.name)} onClick={() => toggleGroup(g.name)}>
              <Caret open={!closed.has(g.name)} />{g.name}
            </button>
            {!closed.has(g.name) && <ul>{g.list.map(t => <TableNode key={t.name} table={t} onInsert={onInsert} onPreview={onPreview} filter={s} />)}</ul>}
          </div>
        ))}
        {tab === "tables" && groups.length === 0 && <p className="st-muted st-small" style={{ padding: "8px 12px" }}>No table matches.</p>}
        {tab === "tables" && emptyCount > 0 && (
          <button type="button" className="st-link st-small" style={{ padding: "8px 12px" }} onClick={() => setShowEmpty(v => !v)}>
            {showEmpty ? "Hide tables without data" : `Show ${emptyCount} tables without data`}
          </button>
        )}
        {tab === "queries" && queryGroups.map(g => (
          <div key={g.name}>
            <button type="button" className="st-schema-group" aria-expanded={!closed.has(g.name)} onClick={() => toggleGroup(g.name)}>
              <Caret open={!closed.has(g.name)} />{g.name}
            </button>
            {!closed.has(g.name) && (
              <ul>
                {g.list.map(item => (
                  <li key={item.id}>
                    <div className="st-schema-row">
                      <button type="button" className="st-row" style={{ gap: 6, flex: "1 1 auto", minWidth: 0 }} title="Double-click to load to editor"
                        aria-label={`${item.name}. Press Enter to load to editor.`} {...activates(() => onLoad(item.query))}>
                        <FileCode2 size={13} aria-hidden color="#605e5c" /><span className="st-ellipsis">{item.name}</span>
                      </button>
                      <span className="actions"><button type="button" className="st-link st-small" onClick={() => onLoad(item.query)}>Load to editor</button></span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
        {tab === "queries" && queryGroups.length === 0 && <p className="st-muted st-small" style={{ padding: "8px 12px" }}>No query matches.</p>}
      </div>
    </aside>
  );
}
