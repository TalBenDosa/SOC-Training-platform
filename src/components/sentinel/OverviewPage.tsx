"use client";
import { useMemo } from "react";
import { useSentinel } from "./context";
import { fmtCount, fmtDateTime, SEVERITIES, STATUSES } from "./helpers";
import { ChartView } from "./ChartView";
import { Empty, Severity, StatusIcon } from "./ui";
import { BarChart2 } from "lucide-react";
import type { KqlColumn, KqlRow } from "@/lib/kql/types";

const BUCKETS = 24;

interface Series { columns: KqlColumn[]; rows: KqlRow[] }

/** Events and alerts per time bucket, counted from the tables themselves. */
function useTimeSeries(): { events: Series; alerts: Series; totalEvents: number } {
  const { ws } = useSentinel();
  return useMemo(() => {
    const stamps: number[] = [];
    for (const t of Object.values(ws.tables)) {
      if (t.name === "SecurityAlert" || t.name === "SecurityIncident") continue;
      for (const r of t.rows) { const ts = Date.parse(String(r.TimeGenerated ?? "")); if (Number.isFinite(ts)) stamps.push(ts); }
    }
    const alertTimes = ws.alerts.map(a => Date.parse(a.time)).filter(Number.isFinite);
    const all = [...stamps, ...alertTimes];
    const columns: KqlColumn[] = [{ name: "TimeGenerated", type: "datetime" }, { name: "count", type: "long" }];
    if (!all.length) return { events: { columns, rows: [] }, alerts: { columns, rows: [] }, totalEvents: 0 };
    let min = Infinity; let max = -Infinity;
    for (const t of all) { if (t < min) min = t; if (t > max) max = t; }
    const span = Math.max(60_000, max - min);
    const width = span / BUCKETS;
    const bucket = (values: number[]) => {
      const c = new Array(BUCKETS + 1).fill(0) as number[];
      for (const t of values) c[Math.floor((t - min) / width)] += 1;
      return c.map((n, i) => ({ TimeGenerated: new Date(min + i * width).toISOString(), count: n }));
    };
    return { events: { columns, rows: bucket(stamps) }, alerts: { columns, rows: bucket(alertTimes) }, totalEvents: stamps.length };
  }, [ws]);
}

export function OverviewPage() {
  const { ws, stateOf, openIncident, go } = useSentinel();
  const { events, alerts, totalEvents } = useTimeSeries();
  const states = useMemo(() => ws.incidents.map(i => stateOf(i.id)), [ws.incidents, stateOf]);
  const byStatus = useMemo(() => Object.fromEntries(STATUSES.map(s => [s, states.filter(x => x.status === s).length])) as Record<string, number>, [states]);
  const bySeverity = useMemo(() => SEVERITIES.map(s => ({ s, n: states.filter(x => x.status !== "Closed" && x.severity === s).length })), [states]);
  const recent = useMemo(() => [...ws.incidents].sort((a, b) => Date.parse(b.lastUpdate) - Date.parse(a.lastUpdate)).slice(0, 6), [ws.incidents]);
  const maxStatus = Math.max(1, ...STATUSES.map(s => byStatus[s]));

  return (
    <div className="st-page">
      <div className="st-page-scroll">
        <div className="st-ov">
          <div className="st-ov-top">
            <div className="cell"><b>{fmtCount(totalEvents)}</b><span>Events</span></div>
            <div className="cell"><b>{fmtCount(ws.alerts.length)}</b><span>Alerts</span></div>
            <div className="cell"><b>{fmtCount(ws.incidents.length)}</b><span>Incidents</span></div>
            <div className="cell"><b>{fmtCount(byStatus.New + byStatus.Active)}</b><span>Open incidents</span></div>
            <div className="cell"><b>{fmtCount(ws.rules.length)}</b><span>Active rules</span></div>
          </div>
          <section className="st-tile" aria-label="Events and alerts over time">
            <h3>Events and alerts over time</h3>
            {events.rows.length === 0 && alerts.rows.length === 0
              ? <Empty icon={<BarChart2 size={28} aria-hidden />} title="No events yet" />
              : (
                <>
                  <div className="st-small st-muted">Events</div>
                  <div style={{ height: 170, display: "flex" }}><ChartView compact columns={events.columns} rows={events.rows} initial="timechart" /></div>
                  <div className="st-small st-muted" style={{ marginTop: 6 }}>Alerts</div>
                  <div style={{ height: 150, display: "flex" }}><ChartView compact columns={alerts.columns} rows={alerts.rows} initial="timechart" /></div>
                </>
              )}
          </section>
          <div className="st-stack" style={{ gap: 12 }}>
            <section className="st-tile" aria-label="Incidents by status">
              <h3>Incidents by status</h3>
              {STATUSES.map(s => (
                <div key={s} className="st-statusbar-row">
                  <span className="st-row" style={{ gap: 4 }}><StatusIcon status={s} size={12} />{s}</span>
                  <span className="st-sevbar-track"><span className="st-sevbar-fill" style={{ display: "block", background: "var(--st-accent)", width: `${(byStatus[s] / maxStatus) * 100}%` }} /></span>
                  <span>{byStatus[s]}</span>
                </div>
              ))}
              <div className="st-row" style={{ flexWrap: "wrap", gap: "4px 14px", marginTop: 8 }}>
                {bySeverity.map(({ s, n }) => <span key={s} className="st-small"><Severity value={s} /> {n}</span>)}
              </div>
            </section>
            <section className="st-tile" aria-label="Recent incidents" style={{ flex: "1 1 auto" }}>
              <h3>Recent incidents</h3>
              {recent.length === 0 && <p className="st-muted st-small">No incidents yet.</p>}
              <ul>
                {recent.map(i => {
                  const st = stateOf(i.id);
                  return (
                    <li key={i.id} className="st-entity-row">
                      <i className={`st-band ${st.severity}`} style={{ height: 30 }} aria-hidden />
                      <button type="button" className="st-grow" onClick={() => openIncident(i.id)} title={i.title}>
                        <span className="st-link st-ellipsis" style={{ display: "block" }}>{i.title}</span>
                        <span className="st-small st-muted">{i.number} | {st.status} | {fmtDateTime(i.lastUpdate)}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              {recent.length > 0 && <button type="button" className="st-link st-small" style={{ marginTop: 6 }} onClick={() => go("incidents")}>View all incidents &gt;</button>}
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
