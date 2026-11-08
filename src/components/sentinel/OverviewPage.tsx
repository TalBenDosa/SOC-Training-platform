"use client";
// Workspace home (owner, 2026-11-08: XDR's own home, not the portal's overview blade): stat cards
// with an icon each, quick ways in, the activity chart, the incidents that need attention as cards,
// and the status mix as one segmented bar.
import { useMemo } from "react";
import { ArrowRight, BarChart2, Bell, ChartSpline, Radar, Rows3, ScrollText, Siren, TriangleAlert } from "lucide-react";
import { useSentinel } from "./context";
import { fmtCount, fmtDateTime, SEVERITIES, STATUSES } from "./helpers";
import { ChartView } from "./ChartView";
import { Empty, StatusIcon } from "./ui";
import { SevChip } from "./XdrParts";
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

const STATUS_TONE: Record<string, string> = { New: "var(--st-accent)", Active: "#c4b5fd", Closed: "#8fbf8f" };

export function OverviewPage() {
  const { ws, stateOf, openIncident, go } = useSentinel();
  const { events, alerts, totalEvents } = useTimeSeries();
  const states = useMemo(() => ws.incidents.map(i => stateOf(i.id)), [ws.incidents, stateOf]);
  const byStatus = useMemo(() => Object.fromEntries(STATUSES.map(s => [s, states.filter(x => x.status === s).length])) as Record<string, number>, [states]);
  const bySeverity = useMemo(() => SEVERITIES.map(s => ({ s, n: states.filter(x => x.status !== "Closed" && x.severity === s).length })), [states]);
  // Needs attention: open incidents, highest severity first, then the latest update.
  const attention = useMemo(() => [...ws.incidents]
    .map(i => ({ i, st: stateOf(i.id) }))
    .filter(x => x.st.status !== "Closed")
    .sort((a, b) => SEVERITIES.indexOf(a.st.severity) - SEVERITIES.indexOf(b.st.severity) || Date.parse(b.i.lastUpdate) - Date.parse(a.i.lastUpdate))
    .slice(0, 5), [ws.incidents, stateOf]);
  const totalStatus = Math.max(1, STATUSES.reduce((n, s) => n + byStatus[s], 0));
  const open = byStatus.New + byStatus.Active;

  const stats = [
    { k: "Events", v: fmtCount(totalEvents), Icon: Rows3 },
    { k: "Alerts", v: fmtCount(ws.alerts.length), Icon: Bell },
    { k: "Incidents", v: fmtCount(ws.incidents.length), Icon: Siren },
    { k: "Open incidents", v: fmtCount(open), Icon: TriangleAlert },
    { k: "Detection rules", v: fmtCount(ws.rules.length), Icon: ChartSpline },
  ];
  const jumps = [
    { label: "Work the incident queue", Icon: Siren, to: "incidents" as const },
    { label: "Write a KQL query", Icon: ScrollText, to: "logs" as const },
    { label: "Run the hunts", Icon: Radar, to: "hunting" as const },
  ];

  return (
    <div className="st-page">
      <div className="st-page-scroll">
        <div className="xd-home">
          <ul className="xd-home-stats" aria-label="Workspace at a glance">
            {stats.map(({ k, v, Icon }) => (
              <li key={k} className="xd-stat"><span className="xd-kpi-ico" aria-hidden><Icon size={15} /></span><span className="k">{k}</span><b>{v}</b></li>
            ))}
          </ul>
          <nav className="xd-jumps" aria-label="Quick ways in">
            {jumps.map(({ label, Icon, to }) => (
              <button key={to} type="button" className="xd-jump" onClick={() => go(to)}><Icon size={15} aria-hidden /><span className="st-grow">{label}</span><ArrowRight size={14} aria-hidden /></button>
            ))}
          </nav>
          <section className="xd-card xd-home-chart" aria-label="Activity over time">
            <h3 className="xd-card-title">Activity over time</h3>
            {events.rows.length === 0 && alerts.rows.length === 0
              ? <Empty icon={<BarChart2 size={28} aria-hidden />} title="No events yet" />
              : (
                <>
                  <div className="xd-eyebrow">Events</div>
                  <div style={{ height: 160, display: "flex" }}><ChartView compact columns={events.columns} rows={events.rows} initial="timechart" /></div>
                  <div className="xd-eyebrow" style={{ marginTop: 8 }}>Alerts</div>
                  <div style={{ height: 140, display: "flex" }}><ChartView compact columns={alerts.columns} rows={alerts.rows} initial="timechart" /></div>
                </>
              )}
          </section>
          <div className="xd-home-side">
            <section className="xd-card" aria-label="Needs attention">
              <h3 className="xd-card-title">Needs attention <span className="xd-count">{open}</span></h3>
              {attention.length === 0 && <p className="st-muted st-small">Nothing open. New incidents show here first.</p>}
              <ul className="xd-attn">
                {attention.map(({ i, st }) => (
                  <li key={i.id}>
                    <button type="button" className={`xd-attn-card ${st.severity}`} onClick={() => openIncident(i.id)} title={i.title}>
                      <span className="xd-attn-top"><SevChip value={st.severity} /><span className="xd-attn-id">#{i.number}</span><span className="st-grow" /><span className={`xd-status ${st.status}`}><StatusIcon status={st.status} size={12} />{st.status}</span></span>
                      <span className="xd-attn-title st-ellipsis">{i.title}</span>
                      <span className="st-small st-muted">Updated {fmtDateTime(i.lastUpdate)}</span>
                    </button>
                  </li>
                ))}
              </ul>
              {ws.incidents.length > 0 && <button type="button" className="st-link st-small" style={{ marginTop: 8 }} onClick={() => go("incidents")}>Open the incident queue</button>}
            </section>
            <section className="xd-card" aria-label="Incidents by status">
              <h3 className="xd-card-title">Incidents by status</h3>
              <div className="xd-mixbar" aria-hidden>
                {STATUSES.map(s => byStatus[s] > 0 && <i key={s} style={{ flexGrow: byStatus[s] / totalStatus, background: STATUS_TONE[s] }} />)}
              </div>
              <ul className="xd-mixlegend">
                {STATUSES.map(s => <li key={s}><span className="st-row" style={{ gap: 5 }}><StatusIcon status={s} size={12} />{s}</span><b>{byStatus[s]}</b></li>)}
              </ul>
              <div className="xd-eyebrow" style={{ marginTop: 10 }}>Open by severity</div>
              <ul className="xd-mixlegend">
                {bySeverity.map(({ s, n }) => <li key={s}><span className="st-row" style={{ gap: 6 }}><i className={`xd-dot ${s}`} aria-hidden />{s}</span><b>{n}</b></li>)}
              </ul>
            </section>
          </div>
        </div>
      </div>
    </div>
  );
}
