"use client";
// Info, Timeline and Insights of an entity: incident Entities tab, Entity behavior page, graph rail.
import { memo, useMemo, useState } from "react";
import { Activity, Bookmark, ChevronDown, ChevronRight, Clock, Lightbulb, ShieldAlert } from "lucide-react";
import type { EntityInsight, SentinelEntity, SentinelIncident } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { insightsForEntity } from "./engine";
import { entityActivity, fmtClock, fmtCount, fmtDateTime, fmtMonthDay, kqlString } from "./helpers";
import { Empty } from "./ui";

export function InsightCard({ insight, range, defaultOpen = true }: { insight: EntityInsight; range?: string; defaultOpen?: boolean }) {
  const { openLogs } = useSentinel();
  const [open, setOpen] = useState(defaultOpen);
  const { columns, rows } = insight.preview;
  return (
    <section className="st-insight">
      <button type="button" className="st-insight-head" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        {open ? <ChevronDown size={13} color="#0078d4" aria-hidden /> : <ChevronRight size={13} color="#0078d4" aria-hidden />}
        <span className="st-ellipsis">{insight.title}</span>
      </button>
      {open && (
        <>
          {range && <div className="st-small st-muted" style={{ marginTop: 2 }}>{range}</div>}
          <p className="st-small st-muted" style={{ marginTop: 2 }}>{insight.description}</p>
          {rows.length > 0 && (
            <table className="st-mini">
              <thead><tr>{columns.map(c => <th key={c} scope="col" title={c}>{c}</th>)}</tr></thead>
              <tbody>{rows.slice(0, 5).map((r, i) => <tr key={i}>{r.map((v, j) => <td key={j} title={v}>{v}</td>)}</tr>)}</tbody>
            </table>
          )}
          <button type="button" className="st-link st-small" style={{ marginTop: 6 }} onClick={() => openLogs({ query: insight.query, run: true })}>See results &gt;</button>
        </>
      )}
    </section>
  );
}

export const EntityInfoCard = memo(function EntityInfoCard({ entity }: { entity: SentinelEntity }) {
  const { ws, openLogs } = useSentinel();
  const activity = useMemo(() => entityActivity(entity, ws), [entity, ws]);
  const facts = Object.entries(entity.info);
  return (
    <div>
      <h4 style={{ fontSize: 14, marginBottom: 6 }}>Information</h4>
      {facts.length === 0 && <p className="st-muted st-small">No identifying facts recorded.</p>}
      <div className="st-2col" style={{ gap: "8px 12px" }}>
        {facts.map(([k, v]) => <div key={k} style={{ minWidth: 0 }}><div className="st-k">{k}</div><div style={{ wordBreak: "break-word" }}>{/^\d{4}-\d{2}-\d{2}T/.test(v) ? fmtDateTime(v) : v || "-"}</div></div>)}
      </div>
      <hr style={{ border: 0, borderTop: "1px solid var(--st-border)", margin: "12px 0" }} />
      <h4 style={{ fontSize: 14, marginBottom: 6 }}>Log Activity</h4>
      <div className="st-2col" style={{ gap: "8px 12px" }}>
        <div><div className="st-k">First Seen</div>{fmtDateTime(activity.firstSeen)}</div>
        <div><div className="st-k">Last Seen</div>{fmtDateTime(activity.lastSeen)}</div>
      </div>
      <div className="st-k" style={{ marginTop: 8 }}>Data Sources</div>
      {activity.tables.length === 0 && <div>-</div>}
      <ul>
        {activity.tables.slice(0, 8).map(t => (
          <li key={t.name} className="st-row" style={{ justifyContent: "space-between" }}>
            <button type="button" className="st-link" onClick={() => openLogs({ query: `${t.name}\n| search ${kqlString(entity.name)}`, run: true })}>{t.name}</button>
            <span className="st-muted st-small">{fmtCount(t.count)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
});

interface TimelineRow { key: string; at: string; title: string; sub: string; icon: "alert" | "foreign" | "bookmark" | "activity"; sev?: string; query: string }

export const EntityTimelineCard = memo(function EntityTimelineCard({ entity, incident }: { entity: SentinelEntity; incident?: SentinelIncident }) {
  const { ws, bookmarks, openLogs } = useSentinel();
  const rows = useMemo(() => {
    const inIncident = new Set(incident?.alertIds ?? []);
    const out: TimelineRow[] = [];
    for (const a of ws.alerts) {
      if (!a.entityIds.includes(entity.id)) continue;
      out.push({ key: a.id, at: a.time, title: a.name, sub: `${a.severity} | ${a.product}`, icon: !incident || inIncident.has(a.id) ? "alert" : "foreign", sev: a.severity, query: a.query });
    }
    for (const b of bookmarks) {
      if (b.entityIds.includes(entity.id)) out.push({ key: b.id, at: b.at, title: b.name, sub: `Bookmark by ${b.author}`, icon: "bookmark", query: b.query });
    }
    for (const [i, r] of entityActivity(entity, ws).recent.entries()) {
      out.push({ key: `activity-${i}`, at: r.time, title: r.text, sub: r.table, icon: "activity", query: `${r.table}\n| where TimeGenerated == datetime(${new Date(r.time).toISOString()})\n| search ${kqlString(entity.name)}` });
    }
    return out.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
  }, [ws, entity, incident, bookmarks]);
  if (!rows.length) return <Empty icon={<Clock size={22} aria-hidden />} title="No activity in this time frame" />;
  return (
    <ul className="st-tl">
      {rows.map(r => (
        <li key={r.key}>
          <button type="button" className="st-tl-item" style={{ gridTemplateColumns: "50px 24px 1fr" }} title={r.title} onClick={() => openLogs({ query: r.query, run: true })}>
            <span className="st-tl-date">{fmtMonthDay(r.at)}<br />{fmtClock(r.at)}</span>
            <span className="st-tl-rail"><span className="st-tl-dot" style={r.icon === "foreign" ? { color: "#a19f9d" } : undefined}>
              {r.icon === "bookmark" ? <Bookmark size={12} aria-hidden /> : r.icon === "activity" ? <Activity size={12} aria-hidden /> : <ShieldAlert size={12} aria-hidden />}
            </span></span>
            <span className="st-tl-main">
              {r.sev && <i className={`st-band ${r.sev}${r.icon === "foreign" ? " dotted" : ""}`} aria-hidden />}
              <span style={{ minWidth: 0 }}>
                <span className="st-tl-title st-ellipsis" style={{ display: "block", fontWeight: r.icon === "activity" ? 400 : 600 }}>{r.title}</span>
                <span className="st-small st-muted st-ellipsis" style={{ display: "block" }}>{r.sub}</span>
              </span>
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
});

export const EntityInsightsCard = memo(function EntityInsightsCard({ entity }: { entity: SentinelEntity }) {
  const { ws } = useSentinel();
  const insights = useMemo(() => insightsForEntity(entity, ws), [entity, ws]);
  if (!insights.length) return <Empty icon={<Lightbulb size={22} aria-hidden />} title="No insights for this entity" />;
  return <>{insights.map(i => <InsightCard key={i.title} insight={i} />)}</>;
});
