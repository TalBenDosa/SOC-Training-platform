"use client";
// Info, Timeline and Insights of an entity: incident Entities tab, Entity behavior page, graph rail.
import { memo, useMemo, useState } from "react";
import { Activity, Bookmark, ChevronDown, ChevronUp, Clock, Lightbulb } from "lucide-react";
import type { EntityInsight, SentinelEntity, SentinelIncident, SentinelSeverity as SentinelAlertSeverity } from "@/lib/sentinel/types";
import { useSentinel } from "./context";
import { insightsForEntity } from "./engine";
import { entityActivity, fmtClock, fmtCount, fmtDateTime, fmtMonthDay, fmtShortTime, kqlString } from "./helpers";
import { Empty, InfoMark } from "./ui";
import { Kv, PaneSection, ProductChip, SevChip } from "./XdrParts";
import { deviceState } from "./IncidentPanes";

/** A device's isolation, in every entity pane (2026-11-07: isolating goes through an approval). */
function DeviceStateLine({ host }: { host: string }) {
  const { actions } = useSentinel();
  const st = deviceState(actions, host);
  return (
    <Kv k="Network state"><span className={`st-devstate${st.isolated ? " isolated" : st.pending ? " pending" : ""}`}>{st.label}</span></Kv>
  );
}

/** What an insight found: its time range, description, a few rows and the way into Query. */
export function InsightResults({ insight, range }: { insight: EntityInsight; range?: string }) {
  const { openLogs } = useSentinel();
  const { columns, rows } = insight.preview;
  return (
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
  );
}

export function InsightCard({ insight, range, defaultOpen = true }: { insight: EntityInsight; range?: string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="st-insight">
      <button type="button" className="st-insight-head" aria-expanded={open} onClick={() => setOpen(o => !o)}>
        {open ? <ChevronUp size={16} color="#6d28d9" aria-hidden /> : <ChevronDown size={16} color="#6d28d9" aria-hidden />}
        <span className="st-ellipsis st-grow">{insight.title}</span>
        <InfoMark title={insight.description} />
      </button>
      {open && <InsightResults insight={insight} range={range} />}
    </section>
  );
}

const HEADING: Partial<Record<SentinelEntity["kind"], string>> = { ip: "Identity and location", account: "Identity", host: "Identity" };

/**
 * What the workspace knows about an entity, in labelled sections: Identity (its facts), Activity
 * (first and last seen, the tables it appears in), Related alerts and, for all but hosts, the hosts it
 * was logged on. XDR's own layout: key-value rows under small section headers.
 */
export const EntityInfoCard = memo(function EntityInfoCard({ entity }: { entity: SentinelEntity }) {
  const { ws, openLogs } = useSentinel();
  const activity = useMemo(() => entityActivity(entity, ws), [entity, ws]);
  const related = useMemo(() => ws.alerts.filter(a => a.entityIds.includes(entity.id)).sort((a, b) => Date.parse(b.time) - Date.parse(a.time)), [ws.alerts, entity.id]);
  const facts = Object.entries(entity.info);
  const top = Math.max(1, ...activity.tables.map(t => t.count));
  return (
    <div className="st-infocard xd-infocard">
      <PaneSection title={HEADING[entity.kind] ?? "Identity"} aside={<InfoMark title="What the workspace knows about this entity." />}>
        {facts.length === 0 && <p className="st-muted st-small">No identifying facts recorded.</p>}
        {facts.map(([k, v]) => <Kv key={k} k={k}>{/^\d{4}-\d{2}-\d{2}T/.test(v) ? fmtDateTime(v) : v || "-"}</Kv>)}
        {entity.kind === "host" && <DeviceStateLine host={entity.name} />}
      </PaneSection>
      <PaneSection title="Activity" aside={<InfoMark title="Where this entity appears in the workspace." />}>
        <Kv k="First seen">{fmtDateTime(activity.firstSeen)}</Kv>
        <Kv k="Last seen">{fmtDateTime(activity.lastSeen)}</Kv>
        <div className="xd-k" style={{ margin: "8px 0 4px" }}>Data sources</div>
        {activity.tables.length === 0 && <div>-</div>}
        <ul className="xd-sources">
          {activity.tables.slice(0, 8).map(t => (
            <li key={t.name}>
              <button type="button" className="st-link st-ellipsis" onClick={() => openLogs({ query: `${t.name}\n| search ${kqlString(entity.name)}`, run: true })}>{t.name}</button>
              <span className="xd-bar" aria-hidden><i style={{ width: `${Math.max(4, (t.count / top) * 100)}%` }} /></span>
              <span className="st-muted st-small xd-num">{fmtCount(t.count)}</span>
            </li>
          ))}
        </ul>
      </PaneSection>
      <PaneSection title={`Related alerts (${related.length})`}>
        {related.length === 0 && <p className="st-muted st-small">No alert names this entity.</p>}
        <ul className="xd-mini-alerts">
          {related.slice(0, 6).map(a => (
            <li key={a.id}>
              <button type="button" className={`xd-alert-card mini ${a.severity}`} onClick={() => openLogs({ query: a.query, run: true })}>
                <span className="xd-ac-top">
                  <span className="xd-ac-title st-ellipsis" title={a.name}>{a.name}</span>
                  <time className="xd-ac-time" dateTime={a.time}>{fmtMonthDay(a.time)}, {fmtClock(a.time)}</time>
                </span>
                <span className="xd-ac-chips"><SevChip value={a.severity} /><ProductChip product={a.product} /></span>
              </button>
            </li>
          ))}
        </ul>
      </PaneSection>
      {entity.kind !== "host" && (
        <PaneSection title="Logged hosts" aside={<InfoMark title="Hosts this entity appears on in the logs." />}>
          <table className="st-mini xd-hosts">
            <thead><tr><th scope="col">Host name</th><th scope="col">First seen</th><th scope="col">Last seen</th></tr></thead>
            <tbody>
              {activity.hosts.length === 0 && <tr><td>-</td><td>-</td><td>-</td></tr>}
              {activity.hosts.slice(0, 8).map(h => (
                <tr key={h.name}><td title={h.name}>{h.name}</td><td>{fmtShortTime(h.first)}</td><td>{fmtShortTime(h.last)}</td></tr>
              ))}
            </tbody>
          </table>
        </PaneSection>
      )}
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
      out.push({ key: a.id, at: a.time, title: a.name, sub: `Detected by ${a.product}`, icon: !incident || inIncident.has(a.id) ? "alert" : "foreign", sev: a.severity, query: a.query });
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
    <ul className="xd-tl">
      {rows.map(r => (
        <li key={r.key} className="xd-tl-item">
          <button type="button" className={`xd-alert-card mini ${r.sev ?? (r.icon === "bookmark" ? "bm" : "act")}${r.icon === "foreign" ? " foreign" : ""}`} title={r.title} onClick={() => openLogs({ query: r.query, run: true })}>
            <span className="xd-ac-top">
              <span className="xd-ac-title st-ellipsis" style={{ fontWeight: r.icon === "activity" ? 400 : 600 }}>{r.title}</span>
              <time className="xd-ac-time" dateTime={r.at}>{fmtMonthDay(r.at)}, {fmtClock(r.at)}</time>
            </span>
            <span className="xd-ac-chips">
              {r.sev ? <SevChip value={r.sev as SentinelAlertSeverity} />
                : r.icon === "bookmark" ? <span className="xd-chip bm"><Bookmark size={11} aria-hidden />Bookmark</span>
                  : <span className="xd-chip prod"><Activity size={11} aria-hidden />Activity</span>}
              <span className="xd-chip prod st-ellipsis">{r.sub}</span>
              {r.icon === "foreign" && <span className="xd-chip prod">Other incident</span>}
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
