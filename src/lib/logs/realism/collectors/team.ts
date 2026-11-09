/**
 * Team Training, XDR console and Forensic workbench collectors. All three show one team session,
 * so they are built from the same timeline:
 *   - Team: buildTeamTimeline(company, "medium", fixed seed) with the team tests' roster; each feed
 *     row re-timed to when the team sees it (T0 + due offset, withRebasedTime, as forensicReview and
 *     the workbench do) and rendered with nativeView under the company's own products.
 *   - XDR: buildWorkspace over those events with the baseline on (the console's tables): every
 *     table row, plus every alert with the events behind it.
 *   - Forensic: buildEvidenceView (memory and triage) for each attacked endpoint host, captured one
 *     minute after its last row: every tool table row.
 * The bonus channel (held until the instructor releases it) is left out.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamTimeline } from "@/lib/team/buildTimeline";
import { teamLoad } from "@/lib/team/load";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { buildWorkspace } from "@/lib/sentinel/workspace";
import { buildEvidenceView, type FeedRow } from "@/lib/forensics/workbench";
import { hostKey } from "@/lib/team/format";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import type { Collected, LogRow } from "../types";
import { renderRow, COMPANIES } from "./live";
import { parseInstant } from "../util";

const T0 = Date.parse("2026-11-09T08:00:00.000Z");
const ROSTER = [{ role: "t1" }, { role: "t1" }, { role: "t2" }, { role: "t3" }, { role: "mgr" }];

export interface TeamSession { company: string; seed: string; events: TelemetryEvent[]; answers: Map<string, Record<string, unknown>>; feed: FeedRow[] }

export function teamSession(company: string): TeamSession {
  const seed = `realism-${company}`;
  const tl = buildTeamTimeline(company, "medium", seed, null, teamLoad("medium", ROSTER), {})
    .filter(t => t.channel === "feed").sort((a, b) => a.due_offset_ms - b.due_offset_ms);
  const feed: FeedRow[] = tl.map(t => { const at = T0 + t.due_offset_ms; return { ev: withRebasedTime(t.body as unknown as TelemetryEvent, new Date(at).toISOString()), atMs: at }; });
  const answers = new Map(tl.map((t, i) => [feed[i].ev.id, (t.answer ?? {}) as Record<string, unknown>]));
  return { company, seed, events: feed.map(f => f.ev), answers, feed };
}

const attackOf = (a?: Record<string, unknown>) => a?.expected_verdict === "tp" || a?.expected_verdict === "escalate";

export function collectTeam(out: Collected, companies = COMPANIES): TeamSession[] {
  const sessions: TeamSession[] = [];
  for (const company of companies) {
    const s = teamSession(company);
    sessions.push(s);
    const rows: LogRow[] = s.events.map((ev, i) => {
      const a = s.answers.get(ev.id) ?? {};
      // The authored event a story row came from (as timelineCoherence.test reads it), for R4 order.
      let authoredTime: number | undefined;
      if (a.origin === "story" || a.feed_origin === "story") {
        const story = ATTACK_STORIES.find(st => st.title === a.attack_name);
        const oid = String(a.original_id ?? "").replace(/__\d+$/, "");
        const idx = story?.events.findIndex(e => e.id === oid) ?? -1;
        if (story && idx >= 0) authoredTime = Date.parse(story.events[idx].ts);
      }
      return renderRow("team", ev, company, {
        authoredTime, storyIndex: i,
        storyId: `${company}:${s.seed}`, rowId: `${company}:${s.seed}:${ev.id}`, isAttack: attackOf(a),
        meta: { answer: a, incident: a.incident_id, origin: a.feed_origin, originalId: a.original_id, attackName: a.attack_name, order: i },
      });
    });
    out.rows.push(...rows);
    out.feeds.push({ surface: "team", id: `${company}:${s.seed}`, company, rows, note: "medium, 5-seat roster" });
    out.notes.push(`team ${company}: ${rows.length} feed rows`);
  }
  return sessions;
}

export function collectXdr(out: Collected, sessions: TeamSession[]): void {
  for (const s of sessions) {
    const ws = buildWorkspace(s.events, { companyId: s.company });
    const owner = new Map<object, string>();
    for (const [eid, list] of Object.entries(ws.eventRows)) for (const m of list) owner.set(m.row, eid);
    const evById = new Map(s.events.map(e => [e.id, e]));
    let n = 0;
    for (const [table, t] of Object.entries(ws.tables)) {
      t.rows.forEach((row, i) => {
        const eid = owner.get(row);
        const ev = eid ? evById.get(eid) : undefined;
        const time = parseInstant(row.TimeGenerated);
        out.rows.push({
          surface: "xdr", company: s.company, storyId: `${s.company}:${s.seed}`,
          rowId: `${s.company}:${table}:${eid ?? `baseline#${i}`}${eid && (ws.eventRows[eid]?.length ?? 0) > 1 ? `#${ws.eventRows[eid].findIndex(m => m.row === row)}` : ""}`,
          source: table, eventType: String(row.Type ?? table), time, raw: row,
          isAttack: eid ? attackOf(s.answers.get(eid)) : false, ev,
          meta: { baseline: !eid, eventId: eid },
        });
        n++;
      });
    }
    // Alerts and the events behind them (R4 order, R7 evidence).
    for (const al of ws.alerts) {
      const ids = ws.alertEventIds[al.id] ?? [];
      out.rows.push({
        surface: "xdr", company: s.company, storyId: `${s.company}:${s.seed}`, rowId: `${s.company}:alert:${al.name}:${ids[0] ?? "none"}`,
        source: "SentinelAlert", eventType: "alert", time: Date.parse(al.time), raw: { AlertName: al.name, Description: al.description, ProductName: al.product },
        severity: al.severity.toLowerCase(),
        meta: { alert: true, eventTimes: ids.map(id => Date.parse(evById.get(id)?.ts ?? "")).filter(Number.isFinite), eventIds: ids },
      });
    }
    out.notes.push(`xdr ${s.company}: ${n} table rows (${ws.baselineRows} baseline), ${ws.alerts.length} alerts, ${ws.incidents.length} incidents`);
  }
}

const ENDPOINT = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit"]);

export function collectForensic(out: Collected, sessions: TeamSession[]): void {
  for (const s of sessions) {
    const hosts = new Map<string, { host: string; last: number }>();
    for (const f of s.feed) {
      if (!f.ev.hostname || !ENDPOINT.has(f.ev.source) || !attackOf(s.answers.get(f.ev.id))) continue;
      const k = hostKey(f.ev.hostname);
      const cur = hosts.get(k);
      if (!cur || f.atMs > cur.last) hosts.set(k, { host: f.ev.hostname, last: f.atMs });
    }
    let n = 0;
    for (const { host, last } of hosts.values()) {
      for (const kind of ["memory", "triage"] as const) {
        const id = `${kind === "memory" ? "MEM" : "TRI"}-${host}`;
        let view;
        try { view = buildEvidenceView({ feed: s.feed, host, evidenceId: id, kind, snapshotMs: last + 60_000, state: { isolatedAtMs: null, kills: [] }, sessionId: s.seed }); }
        catch { out.notes.push(`forensic ${s.company} ${host} ${kind}: build failed`); continue; }
        for (const t of view.tables) {
          t.rows.forEach((r, i) => {
            const raw = Object.fromEntries(t.columns.map((c, j) => [c, r[j]]));
            out.rows.push({
              surface: "forensic", company: s.company, storyId: `${s.company}:${host}:${kind}`, rowId: `${s.company}:${host}:${t.plugin}:${t.keys[i] ?? i}`,
              source: t.plugin, eventType: t.plugin, time: t.times[i] ?? undefined, raw, meta: { table: t.plugin, key: t.keys[i], host },
            });
            n++;
          });
        }
      }
    }
    out.notes.push(`forensic ${s.company}: ${hosts.size} attacked hosts, ${n} tool rows`);
  }
}
