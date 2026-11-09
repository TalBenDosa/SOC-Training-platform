/**
 * R4 Time is coherent.
 *  a. A native record's own time (the source's stamp) equals the row's time (within 1 s).
 *  b. The row's primary time field (Timestamp, TimeGenerated, @timestamp, UtcTime, CreationTime,
 *     createdDateTime, eventTime ...) equals the row's time (within 2 s). XDR: TimeGenerated is
 *     not before the event and at most an hour after it.
 *  c. No time inside a record is later than the row itself (more than 2 minutes), except fields
 *     that name a future time by design (expiry, validity, schedule, due date, SLA).
 *  d. A story keeps its order: rows authored in time order are shown in that order (baseline
 *     context rows, which are declared out of order, are skipped).
 *  e. An alert comes after the events behind it (XDR alerts; the feed's SIEM mirror rows).
 *  f. One record has one creation time (a ServiceNow number with one opened_at).
 */
import type { Checker, LogRow, Violation } from "../types";
import { leaves, parseInstant, isoOf } from "../util";

const PRIMARY = new Set(["@timestamp", "timestamp", "Timestamp", "TimeGenerated", "eventTime", "createdDateTime", "CreationTime", "TimeCreated", "SystemTime",
  "UtcTime", "_time", "published", "activityDateTime", "EventTime", "event.created", "eventTimestamp", "time", "ts"]);
const FUTURE_OK = /expir|until|notafter|not_after|valid|end|due|lease|ttl|deadline|retention|next|schedul|sla|resolv|close|planned|exp$|renew|reset|unlock|lockout_?duration|start_?date|effective|review/i;

const rowLeaves = (r: LogRow) => (typeof r.raw === "string" ? [] : leaves(r.raw));
const leaf = (p: string) => p.replace(/\[\]/g, "").split(".").pop() ?? p;

export const r4: Checker = c => {
  const out: Violation[] = [];
  // XDR background rows have no stable id of their own: one key per table.
  const push = (r: LogRow, detail: string, example?: string, rowId = r.meta?.baseline ? `${r.company}:${r.source}:baseline` : r.rowId) => out.push({ surface: r.surface, rule: "R4", rowId, detail, company: r.company, storyId: r.storyId, example: example ?? r.rowId });

  for (const r of c.rows) {
    if (r.time === undefined || !Number.isFinite(r.time)) continue;
    // a
    if (r.native && Math.abs(r.native.timeMs - r.time) > 1000) push(r, `record time differs from row time`, `${r.rowId}: record ${isoOf(r.native.timeMs)} row ${isoOf(r.time)}`);
    if (typeof r.raw === "string") continue;
    const ls = rowLeaves(r);
    // b
    if (r.surface === "xdr") {
      const evMs = r.ev ? Date.parse(r.ev.ts) : NaN;
      if (Number.isFinite(evMs) && (r.time < evMs - 1000 || r.time > evMs + 3_600_000)) push(r, `TimeGenerated outside the event's hour`, `${r.rowId}: TimeGenerated ${isoOf(r.time)} event ${isoOf(evMs)}`);
    } else if (!r.native && r.surface !== "edr" && r.surface !== "forensic") {
      const prim = ls.filter(([p]) => PRIMARY.has(leaf(p)) && !p.includes("[]") && p.split(".").length <= 3);
      for (const [p, v] of prim) {
        const t = parseInstant(v, p);
        if (!Number.isFinite(t)) continue;
        if (Math.abs(t - r.time) > 2000) { push(r, `${p} differs from row time`, `${r.rowId}: ${p}=${String(v)} row ${isoOf(r.time)}`); break; }
      }
    }
    // c
    for (const [p, v] of ls) {
      if (FUTURE_OK.test(p)) continue;
      const t = parseInstant(v, p);
      if (!Number.isFinite(t) || t <= r.time + 120_000) continue;
      push(r, `future time in ${p.replace(/\[\]/g, "")}`, `${r.rowId}: ${p}=${String(v)} row ${isoOf(r.time)}`);
      break;
    }
  }

  // d. story order
  const stories = new Map<string, LogRow[]>();
  for (const r of c.rows) {
    if (r.authoredTime === undefined || r.time === undefined || r.meta?.mirrorOf || r.ev?.is_baseline) continue;
    if (r.surface !== "live" && r.surface !== "team" && r.surface !== "scenario") continue;
    const k = `${r.surface}|${r.storyId}|${String(r.meta?.incident ?? "")}`;
    (stories.get(k) ?? stories.set(k, []).get(k)!).push(r);
  }
  for (const [k, rows] of stories) {
    let inv = 0; let ex = "";
    const s = [...rows].sort((a, b) => a.authoredTime! - b.authoredTime! || (a.storyIndex ?? 0) - (b.storyIndex ?? 0));
    for (let i = 1; i < s.length; i++) {
      if (s[i].authoredTime! > s[i - 1].authoredTime! && s[i].time! < s[i - 1].time! - 1000) { inv++; if (!ex) ex = `${s[i - 1].rowId} authored before ${s[i].rowId} but shown after`; }
    }
    if (inv) push(rows[0], `rows shown out of authored order`, `${inv} inversions; ${ex}`, k.split("|").slice(1).filter(Boolean).join("|"));
  }

  // e. alerts after their events
  const byId = new Map(c.rows.map(r => [r.rowId, r]));
  for (const r of c.rows) {
    const times = r.meta?.eventTimes as number[] | undefined;
    if (r.meta?.alert && times?.length && r.time !== undefined) {
      const last = Math.max(...times);
      if (r.time < last - 1000) push(r, `alert before the events it describes`, `${r.rowId}: alert ${isoOf(r.time)} last event ${isoOf(last)}`);
    }
    const of = r.meta?.mirrorOf as string | undefined;
    if (of && r.time !== undefined) { const o = byId.get(of); if (o?.time !== undefined && r.time < o.time - 1000) push(r, `SIEM mirror before its detection`); }
  }

  // f. one record, one creation time
  const tickets = new Map<string, { opened: Set<string>; row: LogRow }>();
  for (const r of c.rows) {
    if (typeof r.raw === "string") continue;
    const ls = rowLeaves(r);
    const num = ls.find(([p]) => leaf(p) === "number")?.[1];
    const opened = ls.find(([p]) => leaf(p) === "opened_at" || leaf(p) === "sys_created_on")?.[1];
    if (typeof num !== "string" || !/^(INC|RITM|REQ|CHG|SCTASK|TASK)\d+/.test(num) || opened === undefined) continue;
    const k = `${r.surface}|${r.company ?? r.storyId}|${num}`;
    const slot = tickets.get(k) ?? tickets.set(k, { opened: new Set(), row: r }).get(k)!;
    slot.opened.add(String(opened));
  }
  for (const [k, { opened, row }] of tickets) if (opened.size > 1) push(row, `ticket has more than one creation time`, `${k}: ${[...opened].slice(0, 3).join(" / ")}`, k.split("|").slice(1).join("|"));
  return out;
};
