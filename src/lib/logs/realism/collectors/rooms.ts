/**
 * Learning rooms collector.
 *
 * - Task logs: the `event` of every log_analysis, analyst_choice and flag task in ROOMS (the
 *   rooms-batch-* files). The room player shows `event.raw` as it is (TaskPlayer), so the raw block
 *   is the row. Ground truth: an analyst_choice task's correct verdict.
 * - Lab logs: the hands-on labs a room runs (getRoomExperience, the same gate the player uses), the
 *   parts that show log rows: hunt tables, trace steps, queue alerts, worksheet tables, pcap packet
 *   lists, portal log grids and tables, and terminal command output (as text).
 */
import { ROOMS } from "@/data/rooms";
import { getRoomExperience } from "@/lib/rooms/experience";
import type { BriefingLab } from "@/lib/rooms/experience";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Collected, LogRow } from "../types";

const table = (columns: string[], cells: (string | number)[]) => Object.fromEntries(columns.map((c, i) => [c, cells[i]]));

function labRows(roomId: string, taskId: string, lab: BriefingLab, li: number): LogRow[] {
  const base = { surface: "room" as const, storyId: roomId, meta: { lab: lab.kind, taskId } };
  const id = (k: string) => `${roomId}:${taskId}:lab${li}:${k}`;
  const out: LogRow[] = [];
  switch (lab.kind) {
    case "hunt":
      for (const t of lab.tables) t.rows.forEach((r, i) => out.push({ ...base, rowId: id(`${t.name}#${i}`), source: `lab.hunt.${t.name}`, eventType: t.name, raw: table(t.columns, r) }));
      break;
    case "trace":
      for (const s of lab.steps) s.rows.forEach((r, i) => out.push({ ...base, rowId: id(`${s.id}#${i}`), source: `lab.trace.${s.source}`, eventType: s.source, raw: table(s.columns, r) }));
      break;
    case "queue":
      for (const a of lab.alerts) out.push({ ...base, rowId: id(a.id), source: "lab.queue", eventType: a.rule, raw: Object.fromEntries(a.fields.map(f => [f.k, f.v])), severity: a.severity.toLowerCase(), isAttack: a.answer !== "close" ? undefined : false });
      break;
    case "worksheet":
      lab.rows.forEach((r, i) => out.push({ ...base, rowId: id(`ws#${i}`), source: "lab.worksheet", eventType: lab.caption, raw: table(lab.columns, r) }));
      break;
    case "pcap":
      for (const p of lab.packets) out.push({ ...base, rowId: id(`pkt${p.no}`), source: "lab.pcap", eventType: p.proto, raw: { Source: p.src, Destination: p.dst, Protocol: p.proto, Info: p.info } });
      break;
    case "portal":
      for (const [pid, page] of Object.entries(lab.pages)) page.table?.rows.forEach(r => out.push({ ...base, rowId: id(`page:${pid}:${r.id}`), source: `lab.portal.${lab.skin}`, eventType: pid, raw: table(page.table!.columns, r.cells) }));
      for (const [rid, rec] of Object.entries(lab.records)) rec.logs?.rows.forEach(r => out.push({ ...base, rowId: id(`rec:${rid}:${r.id}`), source: `lab.portal.${lab.skin}.logs`, eventType: rid, raw: table(rec.logs!.columns, r.cells) }));
      break;
    case "terminal":
      lab.commands.forEach((c, i) => out.push({ ...base, rowId: id(`cmd${i}`), source: `lab.terminal.${lab.shell}`, eventType: "output", raw: c.output }));
      break;
    default:
      break;
  }
  return out;
}

export function collectRooms(out: Collected): void {
  let events = 0, labs = 0;
  for (const room of ROOMS) {
    room.tasks.forEach(task => {
      const ev = (task as { event?: TelemetryEvent | null }).event;
      if (!ev || typeof ev !== "object") return;
      const verdict = task.type === "analyst_choice" ? task.correct_verdict : undefined;
      out.rows.push({
        surface: "room", storyId: room.id, rowId: `${room.id}:${task.id}`, source: ev.vendor ?? ev.source, vendor: ev.vendor, eventType: ev.event_type,
        time: Date.parse(ev.ts), raw: (ev.raw ?? {}) as Record<string, unknown>, severity: ev.severity, ev,
        isAttack: verdict ? (verdict === "true_positive" || verdict === "escalate") : undefined,
        meta: { taskType: task.type },
      });
      events++;
    });
    const exp = getRoomExperience(room.id, room.tasks.map(t => t.id));
    for (const [taskId, list] of Object.entries(exp?.briefings ?? {})) list.forEach((lab, i) => { const r = labRows(room.id, taskId, lab, i); labs += r.length; out.rows.push(...r); });
  }
  out.notes.push(`room: ${ROOMS.length} rooms, ${events} task logs, ${labs} lab rows`);
}
