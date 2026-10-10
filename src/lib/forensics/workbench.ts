/**
 * Tier-3 Forensic Workbench (MVP): forensic tool views generated from what really happened in the
 * team session on one host, up to the moment the evidence was collected.
 *
 * Principles (research/t3-manager/T3-forensic-simulation-design.md):
 * - Everything derives from the session: the host's own feed logs (re-timed to when the team saw
 *   them), turned into an endpoint picture by the same builder the EDR console uses, over the
 *   host's normal background (baseline processes, autostarts) so not every row is malicious.
 * - Time gate: a capture only contains what had happened BEFORE its snapshot time. A capture
 *   taken early does not see the attacker's later steps; take another one.
 * - Host state matters: a process killed through RTR before the capture is gone from memory;
 *   an isolated host's outbound sessions are closed.
 * - No answer key: the views never show a verdict or a "malicious" flag. The trainee reads raw
 *   tool output and decides.
 *
 * Column names follow the real tools (Volatility 3 windows.pslist / pstree / cmdline / netscan,
 * Velociraptor-style autoruns and Prefetch, Hayabusa-style event timeline). Values that are not
 * in the telemetry (memory offsets, thread and handle counts) are deterministic placeholders.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { EdrInvestigation, EdrProcess } from "@/lib/edr/investigations";
import { buildInvestigationFromStory } from "@/lib/edr/fromLiveStory";
import { hostProcesses, hostAutostarts } from "@/lib/edr/rtr";
import { hostKey } from "@/lib/team/format";

export type EvidenceKind = "memory" | "triage";
export const COLLECT_DELAY_S: Record<EvidenceKind, number> = { memory: 45, triage: 60 };
export const EVIDENCE_PREFIX: Record<EvidenceKind, string> = { memory: "MEM", triage: "TRI" };

export interface FeedRow { ev: TelemetryEvent; atMs: number }
export interface ToolTable {
  plugin: string;            // e.g. "windows.pslist"
  label: string;             // tab label
  command: string;           // the real command this view stands for
  columns: string[];
  rows: (string | number)[][];
  /** Opaque reference per row (cited by findings). */
  refs: string[];
  /** Session time of each row when known (for the timeline). */
  times: (number | null)[];
  notes: string[];
}
export interface EvidenceView { evidenceId: string; kind: EvidenceKind; host: string; snapshotMs: number; tables: ToolTable[]; empty?: string }

// ── small deterministic helpers ─────────────────────────────────────────────
function hash(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
const hex = (n: number, w = 4) => n.toString(16).padStart(w, "0");
const offset = (seed: string) => `0x${hex(0xb20c, 4)}${hex(hash(seed) >>> 0, 8)}`;
const isInternal = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0)/.test(ip);
// One clock for every view: the viewer's local time, like the rest of the room.
const hhmmss = (ms: number) => new Date(ms).toLocaleTimeString("en-GB", { hour12: false });
const isServer = (host: string) => /(^|[-_])(srv|dc\d*|fs\d*|sql|db|exch|app)([-_\d]|$)/i.test(host);
const SYSTEM_NAMES = new Set(["system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe", "registry", "fontdrvhost.exe", "dwm.exe"]);

export interface HostState { isolatedAtMs: number | null; kills: { pid?: number; name?: string; atMs: number }[] }

/** The endpoint picture of `host` from its own logs up to `untilMs`. */
export function hostInvestigation(feed: FeedRow[], host: string, untilMs: number, sessionId: string): EdrInvestigation | null {
  const k = hostKey(host);
  const own = feed.filter(r => r.atMs <= untilMs && r.ev.hostname && hostKey(r.ev.hostname) === k).map(r => r.ev);
  if (!own.length) return null;
  return buildInvestigationFromStory({ id: `fw-${sessionId}-${k}`, title: host, events: own, iocTruth: null });
}

/** Build the tool views of one evidence item. */
export function buildEvidenceView(args: { feed: FeedRow[]; host: string; evidenceId: string; kind: EvidenceKind; snapshotMs: number; state: HostState; sessionId: string }): EvidenceView {
  const { feed, host, evidenceId, kind, snapshotMs, state, sessionId } = args;
  const base: EvidenceView = { evidenceId, kind, host, snapshotMs, tables: [] };
  const inv = hostInvestigation(feed, host, snapshotMs, sessionId);
  const hostRows = feed.filter(r => r.atMs <= snapshotMs && r.ev.hostname && hostKey(r.ev.hostname) === hostKey(host));
  if (kind === "memory") {
    if (!inv) return { ...base, empty: `No endpoint telemetry from ${host} before this capture: the memory image shows only the operating system.` };
    base.tables = memoryTables(inv, evidenceId, snapshotMs, state);
  } else {
    base.tables = triageTables(inv, hostRows, host, evidenceId, snapshotMs);
  }
  return base;
}

// ── memory (Volatility 3) ───────────────────────────────────────────────────
function memoryTables(inv: EdrInvestigation, id: string, snapshotMs: number, state: HostState): ToolTable[] {
  const killedBefore = state.kills.filter(k => k.atMs <= snapshotMs);
  const killedPids = new Set(killedBefore.map(k => k.pid).filter((x): x is number => typeof x === "number"));
  const procs = hostProcesses(inv, killedPids);
  const isolated = state.isolatedAtMs != null && state.isolatedAtMs <= snapshotMs;
  // Process start times come from the (UTC) telemetry as HH:MM:SS on the snapshot's day.
  const procTime = (p: EdrProcess): number | null => {
    if (!p.startedAt || p.startedAt === "—") return null;
    const d = new Date(snapshotMs); const [h, m, s] = p.startedAt.split(":").map(Number);
    d.setUTCHours(h, m, s, 0); return d.getTime();
  };
  const created = (p: EdrProcess) => { const t = procTime(p); return t == null ? "N/A" : hhmmss(t); };
  const ref = (plugin: string, i: number) => `${id}/${plugin}#${i}`;
  const killNote = killedBefore.length ? [`${killedBefore.length} process${killedBefore.length > 1 ? "es were" : " was"} terminated through RTR before this capture (${killedBefore.map(k => k.name ?? `PID ${k.pid}`).join(", ")}): ${killedBefore.length > 1 ? "they are" : "it is"} no longer in memory.`] : [];

  const pslist: ToolTable = {
    plugin: "windows.pslist", label: "pslist", command: `vol -f ${id}.raw windows.pslist`,
    columns: ["PID", "PPID", "ImageFileName", "Offset(V)", "Threads", "Handles", "SessionId", "Wow64", "CreateTime", "ExitTime"],
    rows: procs.map(p => [p.pid, p.ppid, p.name, offset(`${id}:${p.pid}`), 2 + (hash(`t${p.pid}`) % 30), 40 + (hash(`h${p.pid}`) % 900), SYSTEM_NAMES.has(p.name.toLowerCase()) ? 0 : 1, "False", created(p), "N/A"]),
    refs: procs.map((_, i) => ref("pslist", i)), times: procs.map(procTime), notes: killNote,
  };

  // pstree: depth-first by parent
  const byPid = new Map(procs.map(p => [p.pid, p]));
  const kids = new Map<number, EdrProcess[]>();
  for (const p of procs) { const parent = byPid.has(p.ppid) ? p.ppid : -1; if (!kids.has(parent)) kids.set(parent, []); kids.get(parent)!.push(p); }
  const tree: { p: EdrProcess; depth: number }[] = [];
  const walk = (pid: number, depth: number) => { for (const c of (kids.get(pid) ?? []).sort((a, b) => a.pid - b.pid)) { tree.push({ p: c, depth }); if (depth < 12) walk(c.pid, depth + 1); } };
  walk(-1, 0);
  const pstree: ToolTable = {
    plugin: "windows.pstree", label: "pstree", command: `vol -f ${id}.raw windows.pstree`,
    columns: ["PID", "PPID", "ImageFileName", "CreateTime"],
    rows: tree.map(({ p, depth }) => [p.pid, p.ppid, `${"*".repeat(depth + 1)} ${p.name}`, created(p)]),
    refs: tree.map((_, i) => ref("pstree", i)), times: tree.map(({ p }) => procTime(p)), notes: killNote,
  };

  const cmdline: ToolTable = {
    plugin: "windows.cmdline", label: "cmdline", command: `vol -f ${id}.raw windows.cmdline`,
    columns: ["PID", "Process", "Args"],
    rows: procs.map(p => [p.pid, p.name, p.cmdline || "Required memory at 0x... is not valid (process exited?)"]),
    refs: procs.map((_, i) => ref("cmdline", i)), times: procs.map(procTime), notes: [],
  };

  // A connection time is either a full timestamp or HH:MM:SS (UTC) on the snapshot's day.
  const connTime = (ts?: string): number | null => {
    if (!ts) return null;
    const full = Date.parse(ts); if (!Number.isNaN(full)) return full;
    const m = ts.match(/^(\d{2}):(\d{2}):(\d{2})/); if (!m) return null;
    const d = new Date(snapshotMs); d.setUTCHours(+m[1], +m[2], +m[3], 0); return d.getTime();
  };
  const conns: (string | number)[][] = []; const cRefs: string[] = []; const cTimes: (number | null)[] = [];
  const localIp = inv.host.ip || "10.0.0.10";
  let i = 0;
  for (const p of procs) for (const n of p.network ?? []) {
    const tcp = (n.proto ?? "tcp").toLowerCase() !== "udp";
    const external = !isInternal(n.remote_ip);
    const st = !tcp ? "" : isolated && external ? "CLOSED" : n.direction === "inbound" ? "ESTABLISHED" : "ESTABLISHED";
    conns.push([offset(`${id}:n${i}`), tcp ? "TCPv4" : "UDPv4", localIp, 49152 + (hash(`${p.pid}:${n.remote_ip}:${n.remote_port}`) % 16000), n.remote_ip, n.remote_port, st, p.pid, p.name, connTime(n.ts) != null ? hhmmss(connTime(n.ts)!) : "N/A"]);
    cRefs.push(ref("netscan", i)); cTimes.push(connTime(n.ts)); i++;
  }
  const sys = procs.find(p => p.name.toLowerCase() === "system");
  const rpc = procs.find(p => /-k RPCSS/i.test(p.cmdline));
  for (const [port, owner] of [[445, sys], [135, rpc]] as const) {
    if (!owner) continue;
    conns.push([offset(`${id}:l${port}`), "TCPv4", "0.0.0.0", port, "0.0.0.0", 0, "LISTENING", owner.pid, owner.name, "N/A"]);
    cRefs.push(ref("netscan", i)); cTimes.push(null); i++;
  }
  const netscan: ToolTable = {
    plugin: "windows.netscan", label: "netscan", command: `vol -f ${id}.raw windows.netscan`,
    columns: ["Offset", "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "State", "PID", "Owner", "Created"],
    rows: conns, refs: cRefs, times: cTimes,
    notes: isolated ? [`The host was network-isolated at ${hhmmss(state.isolatedAtMs!)} (before this capture): outbound sessions show as CLOSED.`] : [],
  };
  return [pslist, pstree, cmdline, netscan];
}

// ── triage package (autoruns, Prefetch, event logs) ─────────────────────────
const EVENT_ID: Record<string, string> = {
  process_create: "4688", process_start: "4688", logon: "4624", auth_success: "4624", auth_failure: "4625", login_failed: "4625",
  service_install: "7045", scheduled_task: "4698", account_create: "4720", group_modify: "4728", privilege_escalation: "4672",
  audit_log_cleared: "1102", net_connection: "3", dns_query: "22", file_create: "11", registry_set: "13",
};
// Sysmon numbers its own events (1 process create, 3 network, 11 file create, 13 registry, 22 DNS).
const SYSMON_ID: Record<string, string> = { process_create: "1", process_start: "1", net_connection: "3", file_create: "11", registry_set: "13", dns_query: "22" };
function eventIdOf(e: TelemetryEvent): string {
  const raw = (e.raw ?? {}) as Record<string, unknown>;
  const v = raw.EventID ?? raw.event_id ?? raw["event.code"] ?? raw["winlog.event_id"] ?? raw["data.win.system.eventID"];
  if (v != null && String(v).trim()) return String(v);
  return (e.source === "sysmon" ? SYSMON_ID[String(e.event_type)] : EVENT_ID[String(e.event_type)]) ?? "-";
}
function channelOf(e: TelemetryEvent, id: string): string {
  if (e.source === "sysmon" || ["1", "3", "11", "13", "22"].includes(id)) return "Sysmon";
  if (["7045"].includes(id)) return "System";
  return "Security";
}

function triageTables(inv: EdrInvestigation | null, hostRows: FeedRow[], host: string, id: string, snapshotMs: number): ToolTable[] {
  const ref = (plugin: string, i: number) => `${id}/${plugin}#${i}`;
  const out: ToolTable[] = [];
  if (inv) {
    const a = hostAutostarts(inv);
    const rows: (string | number)[][] = [
      ...a.runKeys.map(r => ["Run key", r.name, r.key, r.data]),
      ...a.tasks.map(t => ["Scheduled task", t.name, `\\Microsoft\\Windows\\Tasks (${t.status})`, t.action ?? "(action not captured)"]),
      ...a.services.map(s => ["Service", s.name, `${s.start} · ${s.account}`, s.binPath]),
      ...a.wmi.map(w => ["WMI subscription", w.filter, w.consumer, w.command]),
    ];
    out.push({ plugin: "autoruns", label: "Autoruns", command: `velociraptor artifacts collect Windows.Sys.StartupItems,Windows.System.TaskScheduler,Windows.System.Services,Windows.Persistence.PermanentWMIEvents -- host ${host}`,
      columns: ["Category", "Entry", "Location", "Image / Command"], rows, refs: rows.map((_, i) => ref("autoruns", i)), times: rows.map(() => null), notes: [] });

    if (isServer(host)) {
      out.push({ plugin: "prefetch", label: "Prefetch", command: `velociraptor artifacts collect Windows.Forensics.Prefetch -- host ${host}`, columns: ["Executable", "PrefetchFile", "RunCount", "LastRunTime"], rows: [], refs: [], times: [],
        notes: ["No Prefetch files: Prefetch is turned off by default on Windows Server. Use the event logs and memory instead."] });
    } else {
      const seen = new Map<string, { n: number; last: string; t: number | null }>();
      for (const p of [...inv.processes].sort((x, y) => x.startedAt.localeCompare(y.startedAt))) {
        const name = p.name.toUpperCase();
        if (SYSTEM_NAMES.has(p.name.toLowerCase())) continue;
        const cur = seen.get(name) ?? { n: 0, last: "N/A", t: null };
        cur.n++;
        if (p.startedAt && p.startedAt !== "—") { const d = new Date(snapshotMs); const [h, m, x] = p.startedAt.split(":").map(Number); d.setUTCHours(h, m, x, 0); cur.last = hhmmss(d.getTime()); }
        seen.set(name, cur);
      }
      const rows = [...seen.entries()].map(([name, v]) => [name, `${name}-${hex(hash(name), 8).toUpperCase()}.pf`, v.n, v.last]);
      out.push({ plugin: "prefetch", label: "Prefetch", command: `velociraptor artifacts collect Windows.Forensics.Prefetch -- host ${host}`, columns: ["Executable", "PrefetchFile", "RunCount", "LastRunTime"], rows, refs: rows.map((_, i) => ref("prefetch", i)), times: rows.map(() => null), notes: [] });
    }
  }
  // Event logs = what the host's EVTX holds: Windows logs and Sysmon. EDR telemetry lives in the EDR console, not here.
  const logRows = hostRows.filter(r => ["windows", "sysmon"].includes(String(r.ev.source))).sort((a, b) => a.atMs - b.atMs);
  const rows = logRows.map(r => { const eid = eventIdOf(r.ev); return [hhmmss(r.atMs), host, channelOf(r.ev, eid), eid, String(r.ev.severity ?? "info"), String(r.ev.description ?? r.ev.event_type ?? "event").slice(0, 160)]; });
  out.push({ plugin: "evtx", label: "Event logs", command: `hayabusa csv-timeline -d ./${id}/evtx -o ${id}-timeline.csv`, columns: ["Timestamp", "Computer", "Channel", "EventID", "Level", "Details"],
    rows, refs: rows.map((_, i) => ref("evtx", i)), times: logRows.map(r => r.atMs),
    notes: logRows.length ? [] : ["No Windows event logs from this host in the collection window."] });
  if (!inv && !logRows.length) out[0] ??= { plugin: "none", label: "Nothing", command: "", columns: [], rows: [], refs: [], times: [], notes: [`Nothing collected from ${host} before ${hhmmss(snapshotMs)}.`] };
  return out;
}
