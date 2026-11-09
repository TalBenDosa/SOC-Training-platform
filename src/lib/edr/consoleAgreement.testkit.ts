/**
 * One story, every console (LOG-REALISM-STANDARD R3, R4, R6): the comparison behind
 * consoleAgreement.test.ts. A story is rendered the way the Live Feed and Team Training render it
 * (stack labels and canonical pids, re-timed, native record), then the same rows go through each
 * console path (EDR process tree, RTR, XDR tables, forensic workbench), and what a learner reads in
 * each is compared: the pid, image, command line and hash of every process, the host and user, and
 * the clock.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog } from "@/lib/logs/native/types";
import type { EdrInvestigation, EdrProcess } from "./investigations";

/** The clock the feed's time column prints (EventFeed.tsx). */
export const feedClock = (ts: string) => new Date(ts).toLocaleTimeString("en-GB", { hour12: false });

const ENDPOINT = new Set(["edr", "sysmon", "linux_audit", "windows_security"]);
export const isEndpoint = (e: TelemetryEvent) => ENDPOINT.has(e.source);

/** Leaf scalars of a record, dotted. */
export function leaves(o: unknown, prefix = "", out: [string, unknown][] = []): [string, unknown][] {
  if (o === null || o === undefined) return out;
  if (typeof o !== "object") { out.push([prefix, o]); return out; }
  if (Array.isArray(o)) { o.forEach((v, i) => leaves(v, `${prefix}[${i}]`, out)); return out; }
  for (const [k, v] of Object.entries(o as Record<string, unknown>)) leaves(v, prefix ? `${prefix}.${k}` : k, out);
  return out;
}

// Keys under which the EDR and Sysmon records print an OS pid (Falcon's 12-digit UPIDs are not OS pids).
const PID_KEY = /(^|\.)(pid|ppid|ProcessId|RawProcessId|process_id|process_pid|ParentProcessId|InitiatingProcessId|InitiatingProcessParentId|parent|TargetProcessId|SourceProcessId|NewProcessId|osSrc\.process\.pid)$/i;
const CMD_KEY = /(CommandLine|cmdline|cmdLine|command_line|commandLine|ProcessCommandLine|proctitle)$/i;
const SHA_KEY = /(sha256|SHA256|SHA256HashData|Hashes)$/i;

export interface RecordFacts { pids: Set<number>; cmdlines: Set<string>; sha256: Set<string> }

/** The pids, command lines and SHA-256 values a native record prints. */
export function recordFacts(log: NativeLog | null | undefined): RecordFacts {
  const out: RecordFacts = { pids: new Set(), cmdlines: new Set(), sha256: new Set() };
  if (!log) return out;
  for (const [k, v] of leaves(log.record)) {
    if (PID_KEY.test(k)) {
      const raw = typeof v === "string" && /^0x[0-9a-f]+$/i.test(v) ? parseInt(v, 16) : Number(typeof v === "string" ? v.split(":")[0] : v);
      if (Number.isInteger(raw) && raw > 0 && raw < 10_000_000) out.pids.add(raw);
    }
    if (CMD_KEY.test(k) && typeof v === "string" && v) out.cmdlines.add(v);
    if (SHA_KEY.test(k) && typeof v === "string") for (const m of v.matchAll(/\b[0-9a-f]{64}\b/gi)) out.sha256.add(m[0].toLowerCase());
  }
  return out;
}

export interface Disagreement { where: string; what: string }

/**
 * Every process the console seeded from a feed row (not an ancestor stub) against the rows of the
 * feed that name it: the record prints its pid, its command line and its hash, and the console's
 * start time is the feed's clock for its first row.
 */
export function compareEdrToFeed(inv: EdrInvestigation, feed: { ev: TelemetryEvent; log: NativeLog | null }[], where: string): Disagreement[] {
  const out: Disagreement[] = [];
  const onHost = feed.filter(r => r.ev.hostname && r.ev.hostname.toLowerCase() === inv.host.name.toLowerCase());
  const byPid = new Map<number, { ev: TelemetryEvent; log: NativeLog | null }[]>();
  for (const r of onHost) {
    const pid = r.ev.process?.pid;
    if (typeof pid === "number") (byPid.get(pid) ?? byPid.set(pid, []).get(pid)!).push(r);
  }
  for (const p of inv.processes) {
    if (p.startedAt === "-") continue;
    const rows = byPid.get(p.pid);
    if (!rows?.length) continue;   // a distractor or a synthesised pid: no feed row names it
    for (const r of rows) {
      const f = recordFacts(r.log);
      // Records that by design do not print the process itself: MDE ServiceInstalled names the SCM
      // (services.exe) as initiator, not the service process; Sysmon 7 Hashes are the loaded module's.
      const props = (r.log?.record as { properties?: { ActionType?: string } } | undefined)?.properties;
      const scmRow = r.log?.sourceId === "mde" && props?.ActionType === "ServiceInstalled";
      const moduleRow = r.log?.sourceId === "sysmon" && /image ?load|^7$|ImageLoad/i.test(String(r.log?.kind ?? ""));
      if (moduleRow) f.sha256.clear();
      if (f.pids.size && !scmRow && !f.pids.has(p.pid)) out.push({ where, what: `pid: console ${p.name}(${p.pid}), feed record ${r.log?.sourceId}/${r.log?.kind} prints ${[...f.pids].join(",")}` });
      if (p.sha256 && f.sha256.size && r.ev.event_type?.startsWith("process") && !f.sha256.has(p.sha256.toLowerCase()))
        out.push({ where, what: `hash: console ${p.name}(${p.pid}) ${p.sha256.slice(0, 12)}, feed record prints ${[...f.sha256].map(h => h.slice(0, 12)).join(",")}` });
      if (f.cmdlines.size && r.ev.process?.cmdline && r.ev.event_type?.startsWith("process") && /process_create|linux_execve/.test(r.ev.event_type)
        && p.cmdline !== p.name && !f.cmdlines.has(p.cmdline))
        out.push({ where, what: `cmdline: console ${p.name}(${p.pid}) "${p.cmdline.slice(0, 60)}", feed record prints "${[...f.cmdlines][0]?.slice(0, 60)}"` });
    }
    const first = rows.map(r => r.ev.ts).sort()[0];
    if (first && p.startedAt !== feedClock(first)) out.push({ where, what: `time: console ${p.name}(${p.pid}) started ${p.startedAt}, the feed shows its first row at ${feedClock(first)}` });
  }
  // The console names the host and its user as the feed does.
  if (!onHost.length) out.push({ where, what: `host: console host ${inv.host.name} is on no feed row` });
  // R3: the account realm the console prints ("MEDCORE\m.verhoeven") is one the host's records print,
  // as a DOMAIN\user value or a domain field of its own.
  // Only identity fields count: a DOMAIN\user value under an account key, or a domain field. A
  // CyberArk safe path (Root\Database-MSSQL-...) or a file path is not an account, and the system
  // realms (NT AUTHORITY\SYSTEM) say nothing about the company's domain. Records that print accounts
  // as bare names (Falcon's UserName) give no realm and are not compared.
  const printed = new Set<string>(), domains = new Set<string>();
  for (const r of onHost) identityRealms(r.log?.record, printed, domains);
  if (printed.size) {
    const realms = new Set(seenProcesses(inv).map(p => /^([^\\]+)\\/.exec(p.user)?.[1]).filter((r): r is string => !!r && !SYSTEM_REALM.test(r)));
    for (const r of realms) {
      const lc = r.toLowerCase();
      if (!printed.has(lc) && !domains.has(lc)) out.push({ where, what: `user: console realm ${r} is printed by no record of ${inv.host.name}` });
    }
  }
  return out;
}

const SYSTEM_REALM = /^(nt authority|builtin|nt service|font driver|window manager|iis apppool|nt virtual machine|workgroup)$/i;
/** The last segment of a field name that holds an account (User, UserName, SubjectUserName, AccountName, srcuser ...). */
const ACCOUNT_KEY = /(user|account|principal|actor|owner)(_?name)?$/i;
const DOMAIN_KEY = /domain(_?name)?$/i;
/** Realms a record prints in its identity fields: DOMAIN\user account values and domain fields (lower case). */
export function identityRealms(v: unknown, printed: Set<string>, domains: Set<string>, key = ""): void {
  if (v && typeof v === "object") {
    for (const [k, x] of Object.entries(v as Record<string, unknown>)) identityRealms(x, printed, domains, k);
    return;
  }
  if (typeof v !== "string") return;
  const leaf = key.split(/[.\s]/).pop() ?? key;
  if (ACCOUNT_KEY.test(leaf) && !/sid|id$|type|count|flags|agent/i.test(leaf)) {
    const m = /^([a-z][\w-]{1,14})\\[a-z0-9._$-]+$/i.exec(v);
    if (m && !SYSTEM_REALM.test(m[1])) printed.add(m[1].toLowerCase());
  } else if (DOMAIN_KEY.test(leaf) && /^[a-z][\w.-]{1,62}$/i.test(v)) {
    domains.add(v.toLowerCase());
  }
}

/** The processes of an investigation that came from the feed (not ancestor stubs or seeded background). */
export const seenProcesses = (inv: EdrInvestigation): EdrProcess[] => inv.processes.filter(p => p.startedAt !== "-");
