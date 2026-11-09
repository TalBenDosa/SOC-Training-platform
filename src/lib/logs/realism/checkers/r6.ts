/**
 * R6 Process truth.
 *  a. Feed rows (live, team, scenario) with a process, per story and host: one pid is one image
 *     (name and path), one hash and one command line; a row's parent pid that is another row's
 *     process names that process's image; no process is its own parent. Pids are the ones the
 *     native record prints (canonicalPids; a scenario prints its authored pid).
 *  b. EDR console: in the `ps` view one pid is one process; a case process and the feed row of the
 *     same image and command line on the same host show the same pid.
 *  c. Forensic workbench: pslist has one row per pid; pstree's parent matches pslist.
 */
import { canonicalPids } from "@/lib/logs/native";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { EdrProcess } from "@/lib/edr/investigations";
import type { Checker, LogRow, Violation } from "../types";

const ENDPOINT = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit"]);
const base = (s?: string) => (s ?? "").split(/[\\/]/).pop()!.toLowerCase();
const normCmd = (s?: string) => {
  // The image is compared by name: "C:\Windows\System32\cmd.exe /c x" and "cmd.exe /c x" are one command line.
  const t = (s ?? "").replace(/"/g, "").replace(/\s+/g, " ").trim().toLowerCase();
  const m = /^(.*?\.(?:exe|com|bat|cmd|ps1|dll|scr))(\s|$)(.*)$/.exec(t);
  return m ? `${base(m[1])}${m[2]}${m[3]}`.trim() : t;
};
/** A command line that is only the image (no arguments) says nothing about which instance it is. */
const bare = (cmd: string, name: string) => !cmd || cmd === base(name) || !cmd.includes(" ") && base(cmd) === base(name);
/** Processes Windows runs once per boot. */
const SINGLETON = new Set(["system", "registry", "smss.exe", "wininit.exe", "services.exe", "lsass.exe", "lsaiso.exe", "memory compression"]);
const hk = (h?: string) => (h ?? "").toLowerCase().split(".")[0];

function pidsOf(r: LogRow, ev: TelemetryEvent): { pid?: number; ppid?: number } {
  if (r.surface === "scenario" || r.surface === "live") return { pid: ev.process?.pid, ppid: ev.process?.parent_pid };
  try { const p = canonicalPids(ev, r.company ?? "nexacorp"); return { pid: p.pid ?? ev.process?.pid, ppid: p.parentPid ?? ev.process?.parent_pid }; }
  catch { return { pid: ev.process?.pid, ppid: ev.process?.parent_pid }; }
}

export const r6: Checker = c => {
  const out: Violation[] = [];
  const push = (r: LogRow, rowId: string, detail: string, example?: string) => out.push({ surface: r.surface, rule: "R6", rowId, detail, company: r.company, storyId: r.storyId, example: example ?? r.rowId });

  // a
  type Inst = { names: Set<string>; paths: Set<string>; hashes: Set<string>; cmds: Set<string>; rows: string[]; first: LogRow };
  const inst = new Map<string, Inst>();
  const parents: { r: LogRow; key: string; pname: string }[] = [];
  for (const r of c.rows) {
    const ev = r.ev;
    if (!ev?.process?.name || !ev.hostname || !ENDPOINT.has(ev.source) || r.meta?.mirrorOf) continue;
    if (r.surface !== "live" && r.surface !== "team" && r.surface !== "scenario") continue;
    // Noise-pool rows are separate events hours apart: a pid may be reused between them.
    if (r.storyId?.endsWith(":pool")) continue;
    const { pid, ppid } = pidsOf(r, ev);
    if (typeof pid !== "number") continue;
    const scope = `${r.surface}|${r.storyId}|${hk(ev.hostname)}`;
    if (ppid === pid && pid > 4) push(r, `${scope}|${pid}`, `process ${ev.process.name} is its own parent (pid ${pid})`);
    const key = `${scope}|${pid}`;
    const s = inst.get(key) ?? inst.set(key, { names: new Set(), paths: new Set(), hashes: new Set(), cmds: new Set(), rows: [], first: r }).get(key)!;
    s.names.add(base(ev.process.name));
    if (ev.process.path) s.paths.add(ev.process.path.toLowerCase());
    if (ev.process.hash?.sha256) s.hashes.add(ev.process.hash.sha256.toLowerCase());
    if (ev.process.cmdline && !bare(normCmd(ev.process.cmdline), ev.process.name)) s.cmds.add(normCmd(ev.process.cmdline));
    s.rows.push(r.rowId);
    if (typeof ppid === "number" && ev.process.parent_name) parents.push({ r, key: `${scope}|${ppid}`, pname: base(ev.process.parent_name) });
  }
  for (const [key, s] of inst) {
    const ex = s.rows.slice(0, 2).join(", ");
    if (s.names.size > 1) push(s.first, key, "one pid, more than one image", `${[...s.names].sort().join(", ")}: ${ex}`);
    else {
      if (s.paths.size > 1) push(s.first, key, "one process, more than one image path", `${ex}: ${[...s.paths].join(" | ")}`);
      if (s.hashes.size > 1) push(s.first, key, "one process, more than one hash", ex);
      if (s.cmds.size > 1) push(s.first, key, "one process, more than one command line", `${ex}: ${[...s.cmds].map(x => x.slice(0, 60)).join(" | ")}`);
    }
  }
  const seenParent = new Set<string>();
  for (const p of parents) {
    const s = inst.get(p.key);
    if (!s || s.names.has(p.pname) || s.names.size > 1) continue;
    const k = `${p.key}|${p.pname}`;
    if (seenParent.has(k)) continue;
    seenParent.add(k);
    push(p.r, `${p.key}|${p.pname}`, "parent name differs from that pid's image", `${p.r.rowId}: parent ${p.pname}, pid is ${[...s.names][0]}`);
  }

  // b
  const ps = new Map<string, Map<number, Set<string>>>();
  // Per case: image + command line -> the pids the console shows / the feed shows; image + user -> count.
  const edrPids = new Map<string, { r: LogRow; pids: Set<number> }>();
  const feedPids = new Map<string, Set<number>>();
  const single = new Map<string, { r: LogRow; pids: Set<number> }>();
  for (const r of c.rows) {
    if (r.surface !== "edr" || r.source !== "rtr.ps") continue;
    const p = r.meta?.process as EdrProcess;
    const m = ps.get(r.storyId!) ?? ps.set(r.storyId!, new Map()).get(r.storyId!)!;
    (m.get(p.pid) ?? m.set(p.pid, new Set()).get(p.pid)!).add(base(p.name));
    if (SINGLETON.has(base(p.name)) || base(p.name) === "explorer.exe") {
      const k = `${r.storyId}|${base(p.name)}${base(p.name) === "explorer.exe" ? `|${(p.user ?? "").toLowerCase()}` : ""}`;
      (single.get(k) ?? single.set(k, { r, pids: new Set() }).get(k)!).pids.add(p.pid);
    }
    if (!r.meta?.inCase || !normCmd(p.cmdline) || bare(normCmd(p.cmdline), p.name)) continue;
    const host = hk(String(r.meta.host));
    const k = `${r.storyId}|${base(p.name)}|${normCmd(p.cmdline)}`;
    (edrPids.get(k) ?? edrPids.set(k, { r, pids: new Set() }).get(k)!).pids.add(p.pid);
    if (!feedPids.has(k)) {
      const f = new Set<number>();
      for (const e of (r.meta.feedEvents as TelemetryEvent[] | undefined) ?? []) {
        if (hk(e.hostname) === host && base(e.process?.name) === base(p.name) && normCmd(e.process?.cmdline) === normCmd(p.cmdline) && typeof e.process?.pid === "number") f.add(e.process.pid);
      }
      feedPids.set(k, f);
    }
  }
  for (const [k, { r, pids }] of edrPids) {
    const f = feedPids.get(k)!;
    if (!f.size || [...pids].some(p => f.has(p))) continue;
    const [story, name] = k.split("|");
    push(r, `${story}|${name}`, "EDR console and feed show different pids for one process", `${r.rowId}: EDR ${[...pids].join("/")}, feed ${[...f].join("/")}`);
  }
  for (const [k, { r, pids }] of single) if (pids.size > 1) {
    push(r, k, "single-instance process shown more than once in ps", `pids ${[...pids].sort((a, b) => a - b).join(", ")}`);
  }
  for (const [story, m] of ps) for (const [pid, names] of m) if (names.size > 1) {
    const r = c.rows.find(x => x.storyId === story && x.source === "rtr.ps")!;
    push(r, `${story}|${pid}`, "ps shows one pid for more than one process", [...names].sort().join(", "));
  }

  // c
  const lists = new Map<string, Map<number, { names: Set<string>; ppid: Set<number> }>>();
  for (const r of c.rows) {
    if (r.surface !== "forensic" || (r.source !== "windows.pslist" && r.source !== "windows.pstree") || typeof r.raw === "string") continue;
    const pid = Number(r.raw.PID), ppid = Number(r.raw.PPID);
    const name = String(r.raw.ImageFileName ?? "").replace(/^\*+\s*/, "").toLowerCase();
    const k = `${r.storyId}`;
    const m = lists.get(k) ?? lists.set(k, new Map()).get(k)!;
    const e = m.get(pid) ?? m.set(pid, { names: new Set(), ppid: new Set() }).get(pid)!;
    e.names.add(name); e.ppid.add(ppid);
  }
  for (const [k, m] of lists) for (const [pid, e] of m) if (e.names.size > 1 || e.ppid.size > 1) {
    const r = c.rows.find(x => x.surface === "forensic" && x.storyId === k)!;
    push(r, `${k}|${pid}`, e.names.size > 1 ? "pslist pid is more than one image" : "pid has more than one parent across pslist/pstree", `${[...e.names].join(", ")} / ppid ${[...e.ppid].join(", ")}`);
  }
  return out;
};
