/**
 * RTR-lite — the simulated Real Time Response shell of the EDR console, as a pure
 * function so it is deterministic and testable. It answers from the investigation
 * (the case's own processes, connections and persistence) layered over the host's
 * NORMAL background (hostBaseline.ts): `ps` shows System / smss / csrss / wininit /
 * services / lsass / several svchost next to the attack processes; `reg query …\Run`,
 * `schtasks /query`, `sc query` and the WMI-subscription check list the benign
 * entries every host has plus the malicious one when the story planted persistence.
 * The analyst has to find the odd one out — the shell never labels it.
 */
import type { EdrInvestigation, EdrProcess } from "./investigations";
import {
  buildHostBaseline, baselineRunKeys, baselineServices, baselineTasks, baselineWmi,
  isLinuxHost, isServerHost, RUN_HKLM,
  type RunKeyEntry, type ServiceEntry, type TaskEntry, type WmiEntry,
} from "./hostBaseline";

export interface RtrState {
  inv: EdrInvestigation;
  killed: ReadonlySet<number>;
  isolated: boolean;
}
export interface RtrResult {
  out: string;
  kill?: number;        // pid the caller should mark terminated
  contain?: boolean;    // caller should network-contain the host
  clear?: boolean;      // caller should clear the transcript
}

export const RTR_HELP =
  "Commands: ps · netstat · kill <pid> · get <path> · cat <path> · reg query <key> · " +
  "schtasks /query [/v] · sc query | sc qc <name> · wmi (root\\subscription filters/consumers) · contain · clear";

const CRITICAL = new Set(["system", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe"]);

/** Every process on the host right now: the case's tree + the normal background. */
export function hostProcesses(inv: EdrInvestigation, killed: ReadonlySet<number>): EdrProcess[] {
  const all = [...inv.processes, ...buildHostBaseline(inv)];
  return all.filter(p => !killed.has(p.pid)).sort((a, b) => a.pid - b.pid);
}

function normKey(k: string): string {
  return k.trim().replace(/^HKCU(?=\\|$)/i, "HKEY_CURRENT_USER").replace(/^HKLM(?=\\|$)/i, "HKEY_LOCAL_MACHINE").toUpperCase();
}

function runKeys(inv: EdrInvestigation): RunKeyEntry[] {
  const out = baselineRunKeys(inv.host);
  for (const a of inv.autoruns ?? []) {
    // autoruns carry "Name    REG_SZ    data" (or a bare data string) under the key
    const m = a.value.match(/^(.+?)\s{2,}(REG_\w+)\s{2,}(.*)$/);
    const key = a.key.replace(/^HKCU(?=\\|$)/i, "HKEY_CURRENT_USER").replace(/^HKLM(?=\\|$)/i, "HKEY_LOCAL_MACHINE");
    out.push(m ? { key, name: m[1].trim(), type: m[2], data: m[3], malicious: true }
               : { key, name: "(unnamed)", type: "REG_SZ", data: a.value, malicious: true });
  }
  return out;
}

function tasks(inv: EdrInvestigation): TaskEntry[] {
  const out = baselineTasks(inv.host);
  for (const t of inv.persistence?.tasks ?? []) out.push({ name: t.name, next: "At log on", status: "Ready", action: t.action, author: t.author, malicious: true });
  return out;
}

function services(inv: EdrInvestigation): ServiceEntry[] {
  const out = baselineServices(inv.host, inv.edrAgent);
  for (const s of inv.persistence?.services ?? []) {
    if (out.some(x => x.name.toLowerCase() === s.name.toLowerCase())) continue;
    out.push({ name: s.name, display: s.name, state: s.running === false ? "STOPPED" : "RUNNING", start: s.start ?? "DEMAND_START", binPath: s.binPath, account: s.account ?? "LocalSystem", malicious: true });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

function wmi(inv: EdrInvestigation): WmiEntry[] {
  return [...baselineWmi(), ...(inv.persistence?.wmi ?? []).map(w => ({ filter: w.filter, query: w.query ?? "(not captured)", consumer: w.consumer, command: w.command, malicious: true }))];
}

function listening(inv: EdrInvestigation, procs: EdrProcess[]): string[] {
  const find = (pred: (p: EdrProcess) => boolean) => procs.find(pred);
  const rpc = find(p => /-k RPCSS/i.test(p.cmdline));
  const lsass = find(p => p.name.toLowerCase() === "lsass.exe");
  const rows = [
    `TCP   0.0.0.0:135     LISTENING   ${rpc ? `svchost.exe(${rpc.pid})` : "svchost.exe"}`,
    "TCP   0.0.0.0:445     LISTENING   System(4)",
    `TCP   0.0.0.0:49664   LISTENING   ${lsass ? `lsass.exe(${lsass.pid})` : "lsass.exe"}`,
  ];
  if (isServerHost(inv.host)) {
    const winrm = find(p => /WinRM/i.test(p.cmdline));
    rows.push(`TCP   0.0.0.0:5985    LISTENING   ${winrm ? `svchost.exe(${winrm.pid})` : "svchost.exe"}`);
  }
  return rows;
}

export function runRtrCommand(raw: string, st: RtrState): RtrResult | null {
  const cmd = raw.trim();
  if (!cmd) return null;
  const { inv, killed, isolated } = st;
  const [verbRaw, ...args] = cmd.split(/\s+/);
  const verb = verbRaw.toLowerCase();
  const linux = isLinuxHost(inv.host);
  const windowsOnly = () => ({ out: `rtr: '${verbRaw}' is a Windows command — ${inv.host.name} is a Linux host. Try ps, netstat, or cat /etc/crontab.` });

  switch (verb) {
    case "help":
      return { out: RTR_HELP };

    case "ps": {
      const procs = hostProcesses(inv, killed);
      const w = Math.min(30, Math.max(12, ...procs.map(p => p.user.length)));
      return { out: ["PID    PPID   " + "USER".padEnd(w) + "  IMAGE",
        ...procs.map(p => `${String(p.pid).padEnd(6)} ${String(p.ppid).padEnd(6)} ${p.user.padEnd(w)}  ${p.name}`)].join("\n") };
    }

    case "netstat": {
      if (isolated) return { out: "Host network-contained — only sensor traffic allowed. No analyst-visible connections." };
      const procs = hostProcesses(inv, killed);
      const live = inv.processes.filter(p => !killed.has(p.pid));
      const rows = live.flatMap(p => (p.network ?? []).map(c => {
        const arrow = c.direction === "inbound" ? "<-" : "->";
        const app = c.application ? `/${c.application}` : "";
        return `${(c.proto ?? "tcp").toUpperCase()}${app}  ${p.name}(${p.pid}) ${arrow} ${c.remote_ip}:${c.remote_port}${c.domain ? ` (${c.domain})` : ""}  ${c.direction.toUpperCase()}  [${c.ts}]`;
      }));
      return { out: [...(linux ? [] : listening(inv, procs)), ...(rows.length ? rows : ["(no established connections)"])].join("\n") };
    }

    case "kill": {
      const pid = Number(args[0]);
      const p = hostProcesses(inv, new Set()).find(x => x.pid === pid);
      if (!p) return { out: `No process with pid ${args[0] ?? "?"}.` };
      if (killed.has(pid)) return { out: `Process ${pid} (${p.name}) is already terminated — nothing to kill.` };
      if (CRITICAL.has(p.name.toLowerCase())) return { out: `Access is denied — ${p.name} (${pid}) is a critical system process; terminating it would bugcheck the host.` };
      return { out: `Process ${pid} (${p.name}) terminated. It no longer appears in ps/netstat.`, kill: pid };
    }

    case "get": {
      const path = args.join(" ");
      if (!path) return { out: "usage: get <full path>" };
      // E-07: accept the image path the console itself shows, not only a logged file op.
      const hit = inv.processes.some(p =>
        (p.path ?? "").toLowerCase() === path.toLowerCase() ||
        (p.files ?? []).some(f => f.path.toLowerCase() === path.toLowerCase()));
      return { out: `Queued "${path}" for upload to the cloud (password: infected).${hit ? " File captured." : " (path not seen on host — check spelling)"}` };
    }

    case "cat": {
      const path = args.join(" ");
      return { out: path ? `(binary content) ${path} — use 'get' to pull it to the cloud for analysis.` : "usage: cat <path>" };
    }

    case "reg": {
      if (linux) return windowsOnly();
      if ((args[0] ?? "").toLowerCase() !== "query") return { out: "usage: reg query <key>   e.g. reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" };
      const want = normKey(args.slice(1).join(" "));
      const entries = runKeys(inv);
      const hive = want.startsWith("HKEY_LOCAL_MACHINE") ? "HKEY_LOCAL_MACHINE" : want.startsWith("HKEY_CURRENT_USER") ? "HKEY_CURRENT_USER" : "";
      const aboutRun = !want || want === "RUN" || /\\RUN(ONCE)?$/.test(want) || want === hive;
      if (!aboutRun) return { out: "ERROR: The system was unable to find the specified registry key or value." };
      const shown = entries.filter(e => !hive || normKey(e.key).startsWith(hive));
      const byKey = new Map<string, RunKeyEntry[]>();
      for (const e of shown) { const l = byKey.get(e.key) ?? []; l.push(e); byKey.set(e.key, l); }
      if (byKey.size === 0) return { out: `${hive || RUN_HKLM}\n    (no values)` };
      return { out: [...byKey].map(([k, list]) => [k, ...list.map(e => `    ${e.name}    ${e.type}    ${e.data}`)].join("\n")).join("\n\n") };
    }

    case "schtasks": {
      if (linux) return windowsOnly();
      const verbose = args.some(a => /^\/v$/i.test(a));
      const list = tasks(inv);
      if (verbose) {
        return { out: list.map(t => [
          `TaskName:        ${t.name}`, `Next Run Time:   ${t.next}`, `Status:          ${t.status}`,
          `Author:          ${t.author ?? "Microsoft Corporation"}`, `Task To Run:     ${t.action ?? "COM handler"}`,
        ].join("\n")).join("\n\n") };
      }
      const w = Math.max(40, ...list.map(t => t.name.length)) + 2;
      return { out: ["TaskName".padEnd(w) + "Next Run Time            Status", "=".repeat(w - 2) + "  ====================== ======",
        ...list.map(t => `${t.name.padEnd(w)}${t.next.padEnd(25)}${t.status}`)].join("\n") };
    }

    case "services":
    case "get-service":
    case "sc": {
      if (linux) return windowsOnly();
      const list = services(inv);
      if (verb === "sc" && (args[0] ?? "").toLowerCase() === "qc") {
        const s = list.find(x => x.name.toLowerCase() === (args[1] ?? "").toLowerCase());
        if (!s) return { out: `[SC] OpenService FAILED 1060:\n\nThe specified service does not exist as an installed service.` };
        return { out: [`[SC] QueryServiceConfig SUCCESS`, ``, `SERVICE_NAME: ${s.name}`, `        START_TYPE         : ${s.start}`,
          `        BINARY_PATH_NAME   : ${s.binPath}`, `        DISPLAY_NAME       : ${s.display}`, `        SERVICE_START_NAME : ${s.account}`].join("\n") };
      }
      if (verb === "sc" && !/^(query|queryex|)$/i.test(args[0] ?? "")) return { out: "usage: sc query  |  sc qc <service name>" };
      return { out: list.map(s => `SERVICE_NAME: ${s.name}\nDISPLAY_NAME: ${s.display}\n        STATE              : ${s.state === "RUNNING" ? "4  RUNNING" : "1  STOPPED"}`).join("\n\n") };
    }

    case "wmi":
    case "wmic":
    case "get-wmiobject":
    case "get-ciminstance": {
      if (linux) return windowsOnly();
      const list = wmi(inv);
      return { out: [`Namespace root\\subscription — ${list.length} event filter(s) / consumer binding(s)`, "",
        ...list.map(w => [`__EventFilter.Name   : ${w.filter}`, `  Query              : ${w.query}`, `  Consumer           : ${w.consumer}`, `  Action             : ${w.command}`].join("\n"))].join("\n") };
    }

    case "contain":
      if (isolated) return { out: "Host is already network-contained." };
      return { out: "Host network-contained. Only sensor traffic allowed.", contain: true };

    case "clear":
      return { out: "", clear: true };

    default:
      return { out: `rtr: unknown command '${verbRaw}'. Type 'help'.` };
  }
}
