/**
 * The normal background of a host — what `ps`, `sc query`, `schtasks /query`,
 * `reg query …\Run` and a WMI-subscription check show on a machine BEFORE you
 * look for the attacker. A real triage is "what here is not normal?"; an RTR shell
 * that lists only the three attack processes answers the question for you.
 *
 * Everything is deterministic from the host name + OS (seeded, never random), so
 * the same host shows the same PIDs on every render, and PIDs are multiples of 4
 * like real Windows PIDs. Session-0 system processes that the investigation's own
 * process tree already contains (e.g. services.exe as the parent of PSEXESVC) are
 * NOT duplicated — the tree and `ps` agree on one PID per process. The same seeding
 * is exposed as baselinePid() so fromLiveStory can root a service process at the
 * very services.exe PID that `ps` will print.
 */
import type { EdrInvestigation, EdrProcess } from "./investigations";

function fnv(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; }
  return h >>> 0;
}
/** Deterministic multiple-of-4 PID in [lo, hi) for a host + slot. */
function pid4(host: string, slot: string, lo: number, hi: number): number {
  const span = Math.floor((hi - lo) / 4);
  return lo + (fnv(`${host.toLowerCase()}|${slot}`) % span) * 4;
}

export function isServerHost(host: { name: string; os?: string }): boolean {
  return /server/i.test(host.os ?? "") || /(^|-)(SRV|SVR|DC|SQL|FS|BKP|EXCH|APP|WEB|DB|ESX|HV)(-|\d|$)/i.test(host.name);
}
export function isLinuxHost(host: { os?: string }): boolean {
  return /linux|ubuntu|debian|centos|rhel|macos|darwin/i.test(host.os ?? "");
}

const SYS = "NT AUTHORITY\\SYSTEM";
const LS = "NT AUTHORITY\\LOCAL SERVICE";
const NS = "NT AUTHORITY\\NETWORK SERVICE";

interface Slot { key: string; name: string; parent?: string; user: string; path: string; cmdline: string; lo: number; hi: number }

function windowsSlots(server: boolean, edrAgent: { name: string; path: string } | null): Slot[] {
  const s32 = "C:\\Windows\\System32\\";
  const slots: Slot[] = [
    { key: "smss", name: "smss.exe", parent: "System", user: SYS, path: `${s32}smss.exe`, cmdline: "\\SystemRoot\\System32\\smss.exe", lo: 300, hi: 420 },
    { key: "csrss", name: "csrss.exe", user: SYS, path: `${s32}csrss.exe`, cmdline: "%SystemRoot%\\system32\\csrss.exe ObjectDirectory=\\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1", lo: 420, hi: 520 },
    { key: "wininit", name: "wininit.exe", user: SYS, path: `${s32}wininit.exe`, cmdline: "wininit.exe", lo: 520, hi: 600 },
    { key: "services", name: "services.exe", parent: "wininit.exe", user: SYS, path: `${s32}services.exe`, cmdline: `${s32}services.exe`, lo: 600, hi: 700 },
    { key: "lsass", name: "lsass.exe", parent: "wininit.exe", user: SYS, path: `${s32}lsass.exe`, cmdline: `${s32}lsass.exe`, lo: 700, hi: 800 },
    { key: "winlogon", name: "winlogon.exe", user: SYS, path: `${s32}winlogon.exe`, cmdline: "winlogon.exe", lo: 800, hi: 900 },
    { key: "svc-dcom", name: "svchost.exe", parent: "services.exe", user: SYS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k DcomLaunch -p`, lo: 900, hi: 1000 },
    { key: "svc-rpcss", name: "svchost.exe", parent: "services.exe", user: NS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k RPCSS -p`, lo: 1000, hi: 1100 },
    { key: "svc-lsnr", name: "svchost.exe", parent: "services.exe", user: LS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k LocalServiceNetworkRestricted -p`, lo: 1100, hi: 1300 },
    { key: "svc-netsvcs", name: "svchost.exe", parent: "services.exe", user: SYS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k netsvcs -p`, lo: 1300, hi: 1500 },
    { key: "svc-ns", name: "svchost.exe", parent: "services.exe", user: NS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k NetworkService -p`, lo: 1500, hi: 1700 },
    { key: "svc-ls", name: "svchost.exe", parent: "services.exe", user: LS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k LocalService -p`, lo: 1700, hi: 1900 },
    { key: "svc-lsns", name: "svchost.exe", parent: "services.exe", user: LS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k LocalServiceNoNetwork -p`, lo: 1900, hi: 2100 },
    { key: "spoolsv", name: "spoolsv.exe", parent: "services.exe", user: SYS, path: `${s32}spoolsv.exe`, cmdline: `${s32}spoolsv.exe`, lo: 2100, hi: 2300 },
    { key: "msmpeng", name: "MsMpEng.exe", parent: "services.exe", user: SYS, path: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe", cmdline: "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe\"", lo: 2300, hi: 2600 },
    { key: "wmiprvse", name: "WmiPrvSE.exe", parent: "svc-dcom", user: NS, path: `${s32}wbem\\WmiPrvSE.exe`, cmdline: `${s32}wbem\\wmiprvse.exe -secured -Embedding`, lo: 2600, hi: 2900 },
  ];
  if (edrAgent) slots.push({ key: "edr", name: edrAgent.name, parent: "services.exe", user: SYS, path: edrAgent.path, cmdline: `"${edrAgent.path}"`, lo: 2900, hi: 3200 });
  if (server) {
    slots.push(
      { key: "svc-winrm", name: "svchost.exe", parent: "services.exe", user: NS, path: `${s32}svchost.exe`, cmdline: `${s32}svchost.exe -k NetworkService -p -s WinRM`, lo: 3200, hi: 3400 },
      { key: "dfssvc", name: "dfssvc.exe", parent: "services.exe", user: SYS, path: `${s32}dfssvc.exe`, cmdline: `${s32}dfssvc.exe`, lo: 3400, hi: 3600 },
    );
  } else {
    slots.push(
      { key: "dwm", name: "dwm.exe", parent: "winlogon.exe", user: "Window Manager\\DWM-1", path: `${s32}dwm.exe`, cmdline: "\"dwm.exe\"", lo: 3200, hi: 3400 },
      { key: "searchidx", name: "SearchIndexer.exe", parent: "services.exe", user: SYS, path: `${s32}SearchIndexer.exe`, cmdline: `${s32}SearchIndexer.exe /Embedding`, lo: 3400, hi: 3600 },
    );
  }
  return slots;
}

/** Which EDR sensor is on the host, from the vendors the case's telemetry came from. */
export function edrAgentFor(vendors: string[]): { name: string; path: string; service: string; display: string } | null {
  const v = vendors.join(" ").toLowerCase();
  if (v.includes("crowdstrike")) return { name: "CSFalconService.exe", path: "C:\\Program Files\\CrowdStrike\\CSFalconService.exe", service: "CSFalconService", display: "CrowdStrike Falcon Sensor Service" };
  if (v.includes("sentinelone")) return { name: "SentinelAgent.exe", path: "C:\\Program Files\\SentinelOne\\Sentinel Agent 24.1.2.6\\SentinelAgent.exe", service: "SentinelAgent", display: "Sentinel Agent" };
  if (v.includes("defender for endpoint")) return { name: "MsSense.exe", path: "C:\\Program Files\\Windows Defender Advanced Threat Protection\\MsSense.exe", service: "Sense", display: "Windows Defender Advanced Threat Protection Service" };
  return null;
}

/** The PID `ps` prints for a named session-0 system process on this host. */
export function baselinePid(hostName: string, name: string, knownPids?: Record<string, number>): number | undefined {
  const n = name.toLowerCase();
  if (knownPids?.[n] != null) return knownPids[n];
  if (n === "system") return 4;
  const slot = windowsSlots(true, null).find(s => s.name.toLowerCase() === n && s.name !== "svchost.exe");
  return slot ? pid4(hostName, slot.key, slot.lo, slot.hi) : undefined;
}

function bp(name: string, pid: number, ppid: number, user: string, path: string, cmdline: string): EdrProcess {
  return { pid, ppid, name, cmdline, user, path, signed: true, startedAt: "—", verdict: "benign" };
}

/**
 * The host's normal background processes, minus anything the investigation's own
 * tree already shows (so one process = one PID across tree and shell).
 */
export function buildHostBaseline(inv: Pick<EdrInvestigation, "host" | "processes" | "knownPids" | "edrAgent">): EdrProcess[] {
  const host = inv.host.name;
  const have = new Set(inv.processes.map(p => p.name.toLowerCase()));
  const used = new Set(inv.processes.map(p => p.pid));
  const out: EdrProcess[] = [];
  const take = (p: EdrProcess) => { while (used.has(p.pid)) p.pid += 4; used.add(p.pid); out.push(p); };

  if (isLinuxHost(inv.host)) {
    const nix: [string, string, string][] = [
      ["systemd", "/sbin/init", "/sbin/init splash"], ["kthreadd", "[kthreadd]", "[kthreadd]"],
      ["systemd-journald", "/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"],
      ["systemd-udevd", "/lib/systemd/systemd-udevd", "/lib/systemd/systemd-udevd"],
      ["rsyslogd", "/usr/sbin/rsyslogd", "/usr/sbin/rsyslogd -n -iNONE"], ["cron", "/usr/sbin/cron", "/usr/sbin/cron -f -P"],
      ["sshd", "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"],
      ["systemd-resolved", "/lib/systemd/systemd-resolved", "/lib/systemd/systemd-resolved"],
      ["falcon-sensor", "/opt/CrowdStrike/falcon-sensor", "/opt/CrowdStrike/falcon-sensor"],
    ];
    nix.forEach(([name, path, cmd], i) => {
      if (have.has(name)) return;
      const pid = name === "systemd" ? 1 : name === "kthreadd" ? 2 : 300 + (fnv(`${host}|${name}`) % 900) + i;
      take({ ...bp(name, pid, name === "systemd" || name === "kthreadd" ? 0 : 1, "root", path, cmd) });
    });
    return out;
  }

  const agent = inv.edrAgent ? { name: inv.edrAgent.name, path: inv.edrAgent.path } : null;
  const slots = windowsSlots(isServerHost(inv.host), agent);
  const pidOf = new Map<string, number>();   // slot key / process name → pid
  for (const p of inv.processes) pidOf.set(p.name.toLowerCase(), p.pid);
  if (!have.has("system")) take(bp("System", 4, 0, SYS, "System", "System"));
  pidOf.set("system", 4);
  for (const s of slots) {
    const lname = s.name.toLowerCase();
    const singleton = s.name !== "svchost.exe";
    const pid = singleton ? (inv.knownPids?.[lname] ?? pid4(host, s.key, s.lo, s.hi)) : pid4(host, s.key, s.lo, s.hi);
    if (singleton && have.has(lname)) { pidOf.set(s.key, pidOf.get(lname)!); continue; }
    const parentPid = s.parent
      ? (pidOf.get(s.parent.toLowerCase()) ?? pidOf.get(s.parent) ?? 0)
      // smss spawns csrss / wininit / winlogon then exits — their PPID names a dead PID.
      : pid4(host, `${s.key}-smss-child`, 300, 420);
    const proc = bp(s.name, pid, parentPid, s.user, s.path, s.cmdline);
    take(proc);
    pidOf.set(s.key, proc.pid);
    if (singleton) pidOf.set(lname, proc.pid);
  }
  return out;
}

// ─── Persistence baselines (benign entries every host has) ──────────────────────

export interface RunKeyEntry { key: string; name: string; type: string; data: string; malicious?: boolean }
export interface TaskEntry { name: string; next: string; status: string; action?: string; author?: string; malicious?: boolean }
export interface ServiceEntry { name: string; display: string; state: "RUNNING" | "STOPPED"; start: string; binPath: string; account: string; malicious?: boolean }
export interface WmiEntry { filter: string; query: string; consumer: string; command: string; malicious?: boolean }

export const RUN_HKLM = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
export const RUN_HKCU = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

export function baselineRunKeys(host: EdrInvestigation["host"]): RunKeyEntry[] {
  const out: RunKeyEntry[] = [
    { key: RUN_HKLM, name: "SecurityHealth", type: "REG_EXPAND_SZ", data: "%windir%\\system32\\SecurityHealthSystray.exe" },
  ];
  if (!isServerHost(host)) {
    out.push({ key: RUN_HKLM, name: "RtkAudUService", type: "REG_SZ", data: "\"C:\\Windows\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_3d4a0a1c\\RtkAudUService64.exe\" -background" });
    const u = host.user.split("\\").pop() || "user";
    out.push({ key: RUN_HKCU, name: "OneDrive", type: "REG_SZ", data: `"C:\\Users\\${u}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background` });
  } else {
    out.push({ key: RUN_HKLM, name: "VMware User Process", type: "REG_SZ", data: "\"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe\" -n vmusr" });
  }
  return out;
}

export function baselineTasks(host: EdrInvestigation["host"]): TaskEntry[] {
  const day = 1 + (fnv(host.name) % 27);
  const d = `${String(day).padStart(2, "0")}/09/2026`;
  const out: TaskEntry[] = [
    { name: "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", next: "N/A", status: "Ready" },
    { name: "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan", next: `${d} 03:00:00`, status: "Ready" },
    { name: "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start", next: `${d} 01:17:00`, status: "Ready" },
    { name: "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan", next: `${d} 04:52:00`, status: "Ready" },
  ];
  if (isServerHost(host)) out.push({ name: "\\Microsoft\\Windows\\Server Manager\\ServerManager", next: "N/A", status: "Ready" });
  else out.push(
    { name: "\\MicrosoftEdgeUpdateTaskMachineUA", next: `${d} 10:42:00`, status: "Ready" },
    { name: "\\Microsoft\\Office\\Office Automatic Updates 2.0", next: `${d} 07:30:00`, status: "Ready" },
  );
  return out;
}

export function baselineServices(host: EdrInvestigation["host"], agent: EdrInvestigation["edrAgent"]): ServiceEntry[] {
  const s32 = "C:\\Windows\\system32\\";
  const out: ServiceEntry[] = [
    { name: "EventLog", display: "Windows Event Log", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k LocalServiceNetworkRestricted -p`, account: "NT AUTHORITY\\LocalService" },
    { name: "Dnscache", display: "DNS Client", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k NetworkService -p`, account: "NT AUTHORITY\\NetworkService" },
    { name: "LanmanServer", display: "Server", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k netsvcs -p`, account: "LocalSystem" },
    { name: "LanmanWorkstation", display: "Workstation", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k NetworkService -p`, account: "NT AUTHORITY\\NetworkService" },
    { name: "RpcSs", display: "Remote Procedure Call (RPC)", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k rpcss -p`, account: "NT AUTHORITY\\NetworkService" },
    { name: "Schedule", display: "Task Scheduler", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k netsvcs -p`, account: "LocalSystem" },
    { name: "W32Time", display: "Windows Time", state: "RUNNING", start: "DEMAND_START", binPath: `${s32}svchost.exe -k LocalService`, account: "NT AUTHORITY\\LocalService" },
    { name: "WinDefend", display: "Microsoft Defender Antivirus Service", state: "RUNNING", start: "AUTO_START", binPath: "\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe\"", account: "LocalSystem" },
    { name: "wuauserv", display: "Windows Update", state: "STOPPED", start: "DEMAND_START", binPath: `${s32}svchost.exe -k netsvcs -p`, account: "LocalSystem" },
    { name: "BITS", display: "Background Intelligent Transfer Service", state: "STOPPED", start: "DEMAND_START", binPath: `${s32}svchost.exe -k netsvcs -p`, account: "LocalSystem" },
  ];
  if (agent) out.push({ name: agent.service, display: agent.display, state: "RUNNING", start: "AUTO_START", binPath: `"${agent.path}"`, account: "LocalSystem" });
  if (isServerHost(host)) out.push({ name: "WinRM", display: "Windows Remote Management (WS-Management)", state: "RUNNING", start: "AUTO_START", binPath: `${s32}svchost.exe -k NetworkService -p`, account: "NT AUTHORITY\\NetworkService" });
  else out.push({ name: "Spooler", display: "Print Spooler", state: "RUNNING", start: "AUTO_START", binPath: `${s32}spoolsv.exe`, account: "LocalSystem" });
  return out;
}

/** Every Windows host has the one built-in WMI subscription (SCM event log filter). */
export function baselineWmi(): WmiEntry[] {
  return [{
    filter: "SCM Event Log Filter",
    query: "select * from MSFT_SCMEventLogEvent",
    consumer: "SCM Event Log Consumer (NTEventLogEventConsumer)",
    command: "(writes to the System event log — built-in, benign)",
  }];
}
