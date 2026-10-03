/**
 * Helpers shared by the CrowdStrike and SentinelOne native modules (not a module itself).
 *
 * Everything here works on the vendor-neutral facts from ./edr-normalize (edrFacts) and only
 * adds DETERMINISTIC filler (ids, times, host IP) via ctx. Entity ids are seeded from the entity
 * (company + host + process), never from the event, so one story correlates across events:
 * the process a ProcessRollup2 / Process Creation creates gets the same Falcon UPID / S1 uid that
 * its own DNS / network / file events carry as ContextProcessId / src.process.uid.
 *
 * Workarounds for edrFacts read gaps (edr-normalize.ts is shared and not edited here):
 *  - MDE rows whose FolderPath already ends in the file name come out as "…\X.exe\X.exe"
 *    → {@link fixPath} drops the duplicated last segment.
 *  - `crowdstrike.remote_address` / `crowdstrike.remote_port` (lower-case legacy keys) are not read
 *    → {@link netFacts} falls back to them.
 *  - os defaults to "Win" when no platform key exists (EKS nodes, macOS app bundles)
 *    → {@link osOf} re-derives it from paths / unix-only image names.
 *  - every network event is marked "outbound"; an event whose LOCAL ip is public while the remote
 *    side is private/absent is really an inbound accept (e.g. RDP from the internet)
 *    → {@link netFacts} flips it.
 *  - the registry VALUE NAME (TelemetryEvent.registry.key / raw "registry.value" when the data is in
 *    "registry.data.strings") is not exposed → {@link registryFacts}.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx } from "../types";
import type { EdrFacts, EdrProc } from "./edr-normalize";
import { procKey, procPid, accountSid, osImagePath, type ProcScope } from "./_proc-identity";

export type { ProcScope } from "./_proc-identity";
export { inferredFileWriter } from "./_proc-identity";

export const baseName = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
const lc = (s?: string) => (s ?? "").toLowerCase();

/** Drop a duplicated trailing segment ("C:\a\X.exe\X.exe" → "C:\a\X.exe"). */
export function fixPath(p?: string): string | undefined {
  if (!p) return p;
  const m = /^(.*)([\\/])([^\\/]+)\2\3$/.exec(p);
  return m ? `${m[1]}${m[2]}${m[3]}` : p;
}

// ── OS / host ────────────────────────────────────────────────────────────────

const MAC_NAMES = new Set(["osascript", "finder", "launchd", "terminal", "google chrome"]);
const MAC_PATH = /^\/(Applications|Users|Volumes|Library|System|private)\//;

export function osOf(f: EdrFacts, ev: TelemetryEvent): "Win" | "Lin" | "Mac" {
  if (f.os !== "Win") return f.os;
  const paths = [f.proc.path, f.file.path, f.parent.path, String(ev.raw?.["crowdstrike.FilePath"] ?? "")].filter(Boolean) as string[];
  if (paths.some(p => MAC_PATH.test(p))) return "Mac";
  if (MAC_NAMES.has(lc(f.proc.name)) || MAC_NAMES.has(lc(f.parent.name))) return "Mac";
  if (paths.some(p => p.startsWith("/"))) return "Lin";
  if (paths.some(p => /^[A-Za-z]:\\|^\\Device\\|^\\\\/.test(p))) return "Win";
  // A Windows image always carries an extension; bash / curl / node / xmrig do not.
  if (f.proc.name && !f.proc.name.includes(".")) return "Lin";
  return "Win";
}

export function isPrivate(ip?: string): boolean {
  if (!ip) return false;
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.)/.test(ip);
}
export const isIPv4 = (ip?: string) => !!ip && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip);

/** The sensor host's own IPv4: authored when known, else a stable private address per host. */
export function hostIpOf(ctx: NativeCtx, f: EdrFacts, host: string): string {
  if (f.hostIp && isIPv4(f.hostIp) && isPrivate(f.hostIp)) return f.hostIp;
  if (f.kind === "network" && isPrivate(f.net.localIp)) return f.net.localIp!;
  if (f.net.localIp && isPrivate(f.net.localIp) && f.kind !== "network") return f.net.localIp;
  const s = `${ctx.companyId}:${host}:ip`;
  return `10.${ctx.int(`${s}:b`, 10, 80)}.${ctx.int(`${s}:c`, 1, 250)}.${ctx.int(`${s}:d`, 10, 250)}`;
}
/** The company's egress (NAT) address as the vendor cloud sees it — one per company. */
/** The company's public egress — the SAME address the firewalls NAT to, so the EDR's
 * external_ip and the firewall's translated source correlate. */
export { egressIp } from "./firewall-shared";
export type HostRole = "workstation" | "laptop" | "server" | "dc";
export function hostRole(host: string): HostRole {
  const h = host.toUpperCase();
  if (/(^|-)DC\d*$|-DC\d+|DC0\d/.test(h)) return "dc";
  if (/^(SRV|SVR|PROD|DB|WEB|EKS|IP-|K8S|APP|BUILD|JUMP|FS|EXCH|SQL|VEEAM)|-SRV|SERVER|NODE/.test(h)) return "server";
  if (/^(LAP|LT|NB|MBP|MAC)/.test(h)) return "laptop";
  return "workstation";
}
export function companyDisplay(ctx: NativeCtx): string {
  const n = ctx.domain.split(".")[0].replace(/-.*/, "");
  return n.charAt(0).toUpperCase() + n.slice(1);
}

// ── deterministic id helpers ────────────────────────────────────────────────

/**
 * Hex string with better spread than chaining ctx.hex's 8-char blocks (whose FNV seeds differ only in the
 * last character and so come out visibly patterned): each block is seeded with the index FIRST.
 */
export function rhex(ctx: NativeCtx, seed: string, len: number): string {
  let s = "";
  for (let i = 0; s.length < len; i++) s += ctx.hex(`${i}|${seed}|${i * 7919}`, 8);
  return s.slice(0, len);
}
/** RFC 4122 v4-shaped UUID from {@link rhex}. */
export function ruuid(ctx: NativeCtx, seed: string): string {
  const h = rhex(ctx, seed, 32);
  const v = ((parseInt(h[16], 16) & 0x3) | 0x8).toString(16);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-${v}${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
/** n decimal digits from a seed (first digit never 0). */
export function digits(ctx: NativeCtx, seed: string, n: number): string {
  const h = rhex(ctx, seed, n);
  let out = "";
  for (let i = 0; i < n; i++) out += String(parseInt(h[i], 16) % 10);
  return out[0] === "0" ? `1${out.slice(1)}` : out;
}
export const secMs = (ms: number) => `${Math.floor(ms / 1000)}.${String(((ms % 1000) + 1000) % 1000).padStart(3, "0")}`;
export const iso = (ms: number) => new Date(ms).toISOString();
/** ISO with µs ("…:26.774519Z") — S1 Threats API style. */
export const isoMicro = (ctx: NativeCtx, ms: number, seed: string) => `${iso(ms).slice(0, -1)}${String(ctx.int(seed, 0, 999)).padStart(3, "0")}Z`;
/** ISO with ns ("…:31.885124513Z") — CrowdStrike Alerts API created/updated style. */
export const isoNano = (ctx: NativeCtx, ms: number, seed: string) => `${iso(ms).slice(0, -1)}${String(ctx.int(seed, 0, 999999)).padStart(6, "0")}Z`;

// ── users ───────────────────────────────────────────────────────────────────

export interface UserFacts { user?: string; domain: string; system: boolean; sid?: string; upn?: string; email?: string }
const SYSTEM_SIDS: Record<string, string> = { system: "S-1-5-18", "local service": "S-1-5-19", "network service": "S-1-5-20", "nt authority\\system": "S-1-5-18" };

/** The event's account: the story's authored SID when it has one (EdrFacts.sid), else the user's directory SID — one value per user in every product. */
export function userOf(ctx: NativeCtx, f: EdrFacts, os: "Win" | "Lin" | "Mac"): UserFacts {
  const user = f.user ?? (f.userEmail ? f.userEmail.split("@")[0] : undefined);
  const system = !!user && (lc(user) in SYSTEM_SIDS || lc(user) === "root");
  const domain = system && os === "Win" ? "NT AUTHORITY" : (f.userDomain ?? ctx.netbios);
  const sid = os !== "Win" || !user ? undefined : SYSTEM_SIDS[lc(user)] ?? f.sid ?? accountSid(ctx, user, f.userEmail);
  return { user, domain, system, sid, email: f.userEmail, upn: f.userEmail ?? (user && !system ? `${user}@${ctx.domain}` : undefined) };
}

// ── processes ───────────────────────────────────────────────────────────────

const SYS32 = "C:\\Windows\\System32\\";
/** Canonical install paths, used ONLY when the event names a well-known binary without any path. */
const CANONICAL: Record<string, string> = {
  "powershell.exe": `${SYS32}WindowsPowerShell\\v1.0\\powershell.exe`, "cmd.exe": `${SYS32}cmd.exe`,
  "rundll32.exe": `${SYS32}rundll32.exe`, "regsvr32.exe": `${SYS32}regsvr32.exe`, "mshta.exe": `${SYS32}mshta.exe`,
  "certutil.exe": `${SYS32}certutil.exe`, "wmic.exe": `${SYS32}wbem\\WMIC.exe`, "bitsadmin.exe": `${SYS32}bitsadmin.exe`,
  "schtasks.exe": `${SYS32}schtasks.exe`, "reg.exe": `${SYS32}reg.exe`, "net.exe": `${SYS32}net.exe`,
  "vssadmin.exe": `${SYS32}vssadmin.exe`, "ntdsutil.exe": `${SYS32}ntdsutil.exe`, "wscript.exe": `${SYS32}wscript.exe`,
  "cscript.exe": `${SYS32}cscript.exe`, "services.exe": `${SYS32}services.exe`, "explorer.exe": "C:\\Windows\\explorer.exe",
  "userinit.exe": `${SYS32}userinit.exe`, "wevtutil.exe": `${SYS32}wevtutil.exe`, "robocopy.exe": `${SYS32}Robocopy.exe`,
  "msiexec.exe": `${SYS32}msiexec.exe`, "curl.exe": `${SYS32}curl.exe`, "taskmgr.exe": `${SYS32}Taskmgr.exe`,
  "notepad.exe": `${SYS32}notepad.exe`, "calc.exe": `${SYS32}calc.exe`, "fodhelper.exe": `${SYS32}fodhelper.exe`,
  "computerdefaults.exe": `${SYS32}ComputerDefaults.exe`, "wmiprvse.exe": `${SYS32}wbem\\WmiPrvSE.exe`, "wuauclt.exe": `${SYS32}wuauclt.exe`,
  "winword.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "excel.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
  "outlook.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
  "powerpnt.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
  "chrome.exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "msedge.exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
};
/** Image path: authored path, else the first token of the command line when it is a full path, else canonical. */
export function imagePath(p: EdrProc): string | undefined {
  const authored = fixPath(p.path);
  if (authored && /[\\/]/.test(authored)) return authored;
  const cmd = p.cmdline?.trim();
  if (cmd) {
    const m = /^"([^"]+)"|^(\S+)/.exec(cmd);
    const tok = m?.[1] ?? m?.[2];
    if (tok && (/^[A-Za-z]:\\/.test(tok) || tok.startsWith("/")) && (!p.name || lc(baseName(tok)) === lc(p.name))) return tok;
  }
  return p.name ? CANONICAL[lc(p.name)] ?? osImagePath(p.name) : undefined;
}
export const procName = (p: EdrProc) => p.name ?? baseName(fixPath(p.path));

/** Windows device-path form used by Falcon ("C:\X" → "\Device\HarddiskVolume3\X"); unix paths unchanged. */
export function ntDevicePath(p: string): string {
  const m = /^([A-Za-z]):\\(.*)$/.exec(p);
  if (!m) return p;
  // C: is the system volume (HarddiskVolume3); another letter (a USB drive at E:) is a later volume.
  const vol = 3 + Math.max(0, m[1].toUpperCase().charCodeAt(0) - 67);
  return `\\Device\\HarddiskVolume${vol}\\${m[2]}`;
}
/** Drive-letter form used by SentinelOne telemetry ("\Device\HarddiskVolume3\X" → "C:\X"). */
export function drivePath(p: string): string {
  const m = /^\\Device\\HarddiskVolume\d+\\(.*)$/.exec(p);
  return m ? `C:\\${m[1]}` : p;
}

/**
 * OS pid of a process instance — derived from its instance key (./_proc-identity), never from the
 * authored pid, which the corpus does not number consistently across a process's own row, its
 * children and its actions. Windows pids are multiples of 4.
 */
export function pidOf(ctx: NativeCtx, s: ProcScope, p: EdrProc): number {
  return procPid(ctx, s, p) ?? (s.os === "Win" ? 4 : 1);
}
/** Seed identifying one process instance (company + host + image + lifetime scope). */
export function procSeed(ctx: NativeCtx, s: ProcScope, p: EdrProc): string {
  return procKey(ctx, s, p) ?? `${ctx.companyId}:${lc(s.host)}:proc:?`;
}

// Processes that start a new chain (their children are storyline roots).
export const SHELLS = new Set(["explorer.exe", "services.exe", "svchost.exe", "userinit.exe", "winlogon.exe", "wininit.exe", "smss.exe",
  "launchd", "finder", "systemd", "init", "cron", "sshd", "terminal", "runner.worker", "wmiprvse.exe"]);

// ── classification sets used by both modules' renderers and use cases ───────

export const OFFICE = ["WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "MSACCESS.EXE", "MSPUB.EXE", "VISIO.EXE", "ONENOTE.EXE"];
export const SCRIPT_HOSTS = ["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"];
export const LOLBINS = ["certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe", "curl.exe", "wmic.exe", "installutil.exe", "msbuild.exe", "odbcconf.exe", "esentutl.exe", "expand.exe", "finger.exe", "ftp.exe"];
/** Case-insensitive alternation for regex use cases. */
export const alt = (xs: string[]) => xs.map(x => x.replace(/[.$^*+?()[\]{}|\\]/g, "\\$&")).join("|");

/** Private/reserved IPv4 ranges for "external destination" conditions. */
export const PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"];

// ── network / registry fact fixes ───────────────────────────────────────────

export interface NetFacts { inbound: boolean; remoteIp?: string; remotePort?: number; localIp?: string; localPort?: number; protocol: "tcp" | "udp"; domain?: string; url?: string }
export function netFacts(f: EdrFacts, ev: TelemetryEvent): NetFacts {
  const r = ev.raw ?? {};
  let remoteIp = f.net.remoteIp ?? (r["crowdstrike.remote_address"] as string | undefined);
  let remotePort = f.net.remotePort ?? (r["crowdstrike.remote_port"] !== undefined ? Number(r["crowdstrike.remote_port"]) : undefined);
  let localIp = f.net.localIp;
  let localPort = f.net.localPort;
  // edrFacts now marks authored inbound accepts itself (remote = public source).
  let inbound = f.net.direction === "inbound";
  if (!inbound && localIp && !isPrivate(localIp) && isIPv4(localIp) && (!remoteIp || isPrivate(remoteIp))) {
    // Authored as src=<internet peer> dst=<this host>: an inbound accept.
    inbound = true;
    [remoteIp, localIp] = [localIp, remoteIp];
    [remotePort, localPort] = [localPort, remotePort];
  }
  const proto = lc(f.net.protocol ?? String(r["network.protocol"] ?? r["network.transport"] ?? ""));
  const port = inbound ? localPort : remotePort;
  const protocol: "tcp" | "udp" = proto.includes("udp") || (!proto && (port === 53 || port === 123 || port === 161)) ? "udp" : "tcp";
  return { inbound, remoteIp, remotePort, localIp, localPort, protocol, domain: f.net.domain, url: f.net.url };
}

export interface RegFacts { hive: "HKCU" | "HKLM" | "HKU" | "HKCR"; keyPath: string; valueName: string; data?: string }
export function registryFacts(f: EdrFacts, ev: TelemetryEvent): RegFacts | null {
  const path = f.registry.path;
  if (!path) return null;
  const r = ev.raw ?? {};
  const norm = path.replace(/^HKEY_CURRENT_USER/i, "HKCU").replace(/^HKEY_LOCAL_MACHINE/i, "HKLM").replace(/^HKEY_USERS/i, "HKU");
  const hive = (/^(HKCU|HKLM|HKU|HKCR)\\/i.exec(norm)?.[1]?.toUpperCase() ?? "HKLM") as RegFacts["hive"];
  const rest = norm.replace(/^(HKCU|HKLM|HKU|HKCR)\\/i, "");
  let valueName = ev.registry?.key ?? (r["registry.data.strings"] !== undefined ? (r["registry.value"] as string | undefined) : undefined) ?? (r["registry.key"] as string | undefined);
  let keyPath = rest;
  const data = (r["registry.data.strings"] as string | undefined) ?? ev.registry?.value ?? f.registry.value;
  if (!valueName || valueName === data) {
    // Path authored as "<key>\<value name>" (e.g. …\Run\SystemBackupSvc).
    if (/\\(Run|RunOnce)$/i.test(rest)) valueName = "(Default)";
    else { valueName = rest.split("\\").pop()!; keyPath = rest.split("\\").slice(0, -1).join("\\"); }
  } else if (rest.toLowerCase().endsWith(`\\${valueName.toLowerCase()}`)) {
    keyPath = rest.slice(0, -(valueName.length + 1));
  }
  return { hive, keyPath, valueName, data: data === valueName ? undefined : data };
}

/** Is the image in a user-writable location (Downloads, Desktop, AppData, Temp, Public, ProgramData, /tmp …)? */
export const USER_WRITABLE_RE = "(\\\\Users\\\\[^\\\\]+\\\\(Downloads|Desktop|Documents|AppData|Music|Pictures|Videos)\\\\|\\\\Users\\\\Public\\\\|\\\\ProgramData\\\\|\\\\Windows\\\\Temp\\\\|\\\\Temp\\\\|\\\\PerfLogs\\\\|^/tmp/|^/var/tmp/|^/dev/shm/|^/Users/[^/]+/Downloads/|^/Volumes/)";
export const DOWNLOADS_PUBLIC_RE = "(\\\\Users\\\\[^\\\\]+\\\\Downloads\\\\|\\\\Users\\\\Public\\\\|^/Users/[^/]+/Downloads/)";

/**
 * An authored detection name another vendor would never emit: Microsoft Defender's
 * "Trojan:Win32/Wacatac.B!ml" naming, or a scenario placeholder ("known_malware_family",
 * "Suspicious activity", "Malware.Generic"). Falcon / SentinelOne records get their own
 * product wording instead.
 */
export function foreignDetectionName(name?: string): boolean {
  if (!name) return true;
  return /^[A-Za-z]+:[A-Za-z0-9]+\/[\w.!-]+$/.test(name)
    || /^(known_malware(_family)?|attacker_methodology|suspicious[_ ]activity|malware\.generic|generic|unknown)$/i.test(name.trim());
}
