/**
 * One process instance → one identity, for every EDR / host-telemetry module (not a module itself).
 *
 * Rendering is per event (stateless), and the authored corpus does not number processes
 * consistently: the same USB_Backup_Tool.exe is pid 7712 on its process event and 4216 on the
 * registry write it made; an installer has a pid on its own row and none on the scheduled task it
 * registered. A UPID / S1 uid / MDE ProcessUniqueId seeded from the authored pid therefore broke
 * every parent → child and actor → action pivot. The identity is instead the INSTANCE KEY below,
 * and the OS pid is derived from it — so a process's own record, its children's parent fields, its
 * DNS / network / file / registry actions and the alert about it all carry the same ids.
 *
 * Instance key = company + host + image name + lifetime scope:
 *   - boot-scoped system singletons (services.exe, lsass.exe, svchost.exe, systemd …): one per host;
 *   - session-scoped shells (explorer.exe, userinit.exe, sihost.exe …): one per host + user + day —
 *     one user's Explorer never parents another user's process, or the same user's next-day work;
 *   - everything else: one per host + incident when the event belongs to one (a clipper that runs for
 *     two days before the alert is still ONE process), else one per host + day.
 * Known trade-off: two instances of the same image on one host on one day collapse into one id
 * (one corpus story runs powershell.exe twice from cmd.exe); every reference stays self-consistent.
 * The exception is an image the story shows as its own parent (powershell.exe → powershell.exe):
 * the story pass gives the child a distinct `inst` so no process is ever listed as its own parent.
 *
 * Windows pids / tids are multiples of 4 (the kernel allocates handle-table indexes in steps of 4);
 * Linux / macOS pids are plain integers.
 */
import type { NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { edrFacts, threadOf, withThread, type EdrFacts, type EndpointThread, type ThreadProc } from "./edr-normalize";

export type Os = "Win" | "Lin" | "Mac";
/** Where and when a process reference is made (the host, its OS, the event time, the event's user and incident). */
export interface ProcScope { host: string; os: Os; timeMs: number; user?: string; incident?: string }
/**
 * Whatever an event says about a process. `inst` tells apart two instances of one image that the
 * story shows as parent and child (powershell.exe spawning powershell.exe) — see {@link threadEndpointStory}.
 */
export interface ProcRef { name?: string; path?: string; cmdline?: string; inst?: string }

const lc = (s?: string) => (s ?? "").toLowerCase();
const baseOf = (p?: string) => (p ? p.split(/[\\/]/).pop() : undefined);
/** "C:\a\X.exe\X.exe" → "C:\a\X.exe" (a legacy FolderPath that already held the file name). */
const undouble = (p?: string) => {
  if (!p) return p;
  const m = /^(.*)([\\/])([^\\/]+)\2\3$/i.exec(p);
  return m ? `${m[1]}${m[2]}${m[3]}` : p;
};

/** The image name that identifies a process: name, else the path's file name, else the command line's first token. */
export function identityName(p: ProcRef): string | undefined {
  if (p.name) return p.name;
  const fromPath = baseOf(undouble(p.path));
  if (fromPath) return fromPath;
  const tok = p.cmdline?.trim().match(/^"([^"]+)"|^(\S+)/);
  return tok ? baseOf(tok[1] ?? tok[2]) : undefined;
}

/** One instance per host for the life of the boot. */
const SINGLETON = new Set(["system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
  "lsaiso.exe", "svchost.exe", "spoolsv.exe", "msmpeng.exe", "dns.exe", "sysmon64.exe", "sysmon.exe", "wmiprvse.exe",
  "systemd", "init", "sshd", "cron", "crond", "dockerd", "containerd", "kubelet", "auditd", "rsyslogd", "launchd", "kernel_task"]);
/** One instance per user logon session. */
const SESSION = new Set(["explorer.exe", "userinit.exe", "sihost.exe", "taskhostw.exe", "runtimebroker.exe", "dwm.exe", "ctfmon.exe",
  "finder", "dock", "loginwindow", "gnome-shell"]);

const dayOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);

/** The instance key every id of this process is seeded from (undefined when the event names no image at all). */
export function procKey(ctx: NativeCtx, s: ProcScope, p: ProcRef): string | undefined {
  const name = lc(identityName(p));
  if (!name) return undefined;
  const host = lc(s.host);
  if (SINGLETON.has(name)) return `${ctx.companyId}:${host}:proc:boot:${name}`;
  if (SESSION.has(name)) return `${ctx.companyId}:${host}:proc:session:${lc(s.user) || "-"}:${dayOf(s.timeMs)}:${name}`;
  return `${ctx.companyId}:${host}:proc:${s.incident ? `inc:${s.incident}` : dayOf(s.timeMs)}:${name}${p.inst ? `:${p.inst}` : ""}`;
}

/** Round to the Windows allocation granularity (multiples of 4, never 0). */
export const win4 = (n: number) => Math.max(4, n - (n % 4));

/** The OS pid of the process — derived from its instance key, so every reference agrees. */
export function procPid(ctx: NativeCtx, s: ProcScope, p: ProcRef): number | undefined {
  const key = procKey(ctx, s, p);
  if (!key) return undefined;
  const name = lc(identityName(p));
  // The numbering follows the image itself (an .exe is a Windows process), never the event's OS
  // guess — which varies between events of one host when some carry no platform hint.
  const windows = name === "system" || name === "registry" || (/\.(exe|com|scr)$/i.test(name) && !(p.path ?? "").startsWith("/"));
  if (windows) {
    if (name === "system") return 4;
    if (name === "registry") return 92;
    return SINGLETON.has(name) ? ctx.int(`${key}:pid`, 100, 320) * 4 : ctx.int(`${key}:pid`, 250, 5000) * 4;
  }
  if (name === "systemd" || name === "init" || name === "launchd") return 1;
  return SINGLETON.has(name) ? ctx.int(`${key}:pid`, 300, 2000) : ctx.int(`${key}:pid`, 1000, 65000);
}

/**
 * The process that wrote a file when the event names none: a file a user drops into a profile
 * folder (Desktop, Documents …) by hand — a copy from a USB stick, a drag-and-drop out of a ZIP —
 * is written by that user's Explorer. Downloads / AppData / Temp writes are not inferred (a browser,
 * an installer or a script writes there, and the event would have to say which).
 */
export function inferredFileWriter(path: string | undefined, os: Os, systemUser: boolean): ProcRef | undefined {
  if (!path || os !== "Win" || systemUser) return undefined;
  if (/^[A-Za-z]:\\Users\\(?!Public\\)[^\\]+\\(Desktop|Documents|Pictures|Music|Videos)\\/i.test(path)) return { name: "explorer.exe", path: "C:\\Windows\\explorer.exe" };
  // A copy onto a removable drive (E:\…) by a user is Explorer's write too.
  if (/^[E-Ze-z]:\\/.test(path)) return { name: "explorer.exe", path: "C:\\Windows\\explorer.exe" };
  return undefined;
}

/** Command lines the OS itself starts these images with — the only parent command lines that can be stated without the event saying so. */
export const OS_COMMAND_LINE: Record<string, string> = {
  "explorer.exe": "C:\\WINDOWS\\Explorer.EXE",
  "userinit.exe": "C:\\WINDOWS\\system32\\userinit.exe",
  "services.exe": "C:\\WINDOWS\\system32\\services.exe",
  "wininit.exe": "wininit.exe",
  "winlogon.exe": "winlogon.exe",
  "lsass.exe": "C:\\WINDOWS\\system32\\lsass.exe",
};
/** The fixed parent of an OS image (explorer.exe is started by userinit.exe, services.exe by wininit.exe …). */
export const OS_PARENT: Record<string, string> = {
  "explorer.exe": "userinit.exe", "userinit.exe": "winlogon.exe", "services.exe": "wininit.exe", "lsass.exe": "wininit.exe",
  "svchost.exe": "services.exe", "spoolsv.exe": "services.exe", "msmpeng.exe": "services.exe", "wmiprvse.exe": "svchost.exe",
};
/** Service-hosted images and the account they run as (a child of WmiPrvSE is not started BY the user's account). */
export const SERVICE_ACCOUNT: Record<string, string> = {
  "services.exe": "NT AUTHORITY\\SYSTEM", "svchost.exe": "NT AUTHORITY\\SYSTEM", "spoolsv.exe": "NT AUTHORITY\\SYSTEM",
  "msmpeng.exe": "NT AUTHORITY\\SYSTEM", "wininit.exe": "NT AUTHORITY\\SYSTEM", "winlogon.exe": "NT AUTHORITY\\SYSTEM",
  "smss.exe": "NT AUTHORITY\\SYSTEM", "lsass.exe": "NT AUTHORITY\\SYSTEM", "psexesvc.exe": "NT AUTHORITY\\SYSTEM",
  "wmiprvse.exe": "NT AUTHORITY\\NETWORK SERVICE",
};

// ── Well-known images ───────────────────────────────────────────────────────

const S32 = "C:\\Windows\\System32\\";
const OFFICE16 = "C:\\Program Files\\Microsoft Office\\root\\Office16\\";
/** Install path of a well-known image (lower-case name → full path) — used only when an event names the binary without a path. */
export const OS_IMAGE_PATH: Record<string, string> = {
  "powershell.exe": `${S32}WindowsPowerShell\\v1.0\\powershell.exe`, "pwsh.exe": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
  "wmic.exe": `${S32}wbem\\WMIC.exe`, "wmiprvse.exe": `${S32}wbem\\WmiPrvSE.exe`, "explorer.exe": "C:\\Windows\\explorer.exe",
  "psexesvc.exe": "C:\\Windows\\PSEXESVC.exe", "robocopy.exe": `${S32}Robocopy.exe`, "taskmgr.exe": `${S32}Taskmgr.exe`,
  "computerdefaults.exe": `${S32}ComputerDefaults.exe`,
  "chrome.exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "msedge.exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "firefox.exe": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "officeclicktorun.exe": "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\OfficeClickToRun.exe",
  "sqlcmd.exe": "C:\\Program Files\\Microsoft SQL Server\\Client SDK\\ODBC\\170\\Tools\\Binn\\SQLCMD.EXE",
  "sapgui.exe": "C:\\Program Files (x86)\\SAP\\FrontEnd\\SAPgui\\sapgui.exe",
  "msmpeng.exe": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe",
  "ccmexec.exe": "C:\\Windows\\CCM\\CcmExec.exe",
  "acrord32.exe": "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe",
};
for (const n of ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe"]) OS_IMAGE_PATH[n] = `${OFFICE16}${n.toUpperCase()}`;
for (const n of ["cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "schtasks.exe", "sc.exe", "net.exe", "net1.exe",
  "whoami.exe", "wevtutil.exe", "vssadmin.exe", "certutil.exe", "bitsadmin.exe", "reg.exe", "svchost.exe", "services.exe", "lsass.exe", "conhost.exe",
  "taskhostw.exe", "ntdsutil.exe", "gpupdate.exe", "msiexec.exe", "nltest.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "taskkill.exe",
  "curl.exe", "fodhelper.exe", "eventvwr.exe", "sdclt.exe", "notepad.exe", "calc.exe", "mstsc.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe",
  "dllhost.exe", "bcdedit.exe", "wbadmin.exe", "netsh.exe", "quser.exe", "query.exe", "nslookup.exe", "ping.exe", "arp.exe", "route.exe", "hostname.exe",
  "dsquery.exe", "adfind.exe", "esentutl.exe", "makecab.exe", "expand.exe", "forfiles.exe", "cmstp.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
  "odbcconf.exe", "searchindexer.exe", "spoolsv.exe", "lsm.exe", "wuauclt.exe", "userinit.exe", "sihost.exe", "runtimebroker.exe", "consent.exe"]) {
  OS_IMAGE_PATH[n] ??= `${S32}${n}`;
}
export const osImagePath = (name?: string) => (name ? OS_IMAGE_PATH[name.toLowerCase()] : undefined);
/** A well-known image: its path is fixed by the OS / vendor, so a ref's own authored path is kept (a masquerading copy elsewhere is a different binary). */
const knownImage = (n: string) => n in OS_IMAGE_PATH || SINGLETON.has(n) || SESSION.has(n);

// ── Hashes ──────────────────────────────────────────────────────────────────

/** Long deterministic hex with full diffusion (each 8-char block's seed varies at its FIRST character). */
function hx(ctx: NativeCtx, seed: string, len: number): string {
  let out = "";
  for (let i = 0; out.length < len; i++) out += ctx.hex(`${i}|${seed}`, 8);
  return out.slice(0, len);
}
/**
 * One binary → one hash: a binary the story gives no hash for is hashed from its path (company-independent,
 * so the fleet build of powershell.exe is the same file on every host and in every product's record).
 */
export function imageHashes(ctx: NativeCtx, path: string): { sha256: string; md5: string } {
  const p = path.toLowerCase();
  return { sha256: hx(ctx, `img:${p}`, 64), md5: hx(ctx, `img:${p}:md5`, 32) };
}
/** SHA1 of one file: from its SHA256 when known (so it follows the binary), else from its path. */
export const sha1Of = (ctx: NativeCtx, sha256OrPath: string) => ctx.hex(`sha1:${sha256OrPath.toLowerCase()}`, 40);

// ── Accounts ────────────────────────────────────────────────────────────────

const WELL_KNOWN_SID: Record<string, string> = {
  system: "S-1-5-18", "nt authority\\system": "S-1-5-18", "local system": "S-1-5-18",
  "local service": "S-1-5-19", "nt authority\\local service": "S-1-5-19",
  "network service": "S-1-5-20", "nt authority\\network service": "S-1-5-20",
};
/**
 * The account's SID: well-known for the service accounts, else the user's domain SID — derived exactly as
 * the Windows Security module derives TargetUserSid / SubjectUserSid (./windows_security), so the user an
 * EDR row names carries the SID of that user's 4624 / 4688 on the same domain. An authored SID
 * (EdrFacts.sid, threaded from any record of the story) is used instead whenever the story has one.
 * (The M365 records' LogonUserSid — collab-email-shared userSid — is seeded differently; kept for reference.)
 */
export function accountSid(ctx: NativeCtx, user: string, _email?: string): string {
  const u = user.toLowerCase();
  const known = WELL_KNOWN_SID[u] ?? WELL_KNOWN_SID[u.split("\\").pop()!];
  if (known) return known;
  const sam = u.split("\\").pop()!.replace(/\$$/, "");
  const dom = [0, 1, 2].map(i => ctx.int(`${ctx.companyId}:winsec:domsid:${i}`, 1_000_000_000, 3_999_999_999)).join("-");
  return `S-1-5-21-${dom}-${ctx.int(`${ctx.companyId}:winsec:rid:${sam}`, 1104, 9800)}`;
}
/**
 * The logon session id (LUID) of a user on a host: the authored one (4624 TargetLogonId / Sysmon LogonId,
 * "0x…") when the story has it; else the session the Windows Security module gives that (host, account) —
 * so an EDR row's LogonId equals the 4624 TargetLogonId of the same session — and, for a later day of the
 * story (`seq` > 0, set by the story pass), a new session. 999 (0x3E7) for SYSTEM, 996 / 997 for the
 * network / local service accounts.
 */
export function logonLuid(ctx: NativeCtx, host: string, user: string, _timeMs: number, authored?: string, seq = 0): number {
  const u = user.toLowerCase().split("\\").pop()!;
  if (u === "system" || u === "local system" || u.endsWith("$")) return 999;
  if (u === "network service") return 996;
  if (u === "local service") return 997;
  if (authored && /^0x[0-9a-f]+$/i.test(authored)) return parseInt(authored, 16);
  if (authored && /^\d+$/.test(authored)) return Number(authored);
  const h = host.toLowerCase().split(".")[0];
  return parseInt(ctx.hex(`${ctx.companyId}:${h}:${u}:luid${seq ? `:${seq}` : ""}`, 6), 16);
}

// ── Story pass ──────────────────────────────────────────────────────────────

const lcBase = (p?: string) => lc(baseOf(undouble(p)));
const s = (v: unknown): string | undefined => (v === undefined || v === null || v === "" || v === "-" ? undefined : String(v));
const num = (v: unknown): number | undefined => { const n = Number(v); return v === undefined || v === null || v === "" || isNaN(n) ? undefined : n; };
const HOSTED = new Set(["edr", "av", "sysmon"]);
const SCRIPT_HOST = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\.exe$/;

interface PView { name?: string; path?: string; pid?: number; cmdline?: string; sha256?: string; md5?: string; integrity?: string; user?: string }
interface View { i: number; host: string; t: number; f: EdrFacts; et: string; proc: PView; parent: PView; user?: string; filePath?: string; fileSha?: string; fileMd5?: string }

/** The facts of one hosted event, completed from a Sysmon EventData block when the event carries only that. */
function viewOf(e: TelemetryEvent, i: number): View | null {
  if (!HOSTED.has(e.source)) return null;
  const f = edrFacts(e);
  const host = lc(f.host);
  if (!host) return null;
  const r = (e.raw ?? {}) as Record<string, unknown>;
  const ed = (k: string) => s(r[`winlog.event_data.${k}`]);
  const sha = (h?: string) => (h ? /SHA256=([0-9A-Fa-f]{64})/.exec(h)?.[1] : undefined);
  const md5 = (h?: string) => (h ? /MD5=([0-9A-Fa-f]{32})/.exec(h)?.[1] : undefined);
  const img = ed("Image") ?? ed("SourceImage");
  const proc: PView = {
    name: f.proc.name ?? baseOf(img), path: f.proc.path ?? img, pid: f.proc.pid ?? num(ed("ProcessId") ?? ed("SourceProcessId")),
    cmdline: f.proc.cmdline ?? ed("CommandLine"), sha256: f.proc.sha256 ?? sha(ed("Hashes")), md5: f.proc.md5 ?? md5(ed("Hashes")),
    integrity: f.proc.integrity ?? ed("IntegrityLevel"), user: ed("User") ?? e.process?.user,
  };
  const parent: PView = {
    name: f.parent.name ?? baseOf(ed("ParentImage")), path: f.parent.path ?? ed("ParentImage"), pid: f.parent.pid ?? num(ed("ParentProcessId")),
    cmdline: f.parent.cmdline ?? ed("ParentCommandLine"), sha256: f.parent.sha256, md5: f.parent.md5,
  };
  const user = lc((f.user ?? ed("User") ?? f.userEmail?.split("@")[0])?.split("\\").pop());
  const filePath = f.file.path ?? ed("TargetFilename");
  return { i, host, t: Date.parse(e.ts), f, et: e.event_type, proc, parent, user: user || undefined, filePath, fileSha: f.file.sha256, fileMd5: f.file.md5 };
}

/** (user, SID) pairs an event's raw states, in every vocabulary the corpus uses. */
const SID_PAIRS: [string, string][] = [
  ["winlog.event_data.TargetUserName", "winlog.event_data.TargetUserSid"], ["winlog.event_data.SubjectUserName", "winlog.event_data.SubjectUserSid"],
  ["TargetUserName", "TargetUserSid"], ["SubjectUserName", "SubjectUserSid"], ["user.name", "user.id"], ["AccountName", "AccountSid"],
  ["InitiatingProcessAccountName", "InitiatingProcessAccountSid"], ["crowdstrike.UserName", "crowdstrike.UserSid"],
];
const URL_KEY = /^(pan\.url|url\.full|url\.original|data\.url|request\.url|http\.url|cs-uri|c-uri)$/i;
const REFERRER_KEY = /^(pan\.referer|http\.request\.referrer|url\.referrer|referer|referrer|data\.referralurl)$/i;
const BROWSER = /^(chrome|msedge|firefox|iexplore|brave|opera|outlook)\.exe$/;

/**
 * One story, one set of endpoint identities. Rendering is per event, but the story knows what one row
 * cannot: the hash of the binary a child row names only as its parent, the folder of an installer a
 * file row names only by file name, who wrote a file the row does not attribute. This pass (run by
 * instantiateStory after the story is re-homed) records those facts on each hosted event
 * (edr-normalize EndpointThread) so every record of the story agrees:
 *   - one path per (host, custom image) — its own process row wins; a well-known image keeps an
 *     authored path (a copy elsewhere is a different binary) and is located by the OS table otherwise;
 *   - one hash per (host, path) — the process's own row, then an alert, then the file row that wrote
 *     it, then an authored parent / actor hash; never two values for one binary;
 *   - a parent's integrity, account and command line from its own row (a service host's account
 *     when the story has no row for it);
 *   - an image the story shows as its own parent (powershell.exe → powershell.exe, authored pids
 *     differ) gets a child instance, so ids never self-parent;
 *   - a file / registry row with no actor gets the writer the story implies: the parent of the later
 *     process that ran the written file, else the latest custom binary (or script host) on that host;
 *   - the user's authored SID, the logon id of the user's latest authored logon on that host, and a
 *     download's origin / referrer URL from the story's own web request for that file name.
 */
export function threadEndpointStory(events: TelemetryEvent[]): TelemetryEvent[] {
  const views = events.map((e, i) => viewOf(e, i));
  const vs = views.filter((v): v is View => !!v).sort((a, b) => a.t - b.t || a.i - b.i);
  if (!vs.length) return events;
  const k2 = (h: string, n?: string) => `${h}|${lc(n)}`;

  // 1. An image shown as its own parent: the child is another instance.
  const instTag = new Map<string, string>();
  for (const v of vs) {
    const n = lc(v.proc.name);
    if (n && n === lc(v.parent.name) && v.proc.pid !== undefined && v.parent.pid !== undefined && v.proc.pid !== v.parent.pid) instTag.set(`${v.host}|${n}|${v.proc.pid}`, `i${v.proc.pid}`);
  }
  const instOf = (h: string, p: PView) => (p.name && p.pid !== undefined ? instTag.get(`${h}|${lc(p.name)}|${p.pid}`) : undefined);

  // 2. One path per (host, custom image): own process rows, then alerts, then the file that wrote it, then any ref.
  const pathBy = new Map<string, string>();
  const notePath = (h: string, n: string | undefined, p: string | undefined) => {
    const name = lc(n ?? baseOf(p));
    if (!name || !p || !/[\\/]/.test(p) || lcBase(p) !== name || pathBy.has(k2(h, name))) return;
    pathBy.set(k2(h, name), undouble(p)!);
  };
  for (const v of vs) if (v.f.kind === "process") notePath(v.host, v.proc.name, v.proc.path);
  for (const v of vs) if (v.f.kind === "detection") notePath(v.host, v.proc.name, v.proc.path);
  for (const v of vs) if (v.filePath && !knownImage(lcBase(v.filePath))) notePath(v.host, undefined, v.filePath);
  for (const v of vs) { notePath(v.host, v.proc.name, v.proc.path); notePath(v.host, v.parent.name, v.parent.path); }
  const resolve = (h: string, p: PView): string | undefined => {
    const n = lc(p.name ?? baseOf(p.path));
    if (!n) return p.path;
    const canon = pathBy.get(k2(h, n));
    return knownImage(n) ? undouble(p.path) ?? canon ?? OS_IMAGE_PATH[n] : canon ?? undouble(p.path);
  };

  // 3. One hash per (host, path).
  const hashBy = new Map<string, { sha256?: string; md5?: string }>();
  const hkey = (h: string, path: string | undefined, name?: string) => (path ? `${h}|${path.toLowerCase()}` : name ? `${h}|name:${lc(name)}` : undefined);
  const noteHash = (key: string | undefined, sha256?: string, md5?: string) => {
    if (!key || (!sha256 && !md5)) return;
    const cur = hashBy.get(key) ?? {};
    if (!cur.sha256 && sha256) cur.sha256 = sha256;
    if (!cur.md5 && md5 && (!sha256 || lc(cur.sha256) === lc(sha256))) cur.md5 = md5;
    hashBy.set(key, cur);
  };
  const procHashKey = (v: View, p: PView) => hkey(v.host, resolve(v.host, p), p.name);
  for (const v of vs) if (v.f.kind === "process") noteHash(procHashKey(v, v.proc), v.proc.sha256, v.proc.md5);
  for (const v of vs) if (v.f.kind === "detection") noteHash(procHashKey(v, v.proc), v.proc.sha256, v.proc.md5);
  for (const v of vs) if (v.filePath && v.f.kind !== "detection") noteHash(hkey(v.host, v.filePath), v.fileSha, v.fileMd5);
  for (const v of vs) if (v.filePath && v.f.kind === "detection") noteHash(hkey(v.host, v.filePath), v.fileSha, v.fileMd5);
  for (const v of vs) noteHash(procHashKey(v, v.parent), v.parent.sha256, v.parent.md5);
  for (const v of vs) if (v.f.kind !== "process" && v.f.kind !== "detection") noteHash(procHashKey(v, v.proc), v.proc.sha256, v.proc.md5);

  // 4. A process's own row: integrity, account, command line (for the rows that name it as a parent).
  const ownBy = new Map<string, PView>();
  for (const v of vs) {
    if (v.f.kind !== "process" || !v.proc.name) continue;
    const key = `${k2(v.host, v.proc.name)}|${instOf(v.host, v.proc) ?? ""}`;
    if (!ownBy.has(key)) ownBy.set(key, v.proc);
  }

  const threadProc = (v: View, p: PView, asParent: boolean): ThreadProc | undefined => {
    if (!p.name && !p.path) return undefined;
    const path = resolve(v.host, p);
    const inst = instOf(v.host, p);
    const h = hashBy.get(hkey(v.host, path, p.name) ?? "") ?? {};
    const own = p.name ? ownBy.get(`${k2(v.host, p.name)}|${inst ?? ""}`) : undefined;
    const svc = SERVICE_ACCOUNT[lc(p.name)];
    const t: ThreadProc = {
      path: path && path !== p.path ? path : undefined,
      sha256: h.sha256 && lc(h.sha256) !== lc(p.sha256) ? h.sha256 : undefined,
      md5: h.md5 && lc(h.md5) !== lc(p.md5) ? h.md5 : undefined,
      inst,
      cmdline: own && own !== p ? own.cmdline : undefined,
      integrity: own && own !== p ? own.integrity : asParent && svc ? "system" : undefined,
      user: asParent ? (own?.user ?? svc) : undefined,
    };
    return Object.values(t).some(x => x !== undefined) ? t : undefined;
  };

  // 5. Writer of an unattributed file / registry row.
  const writerOf = (v: View): ThreadProc | undefined => {
    if (v.f.kind !== "file" && v.f.kind !== "registry") return undefined;
    if (v.proc.name || v.proc.path || v.proc.cmdline) return undefined;
    // A user's hand copy (profile folder, removable drive) is Explorer's — the modules attribute it themselves.
    if (v.f.kind === "file" && inferredFileWriter(v.filePath, "Win", /^(system|local service|network service)$/.test(v.user ?? ""))) return undefined;
    let w: { host: string; p: PView; v: View } | undefined;
    if (v.f.kind === "file" && v.filePath) {
      const target = v.filePath.toLowerCase();
      const runner = vs.find(x => x.host === v.host && x.t >= v.t && x.f.kind === "process" && resolve(x.host, x.proc)?.toLowerCase() === target && x.parent.name);
      if (runner) w = { host: v.host, p: runner.parent, v: runner };
    }
    if (!w) {
      // The process each earlier row shows running on this host (an alert on an executable file counts: it ran).
      const running = (x: View): PView | undefined => x.proc.name ? x.proc
        : x.f.kind === "detection" && x.filePath && /\.(exe|scr|com)$/i.test(x.filePath) ? { name: baseOf(x.filePath), path: x.filePath, sha256: x.fileSha } : undefined;
      const before = vs.filter(x => x.host === v.host && x !== v && x.t <= v.t && v.t - x.t <= 6 * 3_600_000 && x.f.kind !== "file" && x.f.kind !== "registry" && running(x));
      const pick = [...before].reverse().find(x => !knownImage(lc(running(x)!.name))) ?? [...before].reverse().find(x => SCRIPT_HOST.test(lc(running(x)!.name)));
      if (pick) w = { host: v.host, p: running(pick)!, v: pick };
    }
    if (!w) return undefined;
    const path = resolve(w.host, w.p);
    const inst = instOf(w.host, w.p);
    const h = hashBy.get(hkey(w.host, path, w.p.name) ?? "") ?? {};
    const own = w.p.name ? ownBy.get(`${k2(w.host, w.p.name)}|${inst ?? ""}`) : undefined;
    return { name: w.p.name ?? baseOf(path), path, sha256: h.sha256, md5: h.md5, inst, cmdline: own?.cmdline ?? w.p.cmdline, integrity: own?.integrity, user: own?.user, pid: w.p.pid };
  };

  // 7. The user's authored SID.
  const sidBy = new Map<string, string>();
  for (const e of events) for (const [uk, sk] of SID_PAIRS) {
    const u = lc(s(e.raw?.[uk])?.split("\\").pop()), sid = s(e.raw?.[sk]);
    // A domain account (S-1-5-21-…) or a virtual service account (IIS APPPOOL S-1-5-82-…, NT SERVICE S-1-5-80-…).
    if (u && sid && /^S-1-5-(21|80|82)-/.test(sid) && !u.endsWith("$") && !sidBy.has(u)) sidBy.set(u, sid);
  }
  // 8. Authored logon sessions per (host, user): 4624 TargetLogonId, Sysmon LogonId.
  const logons = new Map<string, { t: number; id: string }[]>();
  const noteLogon = (host: string | undefined, user: string | undefined, t: number, id: string | undefined) => {
    const u = lc(user?.split("\\").pop());
    if (!host || !u || !id || /^0x0*3e[4-7]$/i.test(id) || u.endsWith("$") || /^(system|anonymous logon|-)$/.test(u)) return;
    const key = k2(lc(host).split(".")[0], u);
    logons.set(key, [...(logons.get(key) ?? []), { t, id }]);
  };
  for (const e of events) {
    const r = (e.raw ?? {}) as Record<string, unknown>;
    const code = s(r["event.code"] ?? r["winlog.event_id"] ?? r["EventID"]);
    if (code === "4624") noteLogon(e.hostname ?? s(r["winlog.computer_name"]), s(r["winlog.event_data.TargetUserName"] ?? r["TargetUserName"]), Date.parse(e.ts), s(r["winlog.event_data.TargetLogonId"] ?? r["TargetLogonId"]));
    if (e.source === "sysmon" && code === "1") noteLogon(e.hostname ?? s(r["winlog.computer_name"]), s(r["winlog.event_data.User"]), Date.parse(e.ts), s(r["winlog.event_data.LogonId"]));
  }
  for (const list of logons.values()) list.sort((a, b) => a.t - b.t);
  const daysBy = new Map<string, string[]>();
  for (const v of vs) if (v.user) {
    const key = k2(v.host.split(".")[0], v.user), d = dayOf(v.t), list = daysBy.get(key) ?? [];
    if (!list.includes(d)) daysBy.set(key, [...list, d].sort());
  }
  // 9. A download's origin: the story's own web request for that file name.
  const urls: { t: number; name: string; url: string; ref?: string }[] = [];
  for (const e of events) {
    if (HOSTED.has(e.source)) continue;
    const r = (e.raw ?? {}) as Record<string, unknown>;
    const ref = Object.entries(r).find(([k, v]) => REFERRER_KEY.test(k) && s(v))?.[1] as string | undefined;
    const port = s(r["pan.dport"] ?? r["destination.port"]);
    for (const [, v] of [...Object.entries(r).filter(([k]) => URL_KEY.test(k)), ["network.url", e.network?.url] as [string, unknown]]) {
      const url = s(v);
      if (!url) continue;
      const name = lc(decodeURIComponent(url.split(/[?#]/)[0].split("/").pop() ?? ""));
      if (!name || !name.includes(".") || /^[\w-]+\.(com|net|org|io|xyz|top|live|ru|cn)$/.test(name)) continue;
      urls.push({ t: Date.parse(e.ts), name, url: /^[a-z]+:\/\//i.test(url) ? url : `${port === "80" ? "http" : "https"}://${url}`, ref: ref ? s(ref) : undefined });
    }
  }

  // 10. One file → one verdict name: a detection that names no threat takes the name the story's other detection of that file authored.
  const threatBy = new Map<string, string>();
  const threatKey = (v: View) => lc(v.fileSha ?? v.proc.sha256) || undefined;
  for (const v of vs) {
    const name = v.f.detection?.name, key = threatKey(v);
    if (key && name && !/^(none|suspicious activity detected|troj\/agent-a)$/i.test(name) && !threatBy.has(key)) threatBy.set(key, name);
  }

  return events.map((e, i) => {
    const v = views[i];
    if (!v) return e;
    const t: EndpointThread = { ...(threadOf(e) ?? {}) };
    const proc = threadProc(v, v.proc, false);
    const parent = threadProc(v, v.parent, true);
    const writer = writerOf(v);
    if (proc) t.proc = proc;
    if (parent) t.parent = parent;
    if (writer) t.writer = writer;
    // A row that names no user: the account the story shows on this host nearest in time (within two hours).
    if (!v.user && !v.proc.user) {
      const near = vs.filter(x => x.host === v.host && x.user && Math.abs(x.t - v.t) <= 2 * 3_600_000).sort((a, b) => Math.abs(a.t - v.t) - Math.abs(b.t - v.t))[0];
      const acct = near ? (near.proc.user ?? near.f.user ?? near.user) : undefined;
      if (acct) t.user = near!.f.userDomain && !acct.includes("\\") ? `${near!.f.userDomain}\\${acct}` : acct;
    }
    const tk = v.f.kind === "detection" && !v.f.detection?.name ? threatKey(v) : undefined;
    if (tk && threatBy.has(tk)) t.threatName = threatBy.get(tk);
    if (v.user && sidBy.has(v.user) && !v.f.sid) t.sid = sidBy.get(v.user);
    const sess = v.user ? logons.get(k2(v.host.split(".")[0], v.user)) : undefined;
    const latest = sess?.filter(x => x.t <= v.t + 1_000).pop();
    if (latest) t.logonId = latest.id;
    // A later day of the story is a new logon session (ordinal of the event's day among the user's days on this host).
    const days = v.user ? daysBy.get(k2(v.host.split(".")[0], v.user)) : undefined;
    const seq = days ? days.indexOf(dayOf(v.t)) : 0;
    if (!latest && seq > 0) t.logonSeq = seq;
    if (v.f.kind === "file" && v.filePath && !v.f.originUrl) {
      const name = lcBase(v.filePath);
      const dl = urls.filter(u => u.name === name && u.t <= v.t + 60_000 && v.t - u.t <= 2 * 3_600_000).pop();
      const writerName = lc(v.proc.name ?? writer?.name);
      if (dl && (BROWSER.test(writerName) || !writerName)) { t.originUrl = dl.url; if (dl.ref) t.referrerUrl = dl.ref; }
    }
    return Object.keys(t).length ? withThread(e, t) : e;
  });
}
