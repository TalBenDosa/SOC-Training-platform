/**
 * Microsoft Sysinternals Sysmon (Windows) — native module (card: docs/log-schemas/host-sysmon.md).
 *
 * Record: one `Microsoft-Windows-Sysmon/Operational` event as a FLAT object — the Event
 * XML `System` names (ProviderName, EventID, Version, Level, Task, Opcode, Keywords,
 * TimeCreated, EventRecordID, ProcessID, ThreadID, Channel, Computer, UserID) followed by
 * every `EventData` `Data Name` with Sysmon's exact spelling (note `ProcessGuid` vs the
 * event-10 `SourceProcessGUID`). EventData values are strings; `UtcTime` uses a space and
 * no "Z". `rawLine` = the rendered EVTX XML of the same event.
 *
 * Process linkage: `ProcessGuid` is derived from (host, pid, image name), so a child's
 * `ParentProcessGuid` equals the parent's own `ProcessGuid` whenever both were rendered —
 * the student can walk the tree by GUID exactly as on a real Sysmon feed. Authored GUIDs
 * (legacy `winlog.event_data.ProcessGuid`) are kept verbatim.
 *
 * Category-wide: besides Sysmon-authored events, EDR process / network / file / registry /
 * process-access / DNS telemetry (CrowdStrike, MDE, SentinelOne, Sophos-authored) renders
 * as the Sysmon event the same activity produces on a host that runs Sysmon. EDR verdicts
 * (alerts, quarantine, AV detections) and non-Windows hosts have no Sysmon record → null.
 */
import type { NativeSource, NativeLog, KindSchema, UseCase, NativeCtx } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { procPid, procKey, win4, OS_IMAGE_PATH, imageHashes, accountSid, logonLuid } from "./_proc-identity";
import { accessMask, threadOf } from "./edr-normalize";

/** Windows pids / tids are multiples of 4: an authored value is rounded down to one (equal values stay equal). */
const pid4 = (v: string | undefined): string | undefined => (v !== undefined && /^\d+$/.test(v) ? String(win4(Number(v))) : v);

const SYSTEM = ["ProviderName", "EventID", "Version", "Level", "Task", "Opcode", "Keywords", "TimeCreated", "EventRecordID", "ProcessID", "ThreadID", "Channel", "Computer", "UserID"];
const req = (...ed: string[]) => [...SYSTEM, "RuleName", "UtcTime", ...ed];

const kinds: Record<string, KindSchema> = {
  // ProcessCreate
  "1": {
    required: req("ProcessGuid", "ProcessId", "Image", "FileVersion", "Description", "Product", "Company", "OriginalFileName", "CommandLine", "CurrentDirectory", "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "Hashes", "ParentProcessGuid", "ParentProcessId", "ParentImage", "ParentCommandLine"),
    optional: ["ParentUser"],
  },
  // NetworkConnect
  "3": {
    required: req("ProcessGuid", "ProcessId", "Image", "User", "Protocol", "Initiated", "SourceIsIpv6", "SourceIp", "SourceHostname", "SourcePort", "SourcePortName", "DestinationIsIpv6", "DestinationIp", "DestinationHostname", "DestinationPort", "DestinationPortName"),
    optional: [],
  },
  // DriverLoad — the card names event 6 but lists no fields; these are Sysmon's schema names (UNVERIFIED vs card).
  "6": { required: req("ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"), optional: [] },
  // ImageLoad
  "7": { required: req("ProcessGuid", "ProcessId", "Image", "ImageLoaded", "Hashes", "Signed", "Signature", "SignatureStatus"), optional: ["FileVersion", "Description", "Product", "Company", "OriginalFileName", "User"] },
  // CreateRemoteThread
  "8": { required: req("SourceProcessGuid", "SourceProcessId", "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction"), optional: ["SourceUser", "TargetUser"] },
  // ProcessAccess
  "10": { required: req("SourceProcessGUID", "SourceProcessId", "SourceThreadId", "SourceImage", "TargetProcessGUID", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace"), optional: ["SourceUser", "TargetUser"] },
  // FileCreate
  "11": { required: req("ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime"), optional: ["User"] },
  // RegistryEvent (object create / delete)
  "12": { required: req("EventType", "ProcessGuid", "ProcessId", "Image", "TargetObject"), optional: ["User"] },
  // RegistryEvent (value set)
  "13": { required: req("EventType", "ProcessGuid", "ProcessId", "Image", "TargetObject", "Details"), optional: ["User"] },
  // FileCreateStreamHash
  "15": { required: req("ProcessGuid", "ProcessId", "Image", "TargetFilename", "CreationUtcTime", "Hash"), optional: ["Contents", "User"] },
  // PipeEvent (created) — card names 17/18 without a field list; Sysmon schema names (UNVERIFIED vs card).
  "17": { required: req("EventType", "ProcessGuid", "ProcessId", "PipeName", "Image"), optional: ["User"] },
  // DNSEvent
  "22": { required: req("ProcessGuid", "ProcessId", "QueryName", "QueryStatus", "QueryResults", "Image"), optional: ["User"] },
  // FileDelete (archived)
  "23": { required: req("ProcessGuid", "ProcessId", "Image", "TargetFilename", "Hashes", "IsExecutable", "Archived"), optional: ["User"] },
  // FileDeleteDetected
  "26": { required: req("ProcessGuid", "ProcessId", "Image", "TargetFilename", "Hashes", "IsExecutable"), optional: ["User"] },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.ProviderName !== "Microsoft-Windows-Sysmon") return null;
  const k = String(record.EventID);
  return kinds[k] ? k : null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
const str = (v: unknown): string | undefined =>
  v === undefined || v === null || v === "" ? undefined : Array.isArray(v) ? (v.length ? v.map(String).join(" ") : undefined) : String(v);
const base = (p: string) => p.split(/[\\/]/).pop() ?? p;
const isWinPath = (p?: string) => !!p && /^([A-Za-z]:\\|\\\\)/.test(p);
const VERSION: Record<string, number> = { "1": 5, "3": 5, "6": 4, "7": 3, "8": 2, "10": 3, "11": 2, "12": 2, "13": 2, "15": 2, "17": 1, "22": 5, "23": 5, "26": 5 };

const S32 = "C:\\Windows\\System32\\";
const OFFICE = "C:\\Program Files\\Microsoft Office\\root\\Office16\\";
/** Install paths of well-known binaries (lower-case name → full path) — the table every EDR module shares. */
const KNOWN: Record<string, string> = OS_IMAGE_PATH;
/** Version-resource metadata of the most common Windows binaries. */
const META: Record<string, { d: string; o: string }> = {
  "powershell.exe": { d: "Windows PowerShell", o: "PowerShell.EXE" }, "cmd.exe": { d: "Windows Command Processor", o: "Cmd.Exe" },
  "rundll32.exe": { d: "Windows host process (Rundll32)", o: "RUNDLL32.EXE" }, "regsvr32.exe": { d: "Microsoft(C) Register Server", o: "REGSVR32.EXE" },
  "mshta.exe": { d: "Microsoft (R) HTML Application host", o: "MSHTA.EXE" }, "wscript.exe": { d: "Microsoft ® Windows Based Script Host", o: "wscript.exe" },
  "cscript.exe": { d: "Microsoft ® Console Based Script Host", o: "cscript.exe" }, "schtasks.exe": { d: "Task Scheduler Configuration Tool", o: "schtasks.exe" },
  "certutil.exe": { d: "CertUtil.exe", o: "CertUtil.exe" }, "wevtutil.exe": { d: "Eventing Command Line Utility", o: "wevtutil.exe" },
  "vssadmin.exe": { d: "Command Line Interface for Microsoft® Volume Shadow Copy Service ", o: "VSSADMIN.EXE" }, "net.exe": { d: "Net Command", o: "net.exe" },
  "whoami.exe": { d: "whoami - displays logged on user information", o: "whoami.exe" }, "reg.exe": { d: "Registry Console Tool", o: "reg.exe" },
  "svchost.exe": { d: "Host Process for Windows Services", o: "svchost.exe" }, "explorer.exe": { d: "Windows Explorer", o: "EXPLORER.EXE" },
  "ntdsutil.exe": { d: "NT5DS", o: "ntdsutil.exe" }, "msiexec.exe": { d: "Windows® installer", o: "msiexec.exe" },
  "winword.exe": { d: "Microsoft Word", o: "WinWord.exe" }, "excel.exe": { d: "Microsoft Excel", o: "Excel.exe" },
  "powerpnt.exe": { d: "Microsoft PowerPoint", o: "POWERPNT.EXE" }, "outlook.exe": { d: "Microsoft Outlook", o: "Outlook.exe" },
};
const PORTNAME: Record<string, string> = { "443": "https", "80": "http", "445": "microsoft-ds", "3389": "ms-wbt-server", "22": "ssh", "53": "domain", "389": "ldap", "636": "ldaps", "88": "kerberos", "135": "epmap", "139": "netbios-ssn", "1433": "ms-sql-s", "5985": "wsman", "5986": "wsmans", "8080": "http-alt", "25": "smtp" };
const SYSTEM_PARENTS = new Set(["services.exe", "svchost.exe", "wmiprvse.exe", "smss.exe", "wininit.exe", "winlogon.exe", "psexesvc.exe"]);

/**
 * Long deterministic hex (hashes, GUIDs). ctx.hex chains seeds that differ only in their
 * last character, which leaves visible repetition in 32/64-char values; varying the FIRST
 * character of each 8-char chunk's seed diffuses fully.
 */
function hx(ctx: NativeCtx, seed: string, len: number): string {
  let out = "";
  for (let i = 0; out.length < len; i++) out += ctx.hex(`${i}|${seed}`, 8);
  return out.slice(0, len);
}
function utcTime(ms: number): string { return new Date(ms).toISOString().replace("T", " ").replace("Z", ""); }
function timeCreated(ms: number): string { return new Date(ms).toISOString().replace(/\.(\d{3})Z$/, (_, x) => `.${x}0000Z`); }
function xmlEsc(v: string): string { return v.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }

/** `\Device\HarddiskVolume3\Windows\…` → `C:\Windows\…` */
function devicePath(p?: string): string | undefined {
  if (!p) return undefined;
  const m = /^\\Device\\HarddiskVolume\d+\\(.*)$/i.exec(p);
  return m ? `C:\\${m[1]}` : isWinPath(p) ? p : undefined;
}
/** Join an MDE/CS folder with a file name unless the folder already is the full path. */
function joinPath(folder: string | undefined, name: string | undefined): string | undefined {
  if (!folder || !isWinPath(folder)) return undefined;
  if (!name) return folder;
  if (folder.toLowerCase().endsWith(`\\${name.toLowerCase()}`) || base(folder).toLowerCase() === name.toLowerCase()) return folder;
  return `${folder.replace(/\\$/, "")}\\${name}`;
}
/** A full path at the start of a command line: `"C:\x\y.exe" …` or `C:\x\y.exe …`. */
function pathFromCmd(cmd: string | undefined, name: string | undefined): string | undefined {
  if (!cmd) return undefined;
  const m = /^"([A-Za-z]:\\[^"]+)"/.exec(cmd) ?? /^([A-Za-z]:\\\S+)/.exec(cmd);
  if (!m) return undefined;
  if (name && base(m[1]).toLowerCase() !== name.toLowerCase()) return undefined;
  return m[1];
}

interface Actor { name?: string; path?: string; cmd?: string; pid?: string; user?: string; integrity?: string; sha256?: string; md5?: string; guid?: string; inst?: string }

/** The user's SID — the same value every EDR / directory record gives the user (./_proc-identity accountSid). */
const sid = (ctx: NativeCtx, user: string, email?: string) => accountSid(ctx, user, email);

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  const r = (k: string) => str(raw[k]);
  const ed = (k: string) => r(`winlog.event_data.${k}`);
  const sysmonAuthored = ev.source === "sysmon";

  // ── which Sysmon event ──
  const authoredId = r("winlog.event_id") ?? (sysmonAuthored ? r("event.code") : undefined);
  if (authoredId !== undefined && !kinds[authoredId]) return null; // e.g. a Security 4663 filed under sysmon
  const byType: Record<string, string> = {
    process_create: "1", scheduled_task: "1", privilege_escalation: "1", service_install: "1",
    net_connection: "3", dns_query: "22", process_access: "10",
    file_create: "11", file_modify: "11", file_copy: "11", file_delete: "26",
    registry_set: "13", registry_delete: "12",
  };
  const id = authoredId ?? byType[ev.event_type];
  if (!id) return null;

  // ── host ──
  const host = ev.hostname ?? r("host.name") ?? r("winlog.computer_name") ?? r("crowdstrike.ComputerName") ?? r("DeviceName") ?? r("s1.agent.computerName");
  if (!host) return null;
  const devFqdn = r("DeviceName");
  const dnsSuffix = devFqdn && devFqdn.includes(".") && devFqdn.split(".")[0].toLowerCase() === host.split(".")[0].toLowerCase() ? devFqdn.slice(devFqdn.indexOf(".") + 1) : ctx.domain;
  const computer = r("winlog.computer_name") ?? (host.includes(".") ? host : `${host}.${dnsSuffix}`);
  const machine = hx(ctx, `${ctx.companyId}:${host.toLowerCase()}:machine`, 8);
  const timeMs = Date.parse(ev.ts);

  // ── the acting process (new process for event 1; the actor for 3/10/11/13/22/26) ──
  // The story pass (edr-normalize EndpointThread) supplies what this row cannot know: the canonical
  // image path / hash of the actor and its parent, the parent's own account and command line, the
  // writer of an unattributed file, the user's authored SID and logon id.
  const th = threadOf(ev);
  const mdeProcEvent = r("ActionType") === "ProcessCreated";
  const a: Actor = {};
  a.name = ev.process?.name ?? (ed("Image") ? base(ed("Image")!) : undefined) ?? r("process.name") ?? r("crowdstrike.FileName") ?? r("crowdstrike.ContextBaseFileName")
    ?? (mdeProcEvent ? r("FileName") : r("InitiatingProcessFileName")) ?? r("s1.srcProcName");
  a.cmd = ev.process?.cmdline ?? ed("CommandLine") ?? r("process.command_line") ?? r("crowdstrike.CommandLine")
    ?? (mdeProcEvent ? r("ProcessCommandLine") : r("InitiatingProcessCommandLine")) ?? r("s1.srcProcCmdLine");
  // A file / registry row that names no actor: the writer the story implies.
  const wr = /^(11|12|13|23|26)$/.test(id) && th?.writer && !ed("Image") &&
    ((!a.name && !a.cmd) || (a.name && a.name.toLowerCase() === th.writer.name?.toLowerCase())) ? th.writer : undefined;
  if (wr) { a.name = wr.name; a.cmd = wr.cmdline; }
  a.cmd ??= th?.proc?.cmdline;
  a.inst = wr?.inst ?? th?.proc?.inst;
  a.path = (wr?.path && isWinPath(wr.path) ? wr.path : undefined) ?? (th?.proc?.path && isWinPath(th.proc.path) ? th.proc.path : undefined)
    ?? ed("Image") ?? (isWinPath(ev.process?.path) ? ev.process!.path : undefined) ?? (isWinPath(r("process.executable")) ? r("process.executable") : undefined)
    ?? joinPath(r("crowdstrike.FilePath"), r("crowdstrike.FileName") === a.name ? a.name : undefined) ?? devicePath(r("crowdstrike.ImageFileName"))
    ?? joinPath(mdeProcEvent ? r("FolderPath") : r("InitiatingProcessFolderPath"), a.name)
    ?? (a.name ? KNOWN[a.name.toLowerCase()] : undefined) ?? pathFromCmd(a.cmd, a.name)
    ?? (a.name && isWinPath(ev.file?.path) && base(ev.file!.path).toLowerCase() === a.name.toLowerCase() ? ev.file!.path : undefined);
  // Non-Windows actors (Linux EDR telemetry) have no Sysmon-for-Windows record.
  const linuxish = (ev.process?.path ?? "").startsWith("/") || r("host.os.type") === "linux" || ev.event_type.startsWith("linux_")
    || (!!a.name && !a.path && !/\.(exe|com|scr|bat|cmd|ps1|dll)$/i.test(a.name));
  if (linuxish && !sysmonAuthored) return null;
  a.pid = (ev.process?.pid !== undefined ? String(ev.process.pid) : undefined) ?? ed("ProcessId") ?? r("process.pid") ?? r("crowdstrike.RawProcessId")
    ?? (mdeProcEvent ? r("ProcessId") : r("InitiatingProcessId")) ?? r("s1.srcProcPid");
  const email = ev.user_email ?? ev.user?.email;
  const normUser = (u?: string) => !u ? undefined : u.includes("\\") ? u : /^(system|local system)$/i.test(u) ? "NT AUTHORITY\\SYSTEM" : `${ctx.netbios}\\${u}`;
  const mdeAcct = (d?: string, n?: string) => (n ? (d ? `${d}\\${n}` : n) : undefined);
  a.user = ed("User") ?? normUser(ev.process?.user) ?? normUser(r("user.name")) ?? normUser(r("crowdstrike.UserName"))
    ?? normUser(mdeProcEvent ? mdeAcct(r("AccountDomain"), r("AccountName")) : mdeAcct(r("InitiatingProcessAccountDomain"), r("InitiatingProcessAccountName")))
    ?? normUser(r("s1.srcProcUser")) ?? (email ? `${ctx.netbios}\\${email.split("@")[0]}` : undefined);
  a.sha256 = (wr ? wr.sha256 : th?.proc?.sha256) ?? ev.process?.hash?.sha256 ?? /SHA256=([0-9A-Fa-f]{64})/.exec(ed("Hashes") ?? "")?.[1] ?? r("process.hash.sha256") ?? r("crowdstrike.SHA256HashData") ?? (mdeProcEvent ? r("SHA256") : r("InitiatingProcessSHA256"))
    ?? (ev.file?.sha256 && a.name && ev.file.path && base(ev.file.path).toLowerCase() === a.name.toLowerCase() ? ev.file.sha256 : undefined);
  a.md5 = (wr ? wr.md5 : th?.proc?.md5) ?? ev.process?.hash?.md5 ?? /MD5=([0-9A-Fa-f]{32})/.exec(ed("Hashes") ?? "")?.[1] ?? r("process.hash.md5") ?? r("crowdstrike.MD5HashData");
  const integ: Record<string, string> = { low: "Low", medium: "Medium", high: "High", system: "System" };
  a.integrity = ed("IntegrityLevel") ?? (ev.process?.integrity ? integ[ev.process.integrity] : undefined) ?? r("ProcessIntegrityLevel") ?? r("process.integrity_level")
    ?? ((wr ?? th?.proc)?.integrity ? integ[(wr ?? th!.proc!).integrity!.toLowerCase()] ?? (wr ?? th!.proc!).integrity : undefined);
  if (!a.user && wr?.user) a.user = normUser(wr.user);
  if (!a.user && th?.user) a.user = normUser(th.user);

  // Unknown account: SYSTEM only when the parent is a service host; otherwise Sysmon-style "-" (never a guessed user).
  const user = a.user ?? (ev.process?.parent_name && SYSTEM_PARENTS.has(ev.process.parent_name.toLowerCase()) ? "NT AUTHORITY\\SYSTEM" : "-");
  const isSystemUser = /^NT AUTHORITY\\/i.test(user);
  const userName = user.includes("\\") ? user.split("\\").pop()! : user;
  // Every pid and ProcessGuid comes from the shared process identity (./_proc-identity: host + image +
  // lifetime scope, plus the story's instance tag) — never from an authored ProcessId / ProcessGuid, which
  // the corpus does not number consistently — so a parent's ids on its child equal its own row's.
  const scope = { host, os: "Win" as const, timeMs, incident: ev.incident_id, user: user === "-" ? undefined : userName };
  const seededPid = (name?: string, inst?: string) => String(procPid(ctx, scope, { name: name ?? "?", inst }) ?? 4);
  const pid = a.name ? seededPid(a.name, a.inst) : pid4(a.pid) ?? seededPid(undefined);
  const image = a.path ?? "<unknown process>";
  const guidFor = (n: string | undefined, inst?: string, pidFallback?: string) => {
    const key = n ? procKey(ctx, scope, { name: n, inst }) : undefined;
    const h = hx(ctx, key ? `${key}:guid` : `${ctx.companyId}:${host.toLowerCase()}:${pidFallback}:?`, 24);
    return `{${machine}-${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}-${h.slice(12, 24)}}`;
  };
  const procGuid = guidFor(a.name ?? (a.path ? base(a.path) : undefined), a.inst, pid);
  // The session: the story's authored logon id, else one per host + user + day (./_proc-identity logonLuid).
  const luidHex = `0x${logonLuid(ctx, host, userName, timeMs, th?.logonId, th?.logonSeq).toString(16).toUpperCase()}`;

  const sys = {
    ProviderName: "Microsoft-Windows-Sysmon",
    EventID: Number(id), Version: VERSION[id], Level: 4, Task: Number(id), Opcode: 0, Keywords: "0x8000000000000000",
    TimeCreated: timeCreated(timeMs),
    EventRecordID: ctx.int(`${ctx.companyId}:${host.toLowerCase()}:recbase`, 100_000_000, 700_000_000) + (Math.floor(timeMs / 1000) % 10_000_000),
    ProcessID: ctx.int(`${ctx.companyId}:${host.toLowerCase()}:sysmon64`, 500, 1150) * 4,
    ThreadID: ctx.int(`${ev.id}:tid`, 500, 2250) * 4,
    Channel: "Microsoft-Windows-Sysmon/Operational",
    Computer: computer,
    UserID: "S-1-5-18",
  };
  const head = { RuleName: ed("RuleName") ?? "-", UtcTime: utcTime(timeMs) };
  let data: Record<string, string> | null = null;

  const needImage = () => a.path !== undefined || ed("Image") !== undefined;

  switch (id) {
    case "1": {
      if (!a.name && !a.path) return null;
      if (!a.path) return null; // a process with no resolvable image path cannot be shown as Sysmon 1
      const nm = base(image).toLowerCase();
      const parentName = ev.process?.parent_name ?? (ed("ParentImage") ? base(ed("ParentImage")!) : undefined) ?? r("process.parent.name") ?? r("crowdstrike.ParentBaseFileName")
        ?? (mdeProcEvent ? r("InitiatingProcessFileName") : undefined) ?? r("s1.srcProcParentName");
      const parentCmd = ed("ParentCommandLine") ?? r("process.parent.command_line") ?? r("crowdstrike.ParentCommandLine") ?? (mdeProcEvent ? r("InitiatingProcessCommandLine") : undefined) ?? th?.parent?.cmdline;
      const tParentPath = th?.parent?.path && isWinPath(th.parent.path) ? th.parent.path : undefined;
      const parentPath = tParentPath ?? ed("ParentImage") ?? (mdeProcEvent ? joinPath(r("InitiatingProcessFolderPath"), parentName) : undefined)
        ?? (isWinPath(r("process.parent.executable")) ? r("process.parent.executable") : undefined)
        ?? (parentName ? KNOWN[parentName.toLowerCase()] ?? pathFromCmd(parentCmd, parentName) : undefined);
      const pName = parentName ?? (parentPath ? base(parentPath) : undefined);
      const ppid = pName ? seededPid(pName, th?.parent?.inst) : "0";
      const pImage = parentPath ?? (parentName ? `-` : "-");
      const parentKnown = parentPath !== undefined;
      const parentUser = th?.parent?.user ? normUser(th.parent.user)! : parentName && SYSTEM_PARENTS.has(parentName.toLowerCase()) ? "NT AUTHORITY\\SYSTEM" : user;
      const meta = META[nm];
      // Microsoft version info only for the real binary at its install path — a payload dropped into
      // C:\Windows\Temp is not "Microsoft® Windows® Operating System".
      const installed = KNOWN[nm]?.toLowerCase() === image.toLowerCase();
      const winBin = installed && /^C:\\Windows\\/i.test(image);
      const office = installed && image.startsWith(OFFICE);
      const ms = isSystemUser;
      const imphash = hx(ctx, `imphash:${nm}`, 32).toUpperCase();
      // No story hash: the fleet build's hash for this path — the value every EDR record of this binary shows.
      const fleet = imageHashes(ctx, image);
      // Sysmon prints hashes upper-case; an authored hash is kept verbatim.
      const sha = a.sha256 ?? fleet.sha256.toUpperCase();
      const md5 = a.md5 ?? (a.sha256 ? undefined : fleet.md5.toUpperCase());
      data = {
        ...head,
        ProcessGuid: procGuid,
        ProcessId: pid,
        Image: image,
        FileVersion: ed("FileVersion") ?? (winBin ? "10.0.22621.1 (WinBuild.160101.0800)" : office ? "16.0.18025.20160" : "-"),
        Description: ed("Description") ?? meta?.d ?? "-",
        Product: ed("Product") ?? (winBin ? "Microsoft® Windows® Operating System" : office ? "Microsoft Office" : "-"),
        Company: ed("Company") ?? (winBin || office ? "Microsoft Corporation" : "-"),
        OriginalFileName: ed("OriginalFileName") ?? meta?.o ?? (winBin ? base(image) : "-"),
        CommandLine: a.cmd ?? (image.includes(" ") ? `"${image}"` : image),
        CurrentDirectory: ed("CurrentDirectory") ?? (ms ? "C:\\Windows\\system32\\" : user === "-" ? "-" : `C:\\Users\\${user.split("\\").pop()}\\`),
        User: user,
        // One logon session → one LogonGuid (seeded by the LUID, so a new session has a new GUID).
        LogonGuid: (() => { const h = hx(ctx, `${ctx.companyId}:${host.toLowerCase()}:${user.toLowerCase()}:${luidHex}:logon`, 24); return `{${machine}-${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8, 12)}-${h.slice(12, 24)}}`; })(),
        LogonId: ms ? "0x3E7" : luidHex,
        TerminalSessionId: ms ? "0" : String(ctx.int(`${host}:${user}:session`, 1, 3)),
        IntegrityLevel: a.integrity ?? (ms ? "System" : "Medium"),
        // The authored Hashes line verbatim when it names this binary's hash; else built from the story's hash.
        Hashes: ed("Hashes") && ed("Hashes")!.toLowerCase().includes(sha.toLowerCase()) ? ed("Hashes")! : `SHA256=${sha}${md5 ? `,MD5=${md5}` : ""},IMPHASH=${imphash}`,
        ParentProcessGuid: pName ? guidFor(pName, th?.parent?.inst) : "{00000000-0000-0000-0000-000000000000}",
        ParentProcessId: ppid,
        ParentImage: pImage,
        ParentCommandLine: parentCmd ?? (parentKnown ? (pImage.includes(" ") ? `"${pImage}"` : pImage) : "-"),
        ParentUser: parentUser,
      };
      // A parent we can only name (no path) is shown by name rather than invented: Sysmon prints "-"
      // when it cannot open the parent, so keep the name in ParentCommandLine for the analyst.
      if (!parentKnown && parentName) { data.ParentImage = "-"; data.ParentCommandLine = parentCmd ?? parentName; }
      break;
    }
    case "3": {
      const dst = ev.dst_ip ?? ed("DestinationIp") ?? r("destination.ip") ?? r("RemoteIP") ?? r("crowdstrike.RemoteAddressIP4");
      const dport = (ev.dst_port !== undefined ? String(ev.dst_port) : undefined) ?? ed("DestinationPort") ?? r("destination.port") ?? r("RemotePort") ?? r("crowdstrike.RemotePort");
      if (!dst || !needImage()) return null;
      const inbound = r("crowdstrike.ConnectionDirection") === "1";
      const src = ed("SourceIp") ?? ev.src_ip ?? r("LocalIP") ?? r("crowdstrike.LocalAddressIP4")
        ?? `10.${ctx.int(`${ctx.companyId}:${host}:ip2`, 10, 60)}.${ctx.int(`${ctx.companyId}:${host}:ip3`, 1, 250)}.${ctx.int(`${ctx.companyId}:${host}:ip4`, 10, 250)}`;
      const sport = ed("SourcePort") ?? r("LocalPort") ?? r("crowdstrike.LocalPort") ?? (ev.src_port !== undefined ? String(ev.src_port) : undefined) ?? String(ctx.int(`${ev.id}:sport`, 49152, 65535));
      const protoRaw = (ed("Protocol") ?? ev.protocol ?? r("network.transport") ?? r("Protocol") ?? r("crowdstrike.Protocol") ?? "tcp").toLowerCase();
      const proto = protoRaw === "17" || protoRaw === "udp" ? "udp" : "tcp";
      let dhost = ed("DestinationHostname") ?? ev.network?.domain ?? r("destination.hostname") ?? r("network.destination");
      if (!dhost && r("RemoteUrl")) dhost = r("RemoteUrl")!.replace(/^[a-z]+:\/\//i, "").split(/[/:]/)[0];
      const port = dport ?? "443";
      data = {
        ...head, ProcessGuid: procGuid, ProcessId: pid, Image: image, User: user,
        Protocol: proto, Initiated: ed("Initiated") ?? (inbound ? "false" : "true"),
        SourceIsIpv6: String(src.includes(":")), SourceIp: src, SourceHostname: computer, SourcePort: sport, SourcePortName: "-",
        DestinationIsIpv6: String(dst.includes(":")), DestinationIp: dst, DestinationHostname: dhost ?? "-", DestinationPort: port, DestinationPortName: PORTNAME[port] ?? "-",
      };
      break;
    }
    case "22": {
      const q = ev.dns?.query ?? ed("QueryName") ?? r("dns.question.name") ?? ev.network?.domain;
      if (!q) return null;
      const rc = (ev.dns?.rcode ?? r("dns.response_code") ?? "").toUpperCase();
      const resp = ev.dns?.response ?? r("dns.resolved_ip") ?? r("dns.answers.data");
      // Sysmon writes an A record as "::ffff:1.2.3.4;" — the "type:" prefix is for non-A records.
      const authoredResults = ed("QueryResults")?.replace(/type:\s*1\s+(\d{1,3}(?:\.\d{1,3}){3})/g, "::ffff:$1");
      const results = authoredResults ?? (rc === "NXDOMAIN" ? "-" : resp ? (/^\d{1,3}(\.\d{1,3}){3}$/.test(resp) ? `::ffff:${resp};` : `type:  5 ${resp};`) : "-");
      data = {
        ...head, ProcessGuid: procGuid, ProcessId: pid, QueryName: q,
        QueryStatus: ed("QueryStatus") ?? (rc === "NXDOMAIN" ? "9003" : rc === "SERVFAIL" ? "9002" : "0"),
        QueryResults: results, Image: image, User: user,
      };
      break;
    }
    case "10": {
      const tgt = r("crowdstrike.TargetProcessImageFileName") ?? r("s1.tgtProcName") ?? ed("TargetImage") ?? r("TargetImage") ?? th?.access?.path ?? th?.access?.name;
      const access = accessMask(r("crowdstrike.DesiredAccess")) ?? r("s1.granted_access") ?? ed("GrantedAccess") ?? r("GrantedAccess") ?? th?.access?.granted;
      if (!tgt || !access || !needImage()) return null;
      const tPath = isWinPath(tgt) ? tgt : KNOWN[tgt.toLowerCase()] ?? `${S32}${tgt}`;
      const tPid = seededPid(base(tPath)); // the target's own identity (the same pid its rows and every EDR record show)
      const off = (k: string) => hx(ctx, `${ev.id}:${k}`, 5);
      data = {
        ...head,
        SourceProcessGUID: procGuid, SourceProcessId: pid, SourceThreadId: String(win4(Number(pid) + ctx.int(`${ev.id}:thr`, 1, 40) * 4)), SourceImage: image,
        TargetProcessGUID: guidFor(base(tPath)), TargetProcessId: tPid, TargetImage: tPath,
        GrantedAccess: access,
        CallTrace: ed("CallTrace") ?? `C:\\Windows\\SYSTEM32\\ntdll.dll+${off("a")}|C:\\Windows\\System32\\KERNELBASE.dll+${off("b")}|${image}+${off("c")}`,
        SourceUser: user, TargetUser: "NT AUTHORITY\\SYSTEM",
      };
      break;
    }
    case "11": {
      const target = ev.file?.path ?? ed("TargetFilename") ?? r("file.path") ?? r("crowdstrike.TargetFileName") ?? (r("ActionType")?.startsWith("File") ? joinPath(r("FolderPath"), r("FileName")) : undefined);
      // The writer is unknown on some EDR rows: Sysmon prints "<unknown process>" when it cannot resolve the image.
      if (!target || !isWinPath(target)) return null;
      data = { ...head, ProcessGuid: procGuid, ProcessId: pid, Image: image, TargetFilename: target, CreationUtcTime: utcTime(timeMs), User: user };
      break;
    }
    case "26":
    case "23": {
      const target = ev.file?.path ?? ed("TargetFilename") ?? r("file.path");
      if (!target || !isWinPath(target) || !needImage()) return null;
      const fsha = ev.file?.sha256 ?? r("file.hash.sha256") ?? imageHashes(ctx, target).sha256.toUpperCase();
      data = {
        ...head, ProcessGuid: procGuid, ProcessId: pid, User: user, Image: image, TargetFilename: target,
        Hashes: ed("Hashes") ?? `SHA256=${fsha}`, IsExecutable: String(/\.(exe|dll|sys|scr|com)$/i.test(target)),
        ...(id === "23" ? { Archived: ed("Archived") ?? "true" } : {}),
      };
      break;
    }
    case "12":
    case "13": {
      let path = ev.registry?.path ?? ed("TargetObject") ?? r("registry.path");
      if (!path) return null; // actor may be "<unknown process>" (see event 11)
      const name = ev.registry?.key ?? r("registry.key") ?? (r("registry.data.strings") !== undefined || r("registry.data") !== undefined ? r("registry.value") : undefined);
      const value = ev.registry?.value ?? r("registry.data.strings") ?? r("registry.data") ?? (r("registry.key") !== undefined ? r("registry.value") : undefined);
      if (name && !ed("TargetObject") && !path.toLowerCase().endsWith(`\\${name.toLowerCase()}`)) path = `${path}\\${name}`;
      // Sysmon prints the hive abbreviated and HKCU as HKU\<user SID>.
      const usid = th?.sid ?? sid(ctx, userName, ev.user_email ?? ev.user?.email);
      path = path.replace(/^HKEY_LOCAL_MACHINE\\/i, "HKLM\\").replace(/^HKEY_CLASSES_ROOT\\/i, "HKCR\\").replace(/^(HKEY_CURRENT_USER|HKCU)\\/i, `HKU\\${usid}\\`);
      data = {
        ...head, EventType: ed("EventType") ?? (id === "13" ? "SetValue" : "DeleteValue"), ProcessGuid: procGuid, ProcessId: pid, Image: image, TargetObject: path,
        ...(id === "13" ? { Details: ed("Details") ?? value ?? "(Empty)" } : {}),
        User: user,
      };
      break;
    }
    case "6": {
      const loaded = ed("ImageLoaded");
      if (!loaded) return null;
      data = { ...head, ImageLoaded: loaded, Hashes: ed("Hashes") ?? `SHA256=${imageHashes(ctx, loaded).sha256.toUpperCase()}`, Signed: ed("Signed") ?? "true", Signature: ed("Signature") ?? "Microsoft Windows", SignatureStatus: ed("SignatureStatus") ?? "Valid" };
      break;
    }
    case "17": {
      const pipe = ed("PipeName");
      if (!pipe) return null;
      data = { ...head, EventType: ed("EventType") ?? "CreatePipe", ProcessGuid: procGuid, ProcessId: pid, PipeName: pipe, Image: image, User: user };
      break;
    }
    default:
      // 7 / 8 / 15 are rendered only from authored EventData (no platform event type maps to them).
      return null;
  }

  const record: Record<string, unknown> = { ...sys, ...data };
  const sysXml = `<System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>${id}</EventID><Version>${sys.Version}</Version><Level>4</Level><Task>${id}</Task><Opcode>0</Opcode><Keywords>${sys.Keywords}</Keywords><TimeCreated SystemTime="${sys.TimeCreated}"/><EventRecordID>${sys.EventRecordID}</EventRecordID><Correlation/><Execution ProcessID="${sys.ProcessID}" ThreadID="${sys.ThreadID}"/><Channel>${sys.Channel}</Channel><Computer>${xmlEsc(computer)}</Computer><Security UserID="S-1-5-18"/></System>`;
  const edXml = Object.entries(data).map(([k, v]) => `<Data Name="${k}">${xmlEsc(v)}</Data>`).join("");
  const rawLine = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">${sysXml}<EventData>${edXml}</EventData></Event>`;
  return { sourceId: "sysmon", kind: id, format: "xml", record, rawLine, timeMs };
}

// ── use cases ────────────────────────────────────────────────────────────────
const SCRIPT_HOSTS = "\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$";
const OFFICE_RE = "\\\\(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio)\\.exe$";
const USER_WRITABLE = "\\\\(AppData\\\\(Roaming|Local)|Users\\\\Public|ProgramData|Windows\\\\Temp|AppData\\\\Local\\\\Temp)\\\\";
const COMMS_APPS = "\\\\(Teams|Zoom|slack|OneDrive|Code|Discord|WhatsApp)\\.exe$";

const useCases: UseCase[] = [
  {
    id: "sysmon.office_spawns_script_host", title: "Office application spawned a script host", sourceId: "sysmon", kinds: ["1"],
    severity: "high", mitre: ["T1204.002", "T1059.001", "T1566.001"],
    description: "Word, Excel or Outlook almost never needs to start PowerShell, cmd, wscript or mshta. When it does, a macro or exploit in the opened document is usually running code. Read the child's CommandLine, then follow its ProcessGuid into events 22/3/11 to see what it downloaded.",
    logic: "Sigma/KQL: Sysmon | where EventID == 1 and ParentImage matches regex @\"\\\\(winword|excel|powerpnt|outlook)\\.exe$\" and Image matches regex @\"\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$\"",
    match: { all: [{ field: "EventID", op: "eq", value: 1 }, { field: "ParentImage", op: "regex", value: OFFICE_RE }, { field: "Image", op: "regex", value: SCRIPT_HOSTS }] },
    falsePositives: ["Legacy Excel add-ins that shell out to cmd for reporting", "Outlook opening a link handler"],
  },
  {
    id: "sysmon.encoded_powershell", title: "PowerShell with an encoded / hidden command line", sourceId: "sysmon", kinds: ["1"],
    severity: "high", mitre: ["T1059.001", "T1027.010"],
    description: "`-enc` / `-EncodedCommand` hides the real script as base64 UTF-16; together with `-w hidden`, `-nop` or `-ep bypass` it is the most common way loaders start. Decode the blob (it is UTF-16LE base64) and look at what the parent was.",
    logic: "KQL: Sysmon | where EventID == 1 and Image endswith @\"\\powershell.exe\" | where CommandLine matches regex @\"(?i)\\s-(e|en|enc|enco|encodedcommand|ec)\\s\" or CommandLine has_all (\"-w\",\"hidden\")",
    match: { all: [{ field: "EventID", op: "eq", value: 1 }, { field: "Image", op: "regex", value: "\\\\(powershell|pwsh)\\.exe$" },
      { any: [{ field: "CommandLine", op: "regex", value: "\\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand|ec)\\s" }, { field: "CommandLine", op: "regex", value: "-w(indowstyle)?\\s+hidden" }, { field: "CommandLine", op: "regex", value: "FromBase64String" }] }] },
    falsePositives: ["Configuration-management agents (SCCM/Intune) that pass scripts encoded", "Some vendor installers"],
  },
  {
    id: "sysmon.lsass_access", title: "Suspicious process opened LSASS memory", sourceId: "sysmon", kinds: ["10"],
    severity: "critical", mitre: ["T1003.001"],
    description: "Credential dumpers (Mimikatz, procdump, comsvcs MiniDump, custom loaders) open lsass.exe with VM_READ rights. Event 10 with TargetImage lsass.exe and a GrantedAccess such as 0x1010, 0x1410, 0x143a or 0x1fffff from a non-system SourceImage — especially with an UNKNOWN frame in CallTrace — means credentials were likely read.",
    logic: "KQL: Sysmon | where EventID == 10 and TargetImage endswith @\"\\lsass.exe\" and GrantedAccess in~ (\"0x1010\",\"0x1410\",\"0x1438\",\"0x143a\",\"0x1fffff\") and SourceImage !in~ (MsMpEng.exe, csrss.exe, wininit.exe)",
    match: { all: [{ field: "EventID", op: "eq", value: 10 }, { field: "TargetImage", op: "regex", value: "\\\\lsass\\.exe$" },
      { field: "GrantedAccess", op: "regex", value: "^0x(1010|1410|1438|143a|1f0fff|1f1fff|1f3fff|1fffff)$" },
      { not: { field: "SourceImage", op: "regex", value: "\\\\(MsMpEng|csrss|wininit|lsm|svchost|MsSense)\\.exe$" } }] },
    falsePositives: ["EDR/AV engines not on the allow-list", "Windows Error Reporting (WerFault) after an LSASS crash"],
  },
  {
    id: "sysmon.run_key_persistence", title: "Run / RunOnce key pointing to a user-writable or proxy binary", sourceId: "sysmon", kinds: ["13"],
    severity: "high", mitre: ["T1547.001"],
    description: "A value written under ...\\CurrentVersion\\Run(Once) starts at every logon. Legitimate software installs to Program Files; a Run value that points into AppData, Temp, ProgramData or Public, or launches rundll32/powershell, is classic malware persistence. Details holds the command that will run.",
    logic: "KQL: Sysmon | where EventID == 13 and TargetObject matches regex @\"\\\\CurrentVersion\\\\Run(Once)?\\\\\" and Details matches regex @\"AppData|\\\\Temp\\\\|ProgramData|Users\\\\Public|rundll32|powershell\"",
    match: { all: [{ field: "EventID", op: "eq", value: 13 }, { field: "TargetObject", op: "regex", value: "\\\\CurrentVersion\\\\Run(Once)?\\\\" },
      { field: "Details", op: "regex", value: "AppData|\\\\Temp\\\\|ProgramData|Users\\\\Public|rundll32|powershell|mshta|wscript" }] },
    falsePositives: ["Per-user installs (Teams, Zoom, Spotify) that live in AppData — check signer/company"],
  },
  {
    id: "sysmon.payload_drop_user_writable", title: "Executable/script dropped into a user-writable folder by a script host or Office", sourceId: "sysmon", kinds: ["11"],
    severity: "medium", mitre: ["T1105", "T1036.005"],
    description: "Loaders write their second stage into %AppData%, %Temp%, ProgramData or C:\\Users\\Public, often with a system-like name (svchost_update.exe). A FileCreate of an .exe/.dll/.ps1/.vbs/.hta there by PowerShell, cmd, wscript, mshta or an Office app is the drop step.",
    logic: "KQL: Sysmon | where EventID == 11 and TargetFilename matches regex @\"\\\\(AppData|ProgramData|Users\\\\Public|Temp)\\\\.*\\.(exe|dll|ps1|vbs|js|hta|bat|scr)$\" and Image matches regex @\"(powershell|cmd|wscript|mshta|winword|excel)\\.exe$\"",
    match: { all: [{ field: "EventID", op: "eq", value: 11 }, { field: "TargetFilename", op: "regex", value: `${USER_WRITABLE}.*\\.(exe|dll|ps1|vbs|js|hta|bat|scr)$` },
      { any: [{ field: "Image", op: "regex", value: SCRIPT_HOSTS }, { field: "Image", op: "regex", value: OFFICE_RE }] }] },
    falsePositives: ["Admin scripts that stage installers in ProgramData", "Self-updating apps writing to AppData"],
  },
  {
    id: "sysmon.network_from_user_writable", title: "Outbound connection by a binary running from a user-writable folder", sourceId: "sysmon", kinds: ["3"],
    severity: "high", mitre: ["T1071.001", "T1105"],
    description: "After a drop, the payload itself calls home. An Initiated=true connection whose Image lives in AppData/Temp/ProgramData/Public (and is not a known per-user app like Teams or Zoom) ties the dropped file to its C2 IP — pivot DestinationIp to firewall/proxy and DestinationHostname to DNS.",
    logic: "KQL: Sysmon | where EventID == 3 and Initiated == \"true\" and Image matches regex @\"\\\\(AppData|ProgramData|Users\\\\Public|Temp)\\\\\" and Image !matches regex @\"(Teams|Zoom|slack|OneDrive)\\.exe$\"",
    match: { all: [{ field: "EventID", op: "eq", value: 3 }, { field: "Initiated", op: "eq", value: "true" }, { field: "Image", op: "regex", value: USER_WRITABLE },
      { not: { field: "Image", op: "regex", value: COMMS_APPS } }] },
    falsePositives: ["Per-user installs of collaboration or dev tools not in the exclusion list"],
  },
  {
    id: "sysmon.dns_by_unusual_process", title: "DNS lookup by a script host / LOLBin or a binary in a user-writable folder", sourceId: "sysmon", kinds: ["22"],
    severity: "medium", mitre: ["T1071.004", "T1059"],
    description: "Event 22 is the only Windows record that ties a DNS lookup to the process that made it. Browsers and mail clients resolve names all day; PowerShell, rundll32, mshta or a binary in AppData/Temp resolving an external name is usually a downloader or beacon. Correlate QueryName with the DNS server logs and the next event 3.",
    logic: "KQL: Sysmon | where EventID == 22 | where Image matches regex @\"\\\\(powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin)\\.exe$\" or (Image matches regex @\"\\\\(AppData|Temp|ProgramData|Users\\\\Public)\\\\\" and Image !matches regex @\"(Teams|Zoom|slack)\\.exe$\")",
    match: { all: [{ field: "EventID", op: "eq", value: 22 }, { any: [
      { field: "Image", op: "regex", value: "\\\\(powershell|pwsh|rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin)\\.exe$" },
      { all: [{ field: "Image", op: "regex", value: USER_WRITABLE }, { not: { field: "Image", op: "regex", value: COMMS_APPS } }] }] }] },
    falsePositives: ["Admin PowerShell resolving internal hosts", "Per-user apps not in the exclusion list"],
  },
  {
    id: "sysmon.dns_long_label", title: "Process resolved a name with a very long encoded label", sourceId: "sysmon", kinds: ["22"],
    severity: "high", mitre: ["T1071.004", "T1048.003"],
    description: "DNS tunnels pack data into labels up to 63 characters. A QueryName whose first label is 40+ characters of base32/base64/hex, made by a specific Image, names the exact tunnelling process on the endpoint — something the DNS server logs alone cannot do.",
    logic: "KQL: Sysmon | where EventID == 22 and QueryName matches regex @\"^[A-Za-z0-9+/=_-]{40,}\\.\"",
    match: { all: [{ field: "EventID", op: "eq", value: 22 }, { field: "QueryName", op: "regex", value: "^[A-Za-z0-9+/=_-]{40,}\\." }] },
    falsePositives: ["Security products that query hash-based reputation names", "Some CDN / telemetry endpoints with long hashed subdomains"],
  },
  {
    id: "sysmon.uac_bypass_autoelevate", title: "UAC bypass via auto-elevating binary (fodhelper / computerdefaults / eventvwr)", sourceId: "sysmon", kinds: ["1", "13"],
    severity: "high", mitre: ["T1548.002"],
    description: "Auto-elevating Windows binaries read a per-user registry handler (ms-settings / mscfile Shell\\Open\\command). Malware writes its command there (event 13) and then starts fodhelper/computerdefaults/eventvwr from a script host (event 1), getting High integrity without a UAC prompt.",
    logic: "KQL: Sysmon | where (EventID == 13 and TargetObject matches regex @\"\\\\(ms-settings|mscfile)\\\\Shell\\\\Open\\\\command\") or (EventID == 1 and Image matches regex @\"\\\\(fodhelper|computerdefaults|eventvwr|sdclt)\\.exe$\" and ParentImage matches regex @\"(powershell|cmd)\\.exe$\")",
    match: { any: [
      { all: [{ field: "EventID", op: "eq", value: 13 }, { field: "TargetObject", op: "regex", value: "\\\\(ms-settings|mscfile|exefile)\\\\Shell\\\\Open\\\\command" }] },
      { all: [{ field: "EventID", op: "eq", value: 1 }, { field: "Image", op: "regex", value: "\\\\(fodhelper|computerdefaults|eventvwr|sdclt|slui)\\.exe$" }, { field: "ParentImage", op: "regex", value: "\\\\(powershell|pwsh|cmd|wscript|mshta)\\.exe$" }] }] },
    falsePositives: ["A user opening Default Apps settings from a shell (rare)"],
  },
  {
    id: "sysmon.event_log_clearing", title: "Windows event logs cleared from the command line", sourceId: "sysmon", kinds: ["1"],
    severity: "high", mitre: ["T1685.005"],
    description: "`wevtutil cl Security` (or Clear-EventLog) wipes the evidence an investigation needs; ransomware operators do it right before or after encryption. The parent and user tell you which session did it.",
    logic: "KQL: Sysmon | where EventID == 1 and (CommandLine matches regex @\"wevtutil(\\.exe)?\\s+(cl|clear-log)\\b\" or CommandLine has \"Clear-EventLog\")",
    match: { all: [{ field: "EventID", op: "eq", value: 1 }, { any: [{ field: "CommandLine", op: "regex", value: "wevtutil(\\.exe)?\\s+(cl|clear-log)\\b" }, { field: "CommandLine", op: "icontains", value: "Clear-EventLog" }] }] },
    falsePositives: ["Golden-image build scripts that clear logs before sysprep"],
  },
  {
    id: "sysmon.psexec_service", title: "PsExec service started (remote execution)", sourceId: "sysmon", kinds: ["1"],
    severity: "medium", mitre: ["T1569.002", "T1021.002"],
    description: "PsExec copies PSEXESVC.exe to ADMIN$ and starts it as a service; whatever it runs is a child of PSEXESVC. Legitimate for some admins, but a favourite for ransomware lateral movement — check who connected (4624 type 3) and what ran under it.",
    logic: "KQL: Sysmon | where EventID == 1 and (Image endswith @\"\\PSEXESVC.exe\" or ParentImage endswith @\"\\PSEXESVC.exe\")",
    match: { all: [{ field: "EventID", op: "eq", value: 1 }, { any: [{ field: "Image", op: "regex", value: "\\\\PSEXESVC\\.exe$" }, { field: "ParentImage", op: "regex", value: "\\\\PSEXESVC\\.exe$" }] }] },
    falsePositives: ["IT using PsExec for software deployment"],
  },
  {
    id: "sysmon.schtask_user_writable_payload", title: "Scheduled task created to run a binary from a user-writable folder", sourceId: "sysmon", kinds: ["1"],
    severity: "medium", mitre: ["T1053.005"],
    description: "`schtasks /create … /tr <path>` with the action in AppData, Temp, ProgramData or Public gives malware a persistent, often elevated (/rl highest) foothold. Compare the /tr path with recent event 11 drops.",
    logic: "KQL: Sysmon | where EventID == 1 and Image endswith @\"\\schtasks.exe\" and CommandLine has \"/create\" and CommandLine matches regex @\"/tr\\s+.*(AppData|ProgramData|Users\\\\Public|\\\\Temp\\\\)\"",
    match: { all: [{ field: "EventID", op: "eq", value: 1 }, { field: "Image", op: "regex", value: "\\\\schtasks\\.exe$" }, { field: "CommandLine", op: "icontains", value: "/create" },
      { field: "CommandLine", op: "regex", value: "/tr\\s+.*(AppData|ProgramData|Users\\\\Public|\\\\Temp\\\\)" }] },
    falsePositives: ["Per-user updaters (e.g. browser updaters) registering tasks under AppData"],
  },
];

export const source: NativeSource = {
  schema: {
    sourceId: "sysmon", category: "host_telemetry", card: "host-sysmon.md", product: "Microsoft Sysinternals Sysmon",
    format: "xml", vendorMatch: ["sysmon"], telemetrySources: ["sysmon", "edr"], kinds,
  },
  fromTelemetry,
  useCases,
};
