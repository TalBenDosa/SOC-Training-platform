/**
 * Build a live EdrInvestigation from the attack story running in the SOC
 * Dashboard feed — so "Investigate in EDR" opens the SAME attack the analyst is
 * watching, from the endpoint's point of view (SIEM + EDR = one product).
 *
 * The story's telemetry events already carry real endpoint process data
 * (process.pid / parent_pid / cmdline / path / user / hash.sha256 — see
 * TelemetryEvent in src/lib/sim/types.ts), so we reconstruct the true process
 * ANCESTRY rather than inventing one. Network/file activity and MITRE detections
 * are lifted from the same events.
 *
 * Returns null when the story has no endpoint process telemetry (a pure
 * identity/cloud attack — impossible travel, OAuth consent, password spray):
 * there is no process tree to walk, so the caller falls back to the static
 * console instead of showing an empty tree.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { lookupHash } from "@/lib/sim/hashDatabase";
import { classifyScope } from "./classifyScope";
import { baselinePid, edrAgentFor, isServerHost } from "./hostBaseline";
import type { IocTruth } from "./iocIntel";
import { ecsTechniqueId, signState } from "@/lib/logs/ecsFields";
import type { EdrInvestigation, EdrProcess, EdrDetection, EdrFileOp, EdrTimelineEvent, Verdict } from "./investigations";

const USER_WRITABLE = /\\(AppData|Temp|Users\\[^\\]+\\Downloads|ProgramData)\\|\/tmp\/|\/home\/[^/]+\//i;

/** HH:MM:SS out of an ISO timestamp, TZ-agnostic. */
function hhmmss(ts?: string): string {
  const m = ts?.match(/T(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : (ts ?? "").slice(11, 19) || "00:00:00";
}

function mostCommon(values: (string | undefined)[]): string | undefined {
  const counts = new Map<string, number>();
  for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
}

/** Hostname from a URL string, tolerant of relative/garbage values. */
function hostOf(url?: string): string | undefined {
  if (!url) return undefined;
  try { return new URL(url).hostname; } catch { return undefined; }
}

// Canonical on-disk locations of well-known Windows binaries. A real EDR always shows
// the full image path; the corpus often gives only the bare name for system/parent
// processes (explorer.exe, svchost.exe, WINWORD.EXE). We resolve those to their real
// location — but ONLY for a NON-malicious process, so a payload masquerading as a
// system binary from the wrong folder is never falsely given the legit system path
// (that wrong path is the tell the analyst is meant to catch).
const CANONICAL_IMAGE_PATHS: Record<string, string> = {
  "explorer.exe": "C:\\Windows\\explorer.exe",
  "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
  "services.exe": "C:\\Windows\\System32\\services.exe",
  "lsass.exe": "C:\\Windows\\System32\\lsass.exe",
  "winlogon.exe": "C:\\Windows\\System32\\winlogon.exe",
  "csrss.exe": "C:\\Windows\\System32\\csrss.exe",
  "wininit.exe": "C:\\Windows\\System32\\wininit.exe",
  "smss.exe": "C:\\Windows\\System32\\smss.exe",
  "taskhostw.exe": "C:\\Windows\\System32\\taskhostw.exe",
  "cmd.exe": "C:\\Windows\\System32\\cmd.exe",
  "powershell.exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "pwsh.exe": "C:\\Program Files\\PowerShell\\7\\pwsh.exe",
  "rundll32.exe": "C:\\Windows\\System32\\rundll32.exe",
  "regsvr32.exe": "C:\\Windows\\System32\\regsvr32.exe",
  "mshta.exe": "C:\\Windows\\System32\\mshta.exe",
  "wscript.exe": "C:\\Windows\\System32\\wscript.exe",
  "cscript.exe": "C:\\Windows\\System32\\cscript.exe",
  "conhost.exe": "C:\\Windows\\System32\\conhost.exe",
  "dllhost.exe": "C:\\Windows\\System32\\dllhost.exe",
  "schtasks.exe": "C:\\Windows\\System32\\schtasks.exe",
  "net.exe": "C:\\Windows\\System32\\net.exe",
  "net1.exe": "C:\\Windows\\System32\\net1.exe",
  "reg.exe": "C:\\Windows\\System32\\reg.exe",
  "sc.exe": "C:\\Windows\\System32\\sc.exe",
  "wmic.exe": "C:\\Windows\\System32\\wbem\\WMIC.exe",
  "certutil.exe": "C:\\Windows\\System32\\certutil.exe",
  "bitsadmin.exe": "C:\\Windows\\System32\\bitsadmin.exe",
  "curl.exe": "C:\\Windows\\System32\\curl.exe",
  "whoami.exe": "C:\\Windows\\System32\\whoami.exe",
  "ipconfig.exe": "C:\\Windows\\System32\\ipconfig.exe",
  "userinit.exe": "C:\\Windows\\System32\\userinit.exe",
  "wmiprvse.exe": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
  "w3wp.exe": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
  "fodhelper.exe": "C:\\Windows\\System32\\fodhelper.exe",
  "psexesvc.exe": "C:\\Windows\\PSEXESVC.exe",
  "vssadmin.exe": "C:\\Windows\\System32\\vssadmin.exe",
  "wbadmin.exe": "C:\\Windows\\System32\\wbadmin.exe",
  "bcdedit.exe": "C:\\Windows\\System32\\bcdedit.exe",
  "wevtutil.exe": "C:\\Windows\\System32\\wevtutil.exe",
  "netsh.exe": "C:\\Windows\\System32\\netsh.exe",
  "nltest.exe": "C:\\Windows\\System32\\nltest.exe",
  "dsquery.exe": "C:\\Windows\\System32\\dsquery.exe",
  "taskkill.exe": "C:\\Windows\\System32\\taskkill.exe",
  "tasklist.exe": "C:\\Windows\\System32\\tasklist.exe",
  "systeminfo.exe": "C:\\Windows\\System32\\systeminfo.exe",
  "nslookup.exe": "C:\\Windows\\System32\\nslookup.exe",
  "arp.exe": "C:\\Windows\\System32\\arp.exe",
  "route.exe": "C:\\Windows\\System32\\route.exe",
  "ping.exe": "C:\\Windows\\System32\\PING.EXE",
  "findstr.exe": "C:\\Windows\\System32\\findstr.exe",
  "msiexec.exe": "C:\\Windows\\System32\\msiexec.exe",
  "wusa.exe": "C:\\Windows\\System32\\wusa.exe",
  "robocopy.exe": "C:\\Windows\\System32\\Robocopy.exe",
  "icacls.exe": "C:\\Windows\\System32\\icacls.exe",
  "takeown.exe": "C:\\Windows\\System32\\takeown.exe",
  "spoolsv.exe": "C:\\Windows\\System32\\spoolsv.exe",
  "msdt.exe": "C:\\Windows\\System32\\msdt.exe",
  "odbcconf.exe": "C:\\Windows\\System32\\odbcconf.exe",
  "installutil.exe": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe",
  "msbuild.exe": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe",
  "winword.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
  "excel.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
  "powerpnt.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\POWERPNT.EXE",
  "outlook.exe": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
  "chrome.exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "msedge.exe": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "firefox.exe": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  // macOS / Linux system binaries (RocketStack and other *nix estates)
  "finder": "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
  "launchd": "/sbin/launchd",
  "sh": "/bin/sh",
  "bash": "/bin/bash",
  "zsh": "/bin/zsh",
  "dash": "/bin/dash",
  "docker": "/usr/bin/docker",
  "dockerd": "/usr/bin/dockerd",
  "containerd": "/usr/bin/containerd",
  "kubectl": "/usr/bin/kubectl",
  "python3": "/usr/bin/python3",
  "node": "/usr/bin/node",
  "curl": "/usr/bin/curl",
  "wget": "/usr/bin/wget",
  "ssh": "/usr/bin/ssh",
  "sshd": "/usr/sbin/sshd",
  "sudo": "/usr/bin/sudo",
  "crontab": "/usr/bin/crontab",
  "osascript": "/usr/bin/osascript",
};

/**
 * The image path a real EDR shows — the on-disk location the process ran from, the
 * first field an analyst reads to answer "where did this run from?". When the
 * structured process.path is missing or is a bare filename with no directory, recover
 * the folder from the FIRST executable token of the command line (which carries the
 * full path); then, for a NON-malicious well-known system binary, its canonical
 * location. Only when nothing yields a directory do we fall back to the bare name.
 */
function imagePathOf(p: NonNullable<TelemetryEvent["process"]>, opts?: { malicious?: boolean }): string {
  if (p.path && /[\\/]/.test(p.path)) return p.path;         // already a real path
  const cl = p.cmdline ?? "";
  const m = cl.match(/^\s*"([^"]+?\.[A-Za-z0-9]{2,4})"/)      // "C:\dir\prog.exe" …
        ?? cl.match(/^\s*([A-Za-z]:\\[^\s"]+?\.[A-Za-z0-9]{2,4})(?=\s|$)/)  // C:\dir\prog.exe …
        ?? cl.match(/^\s*(\/[^\s"]+?)(?=\s|$)/);              // /usr/bin/prog …
  if (m && /[\\/]/.test(m[1])) return m[1];
  if (!opts?.malicious) {
    const canon = CANONICAL_IMAGE_PATHS[p.name?.toLowerCase() ?? ""];
    if (canon) return canon;
  }
  return p.path ?? p.name;
}

// R-07: benign "look twice" processes seeded into an otherwise two-node tree so the
// analyst has to actually rule suspects out rather than flag the one tagged node. All
// are genuine signed background processes from real install paths (no bad hash, no
// detection) — a careful reader clears them; they are never the answer.
const DISTRACTOR_POOL: { name: string; path: string; cmdline: string }[] = [
  { name: "OneDrive.exe",        path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",                                  cmdline: "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background" },
  { name: "Teams.exe",           path: "C:\\Users\\Public\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe",             cmdline: "\"Teams.exe\" --type=renderer --enable-features=..." },
  { name: "GoogleUpdate.exe",    path: "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe",                            cmdline: "\"GoogleUpdate.exe\" /ua /installsource scheduler" },
  { name: "MsMpEng.exe",         path: "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24010.7-0\\MsMpEng.exe", cmdline: "\"MsMpEng.exe\"" },
  { name: "SearchIndexer.exe",   path: "C:\\Windows\\System32\\SearchIndexer.exe",                                            cmdline: "C:\\Windows\\System32\\SearchIndexer.exe /Embedding" },
  { name: "RuntimeBroker.exe",   path: "C:\\Windows\\System32\\RuntimeBroker.exe",                                            cmdline: "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding" },
  { name: "SecurityHealthService.exe", path: "C:\\Windows\\System32\\SecurityHealthService.exe",                             cmdline: "C:\\Windows\\System32\\SecurityHealthService.exe" },
  { name: "backgroundTaskHost.exe", path: "C:\\Windows\\System32\\backgroundTaskHost.exe",                                    cmdline: "\"backgroundTaskHost.exe\" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca" },
];

// Signed system binaries and interpreters an attacker "lives off the land" with. When
// one of these is the payload and carries no known-bad hash it is ABUSED, not malware.
const EXTRA_LOLBINS = new Set(["sqlservr.exe", "w3wp.exe", "java.exe", "java", "httpd", "nginx", "node"]);

// Unix/Linux binaries — used to tell a Linux/container host from a Windows one so the
// console never puts an explorer.exe parent over a bash/nsenter tree (R-13 OS mismatch).
const UNIX_PROCS = new Set(["bash", "sh", "zsh", "dash", "curl", "wget", "nsenter", "docker",
  "dockerd", "containerd", "kubectl", "cron", "crond", "sshd", "ssh", "python3", "python",
  "sudo", "systemd", "launchd", "perl", "ruby", "xmrig", "chmod", "chown", "cat", "grep", "scp"]);
function isLolBin(name?: string): boolean {
  const n = name?.toLowerCase() ?? "";
  return Object.prototype.hasOwnProperty.call(CANONICAL_IMAGE_PATHS, n) || EXTRA_LOLBINS.has(n);
}

// Compare two HH:MM:SS stamps for "latest". localeCompare is correct within a day; a
// tree that crosses midnight is vanishingly rare in one incident, so this stays simple.
const tsSort = (a: string, b: string) => a.localeCompare(b);

// Parents that have no business launching another executable — an Office doc or
// a script host spawning a child is the classic "living off the land" tell.
const ANOMALOUS_PARENTS = new Set([
  "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
  "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe", "powershell.exe",
]);

/**
 * The behavioural "why this stands out" a real EDR surfaces BEYOND the raw log
 * line — the enrichment the student reasons from. Shown in the debrief after the
 * decision (never up front, so it can't leak the answer). Built from the same
 * telemetry, so it stays tied to the case.
 */
function whyItStandsOut(
  p: NonNullable<TelemetryEvent["process"]>,
  o: { signed: boolean; malicious?: boolean; userWritable: boolean; imagePath?: string },
): string | undefined {
  const path = o.imagePath ?? p.path ?? "?";
  const bits: string[] = [];
  if (o.malicious) bits.push("its SHA-256 matches a known-bad sample on record");
  if (!o.signed && o.userWritable) bits.push(`it runs UNSIGNED from a user-writable path (${path}) — a real system binary never does`);
  else if (!o.signed) bits.push("it is not digitally signed");
  else if (o.userWritable) bits.push(`it runs from a user-writable path (${path})`);
  const parent = p.parent_name?.toLowerCase();
  if (parent && ANOMALOUS_PARENTS.has(parent) && p.name.toLowerCase() !== parent)
    bits.push(`its parent is ${p.parent_name}, which has no legitimate reason to launch this`);
  if (bits.length === 0) return undefined;
  return "Why it stands out: " + bits.join("; ") + ".";
}

// R-11: recover a process object from an endpoint detection that carries the binary
// only in its vendor-native raw block (CrowdStrike `crowdstrike.process_name`,
// SentinelOne `s1.process_name`, Sysmon `Image`, MDE `process.name`…), so a case whose
// EDR events never populated the structured `process` field still opens with a walkable
// tree. Returns [] when nothing names a real binary — a sensor-silence or pure-network
// detection legitimately has no process tree and stays a non-EDR investigation.
const PROC_NAME_KEYS = ["process.name", "process.image", "crowdstrike.process_name", "crowdstrike.ImageFileName", "s1.process_name", "Image", "InitiatingProcessFileName", "proc.name", "ProcessName"];
const CMDLINE_KEYS   = ["process.command_line", "crowdstrike.CommandLine", "s1.command_line", "CommandLine", "cmdline", "InitiatingProcessCommandLine"];
const PARENT_KEYS    = ["process.parent.name", "crowdstrike.parent_basefilename", "ParentImage", "s1.parent_process_name", "InitiatingProcessParentFileName"];
const PROC_USER_KEYS = ["process.user", "crowdstrike.UserName", "user.name", "s1.process_user", "User", "SubjectUserName"];
const baseName = (v: string) => v.split(/[\\/]/).pop() ?? v;
function pickRaw(raw: Record<string, unknown> | undefined, keys: string[]): string | undefined {
  for (const k of keys) { const v = raw?.[k]; if (typeof v === "string" && v.trim()) return v.trim(); }
  return undefined;
}
function synthesizeProcessEvents(endpointEvents: TelemetryEvent[]): TelemetryEvent[] {
  const out: TelemetryEvent[] = [];
  const byName = new Map<string, number>();  // name → assigned pid (dedupe)
  let nextPid = 4000;
  for (const e of endpointEvents) {
    const rawName = pickRaw(e.raw, PROC_NAME_KEYS);
    const name = rawName ? baseName(rawName) : undefined;
    if (!name || !/^[\w.-]+$/.test(name)) continue;      // must be a real binary token
    const cmdline = pickRaw(e.raw, CMDLINE_KEYS) ?? name;
    const parent = pickRaw(e.raw, PARENT_KEYS);
    const user = pickRaw(e.raw, PROC_USER_KEYS) ?? e.user_email;
    let pid = byName.get(`${name}|${cmdline}`);
    if (pid == null) { pid = nextPid++; byName.set(`${name}|${cmdline}`, pid); }
    out.push({
      ...e,
      process: {
        pid,
        name,
        cmdline,
        parent_name: parent ? baseName(parent) : undefined,
        user,
        hash: e.file?.sha256 ? { sha256: e.file.sha256 } : undefined,
      },
    });
  }
  return out;
}


// Endpoint telemetry sources — what an EDR sensor (or the host's own audit log) records.
const ENDPOINT_SOURCES = new Set(["edr", "sysmon", "linux_audit", "windows_security"]);
// Perimeter / network-sensor sources. The firewall's line for a connection is the
// NETWORK's view of it, not endpoint telemetry: mixing it into the EDR timeline showed
// one upload twice (sensor NetworkConnectIP4 + PAN TRAFFIC), and pinning it on a
// process guessed at an owner the log never names.
const PERIMETER_SOURCES = new Set(["firewall", "proxy", "ids", "waf", "dns", "vpn", "nac", "email_gateway", "dhcp"]);

// Binaries the Service Control Manager launches — on a real host their parent is
// services.exe (PSEXESVC runs as SYSTEM under services.exe), never a user's explorer.
const SERVICE_BINARIES = new Set(["psexesvc.exe", "svchost.exe", "spoolsv.exe", "msmpeng.exe", "sqlservr.exe",
  "dfssvc.exe", "vmtoolsd.exe", "csfalconservice.exe", "mssense.exe", "sentinelagent.exe", "veeamagent.exe"]);
const SYSTEM_PRINCIPAL = /^(nt authority\\(system|local ?service|network ?service)|system|localsystem)$/i;
const SYSTEM_USER = "NT AUTHORITY\\SYSTEM";

// Processes that legitimately sit at (or near) the top of a tree — never re-parented.
const WIN_ROOTS = new Set(["system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
  "lsass.exe", "explorer.exe", "userinit.exe"]);
const UNIX_ROOTS = new Set(["systemd", "init", "launchd", "sshd", "bash", "sh", "zsh", "dash", "dockerd",
  "containerd", "cron", "crond", "kubelet", "containerd-shim"]);

const HIGH = (e: TelemetryEvent) => e.severity === "high" || e.severity === "critical";

/** MITRE technique id — typed field, else the vendor raw copy (it survives the
 *  scenario page's F-02 projection, which strips only the typed mapping). */
function techniqueOf(e: TelemetryEvent): string | undefined {
  return e.mitre_technique ?? ecsTechniqueId(e.raw) ?? pickRaw(e.raw, ["AttackTechniques"]);
}

/** The process chain a behavioural detection names: a Falcon detection's Grandparent → Parent →
 *  triggering image (GrandparentImageFileName / ParentImageFileName / FileName), else a
 *  free-text tree ("services.exe > PSEXESVC.exe > cmd.exe") from another product. */
function detectionChain(e: TelemetryEvent): string[] {
  const v = pickRaw(e.raw, ["process_tree", "ProcessTree"]);
  if (v) return v.split(/\s*(?:>|›|→)\s*/).map(s => baseName(s.trim())).filter(Boolean);
  if (!pickRaw(e.raw, ["crowdstrike.ParentImageFileName"])) return [];
  return ["crowdstrike.GrandparentImageFileName", "crowdstrike.ParentImageFileName", "crowdstrike.FileName"]
    .map(k => pickRaw(e.raw, [k])).filter((s): s is string => !!s).map(s => baseName(s));
}

function tsMs(ts?: string): number {
  const n = ts ? Date.parse(ts) : NaN;
  return Number.isNaN(n) ? 0 : n;
}

function fmtBytes(n?: number): string {
  if (!n) return "";
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}
const trunc = (s: string | undefined, n: number) => !s ? "" : s.length > n ? `${s.slice(0, n - 1)}…` : s;

/**
 * The timeline line for an event. The authored description when the surface has it;
 * on the scenario page (where descriptions are stripped until the debrief) a factual
 * line built from the event's own fields — never "process create".
 */
function describeEvent(e: TelemetryEvent): string {
  if (e.description) return e.description;
  const p = e.process;
  const raw = e.raw ?? {};
  const det = pickRaw(raw, ["crowdstrike.DetectName", "threat.name", "AlertTitle", "alert.name"]);
  const chain = detectionChain(e);
  const t = e.event_type;
  if (t === "edr_alert" || t === "av_detection" || (!p && det && e.is_detection)) {
    const disp = pickRaw(raw, ["crowdstrike.PatternDispositionDescription", "remediation.action"]);
    return `Detection: ${det || "EDR alert"}${e.severity ? ` (${e.severity})` : ""}${chain.length ? ` — ${chain.join(" › ")}` : ""}${disp ? ` · ${disp}` : ""}`;
  }
  if (t === "process_access" && p) {
    const target = pickRaw(raw, ["crowdstrike.CrossProcessTargetName", "TargetImage", "target.process.name"]);
    const tpid = pickRaw(raw, ["crowdstrike.CrossProcessTargetPid", "TargetProcessId"]);
    const access = pickRaw(raw, ["crowdstrike.GrantedAccess", "GrantedAccess"]);
    return `${p.name}(${p.pid}) opened ${target ? baseName(target) : "another process"}${tpid ? `(${tpid})` : ""}${access ? ` with access ${access}` : ""}`;
  }
  if (p && (t === "process_create" || t === "linux_execve" || t === "scheduled_task" || t === "service_install")) {
    return `${p.parent_name ?? "?"}${p.parent_pid ? `(${p.parent_pid})` : ""} → ${p.name}(${p.pid}): ${trunc(p.cmdline, 110)}`;
  }
  if (t === "net_connection" || t === "http_request" || t === "net_blocked" || t === "http_blocked") {
    const dom = e.network?.domain ?? hostOf(e.network?.url);
    return `${p ? `${p.name}(${p.pid}) → ` : `${e.src_ip ?? "?"} → `}${e.dst_ip ?? "?"}:${e.dst_port ?? "?"}${dom ? ` (${dom})` : ""}${e.network?.bytes_out ? ` · ${fmtBytes(e.network.bytes_out)} out` : ""}`;
  }
  if (t === "dns_query") return `DNS query ${e.dns?.query ?? e.network?.domain ?? "?"}${e.dns?.response ? ` → ${e.dns.response}` : ""}`;
  if (t.startsWith("file") && e.file?.path) return `${t.replace("file_", "File ")}: ${e.file.path}${p ? ` by ${p.name}(${p.pid})` : ""}`;
  const share = pickRaw(raw, ["winlog.event_data.ShareName"]);
  if (t.startsWith("file") && share) {
    const who = pickRaw(raw, ["winlog.event_data.SubjectUserName", "user.name"]);
    const from = pickRaw(raw, ["winlog.event_data.IpAddress"]) ?? e.src_ip;
    return `Network share access ${share}${who ? ` by ${who}` : ""}${from ? ` from ${from}` : ""}`;
  }
  if (t === "service_install" || pickRaw(raw, ["winlog.event_id"]) === "7045") {
    const svc = pickRaw(raw, ["winlog.event_data.ServiceName", "service.name"]);
    const img = pickRaw(raw, ["winlog.event_data.ImagePath", "service.path"]);
    return `Service installed: ${svc ?? "?"}${img ? ` (${img})` : ""}`;
  }
  if (t.startsWith("registry") && e.registry) return `Registry value set: ${e.registry.path ?? ""}${e.registry.key ? `\\${e.registry.key}` : ""}`;
  if (t === "auth_success" || t === "auth_failure") {
    const lt = pickRaw(raw, ["winlog.event_data.LogonType"]) ?? (e.authentication?.logon_type != null ? String(e.authentication.logon_type) : "");
    const who = pickRaw(raw, ["winlog.event_data.TargetUserName", "user.name"]) ?? e.user_email ?? "?";
    return `Logon ${t === "auth_success" ? "success" : "failure"} — ${who}${lt ? ` (type ${lt})` : ""}${e.src_ip ? ` from ${e.src_ip}` : ""}`;
  }
  return t.replace(/_/g, " ");
}

function timelineKind(e: TelemetryEvent): EdrTimelineEvent["kind"] {
  const t = e.event_type;
  if (t === "edr_alert" || t === "av_detection") return "detection";
  if (t.startsWith("net") || t === "http_request" || t === "dns_query" || t === "http_blocked") return "network";
  if (t.startsWith("file")) return "file";
  if ((techniqueOf(e) || e.is_detection) && HIGH(e)) return "detection";
  return "process";
}

/** Deterministic multiple-of-4 PID for an ancestor we have evidence for but no PID. */
function ancestorPid(host: string, name: string, used: Set<number>): number {
  let h = 2166136261;
  for (const c of `${host}|${name}`) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); }
  let pid = 1000 + (Math.abs(h) % 1500) * 4;
  while (used.has(pid)) pid += 4;
  return pid;
}

// ── Persistence parsing (scheduled tasks / services / WMI / Run keys) ────────────
const argOf = (cl: string, flag: string) =>
  cl.match(new RegExp(`${flag}\\s+"([^"]+)"`, "i"))?.[1] ?? cl.match(new RegExp(`${flag}\\s+(\\S+)`, "i"))?.[1];

function persistenceFrom(events: TelemetryEvent[], procs: EdrProcess[]) {
  const tasks: NonNullable<EdrInvestigation["persistence"]>["tasks"] = [];
  const services: NonNullable<EdrInvestigation["persistence"]>["services"] = [];
  const wmi: NonNullable<EdrInvestigation["persistence"]>["wmi"] = [];
  const autoruns: { key: string; value: string }[] = [];
  const seen = new Set<string>();
  const once = (k: string) => (seen.has(k) ? false : (seen.add(k), true));
  for (const e of events) {
    const raw = e.raw ?? {};
    const cl = e.process?.cmdline ?? "";
    const pname = e.process?.name?.toLowerCase() ?? "";
    // Run keys: registry telemetry, an ASEP update, or `reg add …\Run /v … /d …`.
    const regPath = e.registry?.path ?? pickRaw(raw, ["registry.path", "TargetObject", "RegistryKey"]);
    if ((e.event_type ?? "").startsWith("registry") || pickRaw(raw, ["crowdstrike.event_simpleName"]) === "AsepValueUpdate") {
      if (regPath || e.registry?.key) {
        const key = regPath ?? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        const name = e.registry?.key ?? pickRaw(raw, ["registry.value", "RegistryValueName"]) ?? "(Default)";
        const data = e.registry?.value ?? pickRaw(raw, ["registry.data.strings", "Details", "RegistryValueData"]) ?? e.process?.cmdline ?? "(unnamed)";
        if (once(`run|${key}|${name}`)) autoruns.push({ key, value: `${name}    REG_SZ    ${data}` });
      }
    }
    const regAdd = cl.match(/\breg(?:\.exe)?\s+add\s+"?([^"\s]*\\Run(?:Once)?)"?/i);
    if (regAdd) {
      const name = argOf(cl, "/v") ?? "(Default)";
      const data = argOf(cl, "/d") ?? "";
      if (once(`run|${regAdd[1]}|${name}`)) autoruns.push({ key: regAdd[1], value: `${name}    REG_SZ    ${data}` });
    }
    // Scheduled tasks: schtasks /create, the typed scheduled_task event, or 4698.
    if ((pname === "schtasks.exe" && /\/create/i.test(cl)) || e.event_type === "scheduled_task" || pickRaw(raw, ["winlog.event_id"]) === "4698") {
      const name = argOf(cl, "/tn") ?? pickRaw(raw, ["winlog.event_data.TaskName", "task.name"]);
      const action = argOf(cl, "/tr") ?? pickRaw(raw, ["winlog.event_data.TaskContent", "task.action"]) ?? cl;
      if (name && once(`task|${name}`)) tasks.push({ name: name.startsWith("\\") ? name : `\\${name}`, action, author: e.process?.user });
    }
    // Services: sc create, the typed service_install event, or 7045.
    const scCreate = pname === "sc.exe" && cl.match(/\bcreate\s+"?([\w.-]+)"?/i);
    if (scCreate || e.event_type === "service_install" || pickRaw(raw, ["winlog.event_id"]) === "7045") {
      const name = (scCreate ? scCreate[1] : undefined) ?? pickRaw(raw, ["winlog.event_data.ServiceName", "service.name"]);
      const bin = argOf(cl, "binPath=") ?? pickRaw(raw, ["winlog.event_data.ImagePath", "service.path"]) ?? "";
      if (name && once(`svc|${name.toLowerCase()}`)) services.push({ name, binPath: bin, account: pickRaw(raw, ["winlog.event_data.AccountName"]) ?? "LocalSystem", start: pickRaw(raw, ["winlog.event_data.StartType"]) ?? "DEMAND_START", running: true });
    }
    // WMI event subscriptions: the wmic / PowerShell creation or Sysmon 19-21 fields.
    if (/__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer|__FilterToConsumerBinding/i.test(cl) || pickRaw(raw, ["EventNamespace", "Consumer"])) {
      const filter = cl.match(/Name\s*=\s*['"]([^'"]+)['"]/i)?.[1] ?? pickRaw(raw, ["Name", "wmi.filter"]) ?? "Unnamed filter";
      const query = cl.match(/Query\s*=\s*['"]([^'"]+)['"]/i)?.[1] ?? pickRaw(raw, ["Query"]);
      const command = cl.match(/CommandLineTemplate\s*=\s*['"]([^'"]+)['"]/i)?.[1] ?? pickRaw(raw, ["Destination", "wmi.command"]) ?? cl;
      if (once(`wmi|${filter}`)) wmi.push({ filter, query, consumer: pickRaw(raw, ["Consumer"]) ?? "CommandLineEventConsumer", command });
    }
  }
  // A PsExec landing means the PSEXESVC service is installed on this host.
  const psexe = procs.find(p => p.name.toLowerCase() === "psexesvc.exe");
  if (psexe && !services.some(s => s.name.toLowerCase() === "psexesvc")) {
    services.push({ name: "PSEXESVC", binPath: "%SystemRoot%\\PSEXESVC.exe", account: "LocalSystem", start: "DEMAND_START", running: true });
  }
  return { autoruns, persistence: { tasks, services, wmi } };
}

export function buildInvestigationFromStory(
  story: { id: string; title: string; events: TelemetryEvent[]; iocTruth?: IocTruth | null },
): EdrInvestigation | null {
  // A copy — the synthesis step below appends events, and the caller's array (a
  // scenario bundle or the Dashboard's story) must never be mutated.
  const events = [...(story.events ?? [])];

  // R-02: a story with NO endpoint (EDR / Sysmon / host-audit / Windows Security)
  // telemetry is not an endpoint investigation. Kerberoasting, for example, lives in
  // AD + DB-audit + SIEM; opening an EDR console for it forces the student to flag the
  // victim's own legitimate, signed SQL Server as "malware" — the exact opposite of
  // what the Kerberoasting room teaches. Such cases stay identity/DB investigations.
  if (!events.some(e => ENDPOINT_SOURCES.has(e.source))) return null;

  let procEvents = events.filter(e => e.process?.name && typeof e.process.pid === "number");

  // R-11: endpoint telemetry exists but the EDR detections carry no process object
  // (ESXi ransomware, k8s pod escape, some chains) — synthesise a minimal process from
  // the endpoint detections that DO name a binary, so the case opens instead of leaving
  // the "Investigate in EDR" button silently dead. Only synthesise when we can name a
  // real binary (file.path/name or a process-like token in the raw); never fabricate.
  if (procEvents.length === 0) {
    const synth = synthesizeProcessEvents(events.filter(e => ENDPOINT_SOURCES.has(e.source)));
    if (synth.length === 0) return null; // nothing nameable — leave it non-EDR
    events.push(...synth);
    procEvents = synth;
  }

  // Is this a Linux / container / macOS host? Drives OS-correct tree roots, the host
  // header, and the user format (R-13).
  const winProcCount = procEvents.filter(e => /\.exe$/i.test(e.process?.name ?? "")).length;
  const nixProcCount = procEvents.filter(e => {
    const n = e.process?.name?.toLowerCase() ?? "";
    return UNIX_PROCS.has(n) || (!!n && !/\.\w{2,4}$/.test(n));
  }).length;
  const isLinux = events.some(e => e.source === "linux_audit" || e.source === "k8s_audit")
    || nixProcCount > winProcCount
    || procEvents.some(e => (e.process?.path ?? "").startsWith("/"));

  // R-13: one user format across the whole tree (DOMAIN\user on Windows, bare on unix).
  const caseDomain = mostCommon(events.map(e => e.user_email?.includes("@") ? e.user_email.split("@")[1] : undefined));
  const netbios = (caseDomain?.split(".")[0] ?? "").toUpperCase();
  const normUser = (u?: string): string => {
    if (!u || !u.trim()) return "unknown";
    const v = u.trim();
    if (v.includes("\\")) return v;
    if (/^(nt authority|builtin|nt service|nt virtual|window manager|font driver)/i.test(v)) return v;
    const bare = v.includes("@") ? v.split("@")[0] : v;
    if (isLinux) return bare;
    return netbios ? `${netbios}\\${bare}` : bare;
  };

  // ── Host identity (needed early: the baseline PIDs are seeded from it) ──
  const hostName = mostCommon(procEvents.map(e => e.hostname)) ?? mostCommon(events.map(e => e.hostname)) ?? "endpoint";
  const server = !isLinux && isServerHost({ name: hostName });
  const edrAgent = isLinux ? undefined : (edrAgentFor(events.filter(e => ENDPOINT_SOURCES.has(e.source)).map(e => e.vendor ?? "")) ?? undefined);

  // PIDs the telemetry names for background processes — the lsass.exe an LSASS dump
  // targeted, so `ps` prints the same PID the access event did.
  const knownPids: Record<string, number> = {};
  for (const e of events) {
    const target = pickRaw(e.raw, ["crowdstrike.CrossProcessTargetName", "TargetImage", "target.process.name"]);
    const tpid = Number(pickRaw(e.raw, ["crowdstrike.CrossProcessTargetPid", "TargetProcessId"]) ?? NaN);
    if (target && Number.isFinite(tpid) && tpid > 0) knownPids[baseName(target).toLowerCase()] = tpid;
  }

  // ── Processes (deduped by pid), plus stubs for referenced-but-unseen parents ──
  const procByPid = new Map<number, EdrProcess>();
  // When each process came into existence (epoch ms); null = before the telemetry
  // window (an ancestor we only know from a child). Drives "who could own this
  // connection at this moment" — a process never owns traffic from before it existed.
  const startMs = new Map<number, number | null>();
  const seedProcess = (e: TelemetryEvent) => {
    const p = e.process!;
    if (procByPid.has(p.pid)) return;
    const sha256 = p.hash?.sha256;
    const malicious = sha256 ? lookupHash(sha256)?.malicious : false;
    const imagePath = imagePathOf(p, { malicious });   // real on-disk path (recovered from cmdline / canonical if needed)
    const userWritable = USER_WRITABLE.test(imagePath);
    // E-02: signing is authoritative when the log states it (the log always wins over
    // the heuristic); only when the log is silent do we fall back to it.
    // ECS process.code_signature.*: any signature (trusted or not) counts as signed; a
    // revoked certificate or no signature at all does not.
    const sign = signState(e.raw, "process");
    const rawSigned =
      (e.raw?.["process.signed"] ?? e.raw?.["file.signed"] ?? e.raw?.["code_signature.signed"] ??
       (sign ? sign === "trusted" || sign === "untrusted" : undefined) ?? e.raw?.["file.code_signature.valid"] ??
       e.raw?.["mde.SignatureStatus"]) as unknown;
    const signed = rawSigned != null
      ? !/^(false|no|0|unsigned|invalid|revoked|untrusted)$/i.test(String(rawSigned).trim())
      : !malicious && !userWritable;
    // Suspicion signals that survive the scenario page's projection (which strips the
    // typed MITRE mapping): a raw technique id, the alert-grade flag, an unsigned image.
    const tech = techniqueOf(e);
    const verdict: Verdict = malicious
      ? "malicious"
      : (tech && HIGH(e)) || (e.is_detection && (HIGH(e) || e.severity === "medium")) || userWritable || (rawSigned != null && !signed)
        ? "suspicious"
        : "benign";
    const ofn = pickRaw(e.raw, ["process.original_file_name", "pe.original_file_name", "OriginalFileName",
      "ProcessVersionInfoOriginalFileName", "crowdstrike.OriginalFilename"]);
    procByPid.set(p.pid, {
      pid: p.pid,
      ppid: p.parent_pid ?? 0,
      name: p.name,
      cmdline: p.cmdline ?? p.name,
      user: normUser(p.user ?? e.user_email ?? e.user?.email),
      path: imagePath,
      signed,
      sha256,
      ...(ofn ? { originalFileName: ofn } : {}),
      startedAt: hhmmss(e.ts),
      verdict,
      note: verdict === "benign" ? undefined : whyItStandsOut(p, { signed, malicious, userWritable, imagePath }),
      network: [],
      files: [],
    });
    // A process_create/exec IS the start; any other event only proves "alive by then".
    startMs.set(p.pid, tsMs(e.ts));
  };
  for (const e of [...procEvents].sort((a, b) => tsMs(a.ts) - tsMs(b.ts))) {
    seedProcess(e);
    const p = e.process!;
    if (p.parent_pid != null && p.parent_pid !== 0 && !procByPid.has(p.parent_pid)) {
      // A parent we never saw a create event for — add a benign stub so the tree
      // connects (real consoles show the ancestor even without its own row). It
      // started before the telemetry window, so its start time is unknown ("—").
      const parentName = p.parent_name ?? "process";
      const ln = parentName.toLowerCase();
      const parentPath = imagePathOf({ pid: p.parent_pid, name: parentName, cmdline: parentName }, { malicious: false });
      procByPid.set(p.parent_pid, {
        pid: p.parent_pid, ppid: 0, name: parentName,
        cmdline: p.parent_name ? parentPath : "—",
        user: SERVICE_BINARIES.has(ln) || ln === "services.exe" ? SYSTEM_USER : normUser(p.user),
        path: parentPath, signed: true, startedAt: "—", verdict: "benign",
        network: [], files: [],
      });
      startMs.set(p.parent_pid, null);
    }
  }

  // ── Ancestry — from the events, never invented ──
  // #8: every tree used to start at a synthetic explorer.exe (PID 90000, PPID 0) on
  // every host, servers included, with PSEXESVC sitting under it as the user. Now an
  // orphan's parent comes from evidence only:
  //   1. the detection's own process chain ("services.exe > PSEXESVC.exe > cmd.exe");
  //   2. the Service Control Manager for service binaries / SYSTEM-owned processes;
  //   3. the host's REAL explorer.exe, when the telemetry has one, for user apps.
  // An ancestor we have evidence for but no PID (services.exe) takes the same PID the
  // RTR `ps` baseline prints for it. With no evidence the process stays a root.
  const chainParent = new Map<string, string>();
  for (const e of events) {
    const chain = detectionChain(e);
    for (let i = 1; i < chain.length; i++) {
      const k = chain[i].toLowerCase();
      if (!chainParent.has(k)) chainParent.set(k, chain[i - 1]);
    }
  }
  const realExplorer = [...procByPid.values()].find(p => p.name.toLowerCase() === "explorer.exe");
  const hostUser = normUser(mostCommon(procEvents.map(e => e.process?.user ?? e.user_email).filter(u => u && !SYSTEM_PRINCIPAL.test(u))));
  const usedPids = new Set(procByPid.keys());
  const findByName = (n: string) => [...procByPid.values()].find(p => p.name.toLowerCase() === n.toLowerCase());
  const ensureAncestor = (name: string): EdrProcess => {
    const existing = findByName(name);
    if (existing) return existing;
    const ln = name.toLowerCase();
    let pid = (!isLinux ? baselinePid(hostName, ln, knownPids) : undefined) ?? ancestorPid(hostName, ln, usedPids);
    while (usedPids.has(pid)) pid += 4;
    usedPids.add(pid);
    const sessionZero = /^(services|wininit|smss|csrss|lsass|winlogon|svchost)\.exe$/.test(ln) || SERVICE_BINARIES.has(ln);
    const proc: EdrProcess = {
      pid, ppid: ln === "services.exe" ? (baselinePid(hostName, "wininit.exe") ?? 0) : 0, name,
      cmdline: imagePathOf({ pid, name, cmdline: name }, { malicious: false }),
      user: isLinux ? "root" : sessionZero ? SYSTEM_USER : hostUser,
      path: imagePathOf({ pid, name, cmdline: name }, { malicious: false }),
      signed: true, startedAt: "—", verdict: "benign", network: [], files: [],
    };
    procByPid.set(pid, proc);
    startMs.set(pid, null);
    return proc;
  };
  const isAncestorOf = (anc: EdrProcess, p: EdrProcess) => {
    let cur: EdrProcess | undefined = anc;
    for (let i = 0; cur && i < 64; i++) { if (cur.pid === p.pid) return true; cur = procByPid.get(cur.ppid); }
    return false;
  };
  for (let pass = 0; pass < 6; pass++) {
    let changed = false;
    for (const p of [...procByPid.values()]) {
      if (p.ppid !== 0 && procByPid.has(p.ppid)) continue;          // already connected
      const n = p.name.toLowerCase();
      if (isLinux ? UNIX_ROOTS.has(n) && !chainParent.has(n) : WIN_ROOTS.has(n)) continue;
      let parentName = chainParent.get(n);
      if (!parentName && !isLinux) {
        if (SERVICE_BINARIES.has(n) || SYSTEM_PRINCIPAL.test(p.user)) parentName = "services.exe";
        else if (realExplorer && realExplorer.pid !== p.pid) parentName = "explorer.exe";
      }
      // R-13: a Linux/container orphan hangs off its shell, never a Windows explorer.
      if (!parentName && isLinux) parentName = "bash";
      if (!parentName || parentName.toLowerCase() === n) continue;
      const parent = ensureAncestor(parentName);
      if (parent.pid === p.pid || isAncestorOf(parent, p)) continue;  // no cycles
      if (p.ppid !== 0 && p.ppid !== parent.pid && !procByPid.has(p.ppid)) {
        // the log named a parent PID we have no row for — keep it; don't overwrite evidence
        continue;
      }
      p.ppid = parent.pid;
      changed = true;
    }
    if (!changed) break;
  }
  // A service-launched stub runs as SYSTEM (PsExec's service does), whatever user
  // its child later impersonates.
  for (const p of procByPid.values()) {
    const parent = procByPid.get(p.ppid);
    if (startMs.get(p.pid) === null && parent?.name.toLowerCase() === "services.exe" && !isLinux) p.user = SYSTEM_USER;
  }

  const processes = [...procByPid.values()];

  // Falcon keys processes by its own id (UPID): a NetworkConnectIP4 / DnsRequest /
  // file event names its actor by ContextProcessId = that process's TargetProcessId,
  // and the OS PID is RawProcessId. Map both back to the tree's PIDs so an event with
  // no structured process block still lands on the process it names — and ONLY that one.
  const upidToPid = new Map<string, number>();
  for (const e of procEvents) {
    const upid = pickRaw(e.raw, ["crowdstrike.TargetProcessId", "crowdstrike.TargetProcessId_decimal"]);
    if (upid && e.process?.pid != null) upidToPid.set(upid, e.process.pid);
  }
  const pidFromRaw = (raw: Record<string, unknown> | undefined): number | undefined => {
    const osPid = Number(pickRaw(raw, ["crowdstrike.RawProcessId", "InitiatingProcessId", "ProcessId"]) ?? NaN);
    if (Number.isFinite(osPid) && procByPid.has(osPid)) return osPid;
    for (const k of ["crowdstrike.ContextProcessId", "crowdstrike.ContextProcessId_decimal", "crowdstrike.ProcessId"]) {
      const v = pickRaw(raw, [k]);
      if (!v) continue;
      const viaUpid = upidToPid.get(v);
      if (viaUpid != null) return viaUpid;
      const n = Number(v);
      if (Number.isFinite(n) && procByPid.has(n)) return n;
    }
    return undefined;
  };

  // ── Detections ────────────────────────────────────────────────────────────
  // E-03: map EVERY EDR-source detection to a console detection, not only the ones
  // carrying a MITRE technique (a prevention/quarantine is the decisive detection of a
  // case yet carries no technique id). #23: a behavioural DetectionSummaryEvent that
  // has no process node of its own is attributed to the LAST process of the chain it
  // names, so its severity and ATT&CK technique reach the header ("Critical · T1003.001")
  // instead of the console reading "40 · High · ATT&CK: none".
  const ACTION_LABEL: Record<string, string> = {
    quarantine: "Quarantine", kill: "Kill Process", block: "Prevention", prevent: "Prevention",
  };
  // R-10: the detection NAME — authored rule name, then a vendor threat name, then the
  // first real CLAUSE of the description (never split on a bare dot), then a name
  // built from the process itself. Never returns a sub-4-character name.
  const detectionName = (e: TelemetryEvent, pid: number): string => {
    const rule = e.rule?.name?.trim();
    if (rule && rule.length >= 4) return rule.slice(0, 80);
    const threat = pickRaw(e.raw, ["crowdstrike.DetectName", "threat.name", "s1.threat_name", "detection_name", "alert.name", "AlertTitle"]);
    if (threat && threat.length >= 4) return threat.slice(0, 80);
    const d = (e.description ?? "").trim();
    if (d) {
      const clause = d.split(/(?:\.\s)|[—;]/)[0].trim();
      return (clause.length >= 8 ? clause : d).slice(0, 80);
    }
    const p = procByPid.get(pid);
    const tech = techniqueOf(e);
    if (e.event_type === "process_access" && p) {
      const target = pickRaw(e.raw, ["crowdstrike.CrossProcessTargetName", "TargetImage"]);
      return `Suspicious process access by ${p.name}${target ? ` → ${baseName(target)}` : ""}`;
    }
    if ((e.event_type ?? "").startsWith("net") && p) return `Suspicious network activity by ${p.name}`;
    if (p) return `Suspicious process: ${p.name}`;
    return tech ? `Detection ${tech}` : (e.event_type ?? "EDR Detection");
  };
  const detectionKind = (e: TelemetryEvent) => {
    const hay = `${e.event_type ?? ""} ${String(e.raw?.["action_result"] ?? "")} ${String(e.raw?.["quarantine.status"] ?? "")}`.toLowerCase();
    if (/quarantin/.test(hay)) return "quarantine";
    if (/kill|terminat/.test(hay)) return "kill";
    if (/block|prevent/.test(hay)) return "block";
    return null;
  };
  const isDetectionEvent = (e: TelemetryEvent) =>
    e.is_detection === true ||
    /detection|threat|malware|ransom|quarantin|prevent/i.test(`${e.event_type ?? ""} ${String(e.raw?.["action_result"] ?? "")}`);
  // The process a process-less alert is about: the last binary of its chain (or the
  // file it names), latest instance alive at alert time.
  const alertPid = new Map<string, number>();   // event id → attributed pid
  const attributeAlert = (e: TelemetryEvent): number | undefined => {
    const direct = pidFromRaw(e.raw);                       // the alert names its process
    if (direct != null) return direct;
    const chain = detectionChain(e);
    const target = chain.at(-1) ?? pickRaw(e.raw, ["crowdstrike.FileName", "FileName", "process.name"]);
    if (!target) return undefined;
    const at = tsMs(e.ts);
    const cands = processes
      .filter(p => p.name.toLowerCase() === baseName(target).toLowerCase())
      .filter(p => { const s = startMs.get(p.pid); return s == null || s <= at || !at; })
      .sort((a, b) => (startMs.get(b.pid) ?? 0) - (startMs.get(a.pid) ?? 0));
    return cands[0]?.pid;
  };
  const seenDet = new Set<string>();
  const detections: EdrDetection[] = [];
  for (const e of events) {
    let pid = e.process?.pid;
    const tech = techniqueOf(e);
    const edrDet = e.source === "edr" && isDetectionEvent(e);
    if (pid == null) {
      if (!edrDet) continue;
      pid = attributeAlert(e);
      if (pid == null) continue;
      alertPid.set(e.id, pid);
    }
    const sevOk = e.severity === "critical" || e.severity === "high" || e.severity === "medium";
    // R-03: an EDR-source event carrying a technique is a detection at ANY severity;
    // non-EDR technique events (a firewall/AD line) need medium+.
    const techniqueDet = !!tech && (sevOk || e.source === "edr");
    if (!techniqueDet && !edrDet) continue;
    const action = detectionKind(e);
    const key = `${pid}:${tech ?? `${e.event_type}:${action ?? String(e.raw?.["action_result"] ?? "")}`}`;
    if (seenDet.has(key)) continue;
    seenDet.add(key);
    const technique = tech ?? (action ? ACTION_LABEL[action] : "EDR Detection");
    const severity = (["critical", "high", "medium", "low"].includes(e.severity as string)
      ? e.severity : "high") as EdrDetection["severity"];
    detections.push({
      pid,
      technique,
      name: detectionName(e, pid),
      severity,
      ioa: e.description ?? pickRaw(e.raw, ["crowdstrike.DetectDescription", "threat.technique.name", "crowdstrike.Technique"]),
    });
  }
  // One behaviour, one row: a generic "EDR Detection" on a pid that also carries a
  // real ATT&CK-mapped detection is the same event seen twice (the process telemetry
  // + its alert summary). Fold it into the mapped row, keeping the worse severity
  // and the more specific name.
  const SEV_ORDER = ["low", "medium", "high", "critical"];
  for (let i = detections.length - 1; i >= 0; i--) {
    const d = detections[i];
    if (d.technique !== "EDR Detection") continue;
    const mapped = detections.find(x => x !== d && x.pid === d.pid && /^T\d{4}/.test(x.technique));
    if (!mapped) continue;
    if (SEV_ORDER.indexOf(d.severity) > SEV_ORDER.indexOf(mapped.severity)) mapped.severity = d.severity;
    if (/^(Suspicious |Detection T)/.test(mapped.name) && !/^(Suspicious |Detection T)/.test(d.name)) mapped.name = d.name;
    mapped.ioa = mapped.ioa ?? d.ioa;
    detections.splice(i, 1);
  }
  // A process a detection fired on is never shown as plain benign.
  for (const d of detections) {
    const p = procByPid.get(d.pid);
    if (p && p.verdict === "benign") {
      p.verdict = "suspicious";
      p.note = p.note ?? `Why it stands out: a ${d.severity} detection fired on it (${d.name}).`;
    }
  }

  // ── Payload = the process to flag. Prefer a known-bad hash; else the highest-
  //    severity endpoint detection; else the last-started suspicious process. ──
  const byHash = processes.filter(p => p.sha256 && lookupHash(p.sha256!)?.malicious);
  const payload =
    byHash.sort((a, b) => tsSort(a.startedAt, b.startedAt)).at(-1)
    ?? processes.filter(p => p.verdict !== "benign").sort((a, b) => tsSort(a.startedAt, b.startedAt)).at(-1)
    ?? null;
  // R-04: a signed system binary / LOLBin with no known-bad hash is ABUSED, not malware.
  if (payload) {
    const badHash = !!(payload.sha256 && lookupHash(payload.sha256)?.malicious);
    payload.verdict = badHash ? "malicious"
      : (payload.signed || isLolBin(payload.name)) ? "abused"
      : "malicious";
  }

  // R-07: seed benign look-twice siblings into a thin tree so flagging is a decision.
  // They are desktop background apps (OneDrive, Teams, an updater), so only on a
  // WORKSTATION and only under the user's REAL explorer.exe from the telemetry —
  // never as invented PPID-0 roots, never under the attacker's cmd.exe, never on a
  // server. (The RTR `ps` baseline supplies the rest of the host's normal noise.)
  if (payload && realExplorer && !server && !isLinux && processes.length <= 2) {
    const anchorPpid = realExplorer.pid;
    const startedAt = payload.startedAt;
    const hash = (() => { let x = 2166136261; for (const c of story.id) { x ^= c.charCodeAt(0); x = Math.imul(x, 16777619); } return Math.abs(x); })();
    const chosen = [DISTRACTOR_POOL[hash % DISTRACTOR_POOL.length], DISTRACTOR_POOL[(hash + 1) % DISTRACTOR_POOL.length]];
    let dpid = 7000 + (hash % 500) * 4;
    for (const d of chosen) {
      if (processes.some(p => p.name.toLowerCase() === d.name.toLowerCase())) continue; // don't duplicate a real one
      while (usedPids.has(dpid)) dpid += 4;
      usedPids.add(dpid);
      const proc = { pid: dpid, ppid: anchorPpid, name: d.name, cmdline: d.cmdline, user: payload.user,
        path: d.path, signed: true, startedAt, verdict: "benign" as Verdict, network: [], files: [] };
      procByPid.set(proc.pid, proc);
      startMs.set(proc.pid, tsMs(story.events.find(e => e.process?.pid === payload.pid)?.ts));
      processes.push(proc);
    }
  }

  // ── Network / file activity → the process the EVENT names ──
  // #9: a connection belongs to the process whose PID (Falcon ContextProcessId) the
  // event carries — never to whichever process happens to be flagged, and never to a
  // process that did not exist yet (the 18:40 download used to land on a cmd.exe that
  // started at 18:43). Endpoint-attributed connections come first; a perimeter line
  // (firewall/proxy/DNS) with no process is the network's view of a connection the
  // sensor may already own — dropped as a duplicate when it is, otherwise attributed
  // only to the payload (or, on a no-payload case, the app that browsed) IF it was
  // alive at that moment.
  const hostIp = mostCommon(procEvents.map(e => e.src_ip)) ?? mostCommon(events.map(e => e.src_ip));
  const aliveAt = (pid: number, ms: number) => { const s = startMs.get(pid); return s == null || !ms || s <= ms; };
  const connKey = (ip?: string, port?: number, domain?: string) => `${ip ?? ""}|${port ?? ""}|${domain ?? ""}`;
  const ownedConns = new Set<string>();
  const ownedTargets = new Set<string>();
  const netOf = (e: TelemetryEvent) => {
    const net = e.network;
    const isDns = e.source === "dns" || e.event_type === "dns_query" || (e.event_type ?? "").includes("dns");
    const domain = net?.domain ?? hostOf(net?.url) ?? e.dns?.query
      ?? pickRaw(e.raw, ["dns.question.name", "dns.query", "question.name", "query", "dns_query"]);
    if (!(domain || net?.url || e.dst_ip)) return null;
    // R-05: a connection whose DESTINATION is our own host is INBOUND.
    const inbound = !!(e.dst_ip && hostIp && e.dst_ip === hostIp);
    // A DNS request's remote end is the host's resolver (not an IP the log names).
    const remote_ip = inbound ? (e.src_ip ?? "—") : (e.dst_ip ?? (isDns ? "resolver" : "—"));
    // R-08: transport in `proto`, layer-7 in `application`.
    const rawProto = String(e.protocol ?? "").toLowerCase();
    const isTransport = /^(tcp|udp|icmp)$/.test(rawProto);
    const port = e.dst_port ?? (net?.url?.startsWith("https") ? 443 : isDns ? 53 : 80);
    const application =
      isDns || port === 53 ? "DNS"
      : net?.url?.startsWith("https") || port === 443 ? "TLS"
      : net?.url?.startsWith("http") || net?.method || net?.status || port === 80 || port === 8080 ? "HTTP"
      : !isTransport && rawProto ? rawProto.toUpperCase()
      : undefined;
    const proto = isTransport ? rawProto : (isDns || port === 53 ? "udp" : "tcp");
    return {
      ts: hhmmss(e.ts), direction: (inbound ? "inbound" : "outbound") as "inbound" | "outbound",
      remote_ip, remote_port: port, domain, proto, application,
      bytes: inbound ? (net?.bytes_in ?? net?.bytes_out) : (net?.bytes_out ?? net?.bytes_in),
      method: net?.method, status: net?.status, url: net?.url,
    };
  };
  const namedPid = (e: TelemetryEvent): number | undefined => {
    if (e.process?.pid != null) return e.process.pid;
    return pidFromRaw(e.raw);
  };
  const sorted = events.slice().sort((a, b) => tsMs(a.ts) - tsMs(b.ts));
  const orphans: TelemetryEvent[] = [];
  for (const e of sorted) {
    const pid = namedPid(e);
    const owner = pid != null ? procByPid.get(pid) : undefined;
    const conn = netOf(e);
    if (!owner) { if (conn || e.file?.path) orphans.push(e); continue; }
    if (!aliveAt(owner.pid, tsMs(e.ts))) continue;   // impossible attribution — never show it
    if (conn && owner.network!.length < 8) {
      owner.network!.push(conn);
      ownedConns.add(connKey(conn.remote_ip, conn.remote_port, conn.domain));
      ownedConns.add(connKey(conn.remote_ip, conn.remote_port, undefined));
      if (conn.domain) ownedTargets.add(conn.domain);
      if (conn.remote_ip !== "—") ownedTargets.add(conn.remote_ip);
    }
    if (e.file?.path && owner.files!.length < 8) {
      const action: EdrFileOp["action"] =
        e.event_type === "file_delete" ? "delete" : e.event_type === "file_rename" ? "rename"
        : e.event_type === "file_access" ? "read" : "write";
      owner.files!.push({ ts: hhmmss(e.ts), action, path: e.file.path });
    }
  }
  // R-06: a network-only case (drive-by miner, RDP brute force) still needs its traffic
  // visible — fall back to the payload, else the real app process, but only when that
  // process was alive at the time of the connection.
  // With a payload, ONLY the payload may take an unattributed connection (the C2 the
  // firewall saw after the beacon started); never a sibling that merely existed.
  const fallbackOwners = (payload ? [payload]
    : [...processes.filter(p => startMs.get(p.pid) != null && p.ppid !== 0), ...processes.filter(p => startMs.get(p.pid) != null)]);
  for (const e of orphans) {
    const ms = tsMs(e.ts);
    const conn = netOf(e);
    const owner = fallbackOwners.find(p => aliveAt(p.pid, ms) && startMs.get(p.pid) != null);
    if (!owner) continue;
    if (conn) {
      const dup = ownedConns.has(connKey(conn.remote_ip, conn.remote_port, conn.domain))
        || ownedConns.has(connKey(conn.remote_ip, conn.remote_port, undefined))
        || (conn.domain && ownedTargets.has(conn.domain)) || ownedTargets.has(conn.remote_ip);
      if (!dup && owner.network!.length < 8) {
        owner.network!.push(conn);
        ownedConns.add(connKey(conn.remote_ip, conn.remote_port, conn.domain));
        if (conn.domain) ownedTargets.add(conn.domain);
        if (conn.remote_ip !== "—") ownedTargets.add(conn.remote_ip);
      }
    }
    if (e.file?.path && owner.files!.length < 8 && !PERIMETER_SOURCES.has(e.source)) {
      const action: EdrFileOp["action"] =
        e.event_type === "file_delete" ? "delete" : e.event_type === "file_rename" ? "rename"
        : e.event_type === "file_access" ? "read" : "write";
      owner.files!.push({ ts: hhmmss(e.ts), action, path: e.file.path });
    }
  }

  // ── Persistence (E-04) — from THIS case's own telemetry ──
  const { autoruns, persistence } = persistenceFrom(events, processes);

  // ── Timeline (chronological, capped) — endpoint view only ──
  // The perimeter's lines stay in the SIEM; the EDR timeline is what the host saw.
  // (A network-only case with no endpoint lines keeps them, so it is never empty.)
  const endpointView = sorted.filter(e => !PERIMETER_SOURCES.has(e.source));
  const timeline: EdrTimelineEvent[] = (endpointView.length ? endpointView : sorted)
    .slice(0, 20)
    .map(e => ({
      at: hhmmss(e.ts),
      kind: timelineKind(e),
      pid: e.process?.pid ?? alertPid.get(e.id),
      text: describeEvent(e),
    }));

  // ── Host header ── (isLinux computed once, above, so the OS label matches the tree)
  const host = {
    name: hostName,
    os: isLinux ? "Linux" : server ? "Windows Server 2022" : "Windows 11 23H2",
    ip: mostCommon(procEvents.map(e => e.src_ip)) ?? mostCommon(events.map(e => e.src_ip)) ?? "—",
    // The signed-in HUMAN — a service-launched shell running as SYSTEM is not who is logged on.
    user: mostCommon(procEvents.map(e => e.process?.user ?? e.user_email).filter(u => u && !SYSTEM_PRINCIPAL.test(u)))
      ?? mostCommon(procEvents.map(e => e.process?.user ?? e.user_email)) ?? "—",
  };

  const explanation = payload
    ? payload.verdict === "abused"
      ? `${payload.name} (pid ${payload.pid}) is the process to flag — but note it is a legitimate, signed binary being ABUSED, not malware itself. The malice is in what it was made to do: "${payload.cmdline}". Contain it and its parent chain, but in your report name the technique (living-off-the-land), not the binary, as the threat — ${payload.name} is trusted and will run again.`
      : `${payload.name} (pid ${payload.pid}) is the payload of this attack: ${payload.signed ? "" : "an unsigned binary "}running "${payload.cmdline}"${payload.sha256 && lookupHash(payload.sha256)?.malicious ? ", with a hash that matches a known-bad sample" : ""}${payload.originalFileName && payload.originalFileName.toLowerCase() !== payload.name.toLowerCase() ? ` — its PE original file name is ${payload.originalFileName}, so the on-disk name is a disguise` : ""}. It is the process in the chain that carried the malicious behaviour — the parents above it are the delivery chain that launched it.`
    : "No single payload process stood out — treat the highest-severity detection in the tree as the process to contain, and correlate it with the timeline.";

  return {
    id: "live",
    title: `${story.title} — live from the Dashboard`,
    summary: `This is the endpoint view of the attack running in your SOC Dashboard feed (${story.title}). Walk the process tree, confirm the payload, and contain the host.`,
    host,
    processes,
    detections,
    timeline,
    autoruns,
    persistence,
    ...(Object.keys(knownPids).length ? { knownPids } : {}),
    ...(edrAgent ? { edrAgent } : {}),
    ...(story.iocTruth ? { iocTruth: story.iocTruth } : {}),
    answer: { pid: payload?.pid ?? -1, explanation },
  };
}

/**
 * Build the EDR investigations for a ready scenario — ONE per incident_id, fully
 * isolated (SPEC-edr-scenario-integration §6.1). Each incident that is endpoint-
 * investigable (edr / hybrid) and actually carries process telemetry becomes its
 * own EdrInvestigation whose id is the incident_id, so the console's case-switcher
 * shows them as separate cases with no cross-incident mixing. Identity/cloud-only
 * incidents (non_edr) and incidents with no process tree to walk are skipped.
 * `iocTruth` (the scenario's server-built IOC truth table) rides along on every case
 * so the console's hash lookup agrees with the threat-intel drawer.
 */
export function buildInvestigationsFromScenario(
  bundle: { title?: string; events: TelemetryEvent[]; iocTruth?: IocTruth | null },
): EdrInvestigation[] {
  const byIncident = new Map<string, TelemetryEvent[]>();
  for (const e of bundle.events) {
    if (!e.incident_id) continue;
    const list = byIncident.get(e.incident_id) ?? [];
    list.push(e);
    byIncident.set(e.incident_id, list);
  }
  const out: EdrInvestigation[] = [];
  for (const [incidentId, events] of byIncident) {
    // The authored edr_scope on the detection wins; fall back to the classifier.
    const authored = events.find(e => e.edr_scope)?.edr_scope;
    const scope = authored ?? classifyScope(events);
    if (scope === "non_edr") continue;
    const inv = buildInvestigationFromStory({ id: incidentId, title: bundle.title ?? incidentId, events, iocTruth: bundle.iocTruth });
    if (!inv) continue; // no process tree to walk
    inv.id = incidentId;
    inv.title = `${bundle.title ?? "Incident"} — endpoint view`;
    out.push(inv);
  }
  return out;
}
