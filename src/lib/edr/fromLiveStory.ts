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

function timelineKind(e: TelemetryEvent): EdrTimelineEvent["kind"] {
  const t = e.event_type;
  if (t.startsWith("net") || t === "http_request" || t === "dns_query" || t === "http_blocked") return "network";
  if (t.startsWith("file")) return "file";
  if (e.mitre_technique && (e.severity === "high" || e.severity === "critical")) return "detection";
  return "process";
}

export function buildInvestigationFromStory(
  story: { id: string; title: string; events: TelemetryEvent[] },
): EdrInvestigation | null {
  const events = story.events ?? [];

  // R-02: a story with NO endpoint (EDR / Sysmon / host-audit / Windows Security)
  // telemetry is not an endpoint investigation. Kerberoasting, for example, lives in
  // AD + DB-audit + SIEM; opening an EDR console for it forces the student to flag the
  // victim's own legitimate, signed SQL Server as "malware" — the exact opposite of
  // what the Kerberoasting room teaches. Such cases stay identity/DB investigations.
  const ENDPOINT_SOURCES = new Set(["edr", "sysmon", "linux_audit", "windows_security"]);
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
  // header, and the user format (R-13). True when the telemetry is host-audit/k8s, the
  // process names are predominantly unix, or an image path is POSIX-absolute.
  const winProcCount = procEvents.filter(e => /\.exe$/i.test(e.process?.name ?? "")).length;
  const nixProcCount = procEvents.filter(e => {
    const n = e.process?.name?.toLowerCase() ?? "";
    return UNIX_PROCS.has(n) || (!!n && !/\.\w{2,4}$/.test(n));
  }).length;
  const isLinux = events.some(e => e.source === "linux_audit" || e.source === "k8s_audit")
    || nixProcCount > winProcCount
    || procEvents.some(e => (e.process?.path ?? "").startsWith("/"));

  // R-13: one user format across the whole tree. The console mixed "NEXACORP\r.avraham"
  // with bare "s.patel" / "svc-mssql" on the same screen; a real EDR shows DOMAIN\user
  // consistently on Windows. Derive the realm from the case's own identities and
  // normalise every process owner to it (system principals like NT AUTHORITY\SYSTEM are
  // left as-is; a Linux host keeps bare unix usernames like "root", which have no realm).
  const caseDomain = mostCommon(events.map(e => e.user_email?.includes("@") ? e.user_email.split("@")[1] : undefined));
  const netbios = (caseDomain?.split(".")[0] ?? "").toUpperCase();
  const normUser = (u?: string): string => {
    if (!u || !u.trim()) return "unknown";
    const v = u.trim();
    if (v.includes("\\")) return v;                              // already DOMAIN\user
    if (/^(nt authority|builtin|nt service|nt virtual|window manager|font driver)/i.test(v)) return v;
    const bare = v.includes("@") ? v.split("@")[0] : v;
    if (isLinux) return bare;                        // unix has no DOMAIN\ realm
    return netbios ? `${netbios}\\${bare}` : bare;
  };

  // ── Processes (deduped by pid), plus stubs for referenced-but-unseen parents ──
  const procByPid = new Map<number, EdrProcess>();
  const seedProcess = (e: TelemetryEvent) => {
    const p = e.process!;
    if (procByPid.has(p.pid)) return;
    const sha256 = p.hash?.sha256;
    const malicious = sha256 ? lookupHash(sha256)?.malicious : false;
    const imagePath = imagePathOf(p, { malicious });   // real on-disk path (recovered from cmdline / canonical if needed)
    const userWritable = USER_WRITABLE.test(imagePath);
    // E-02: signing is authoritative when the log states it — a real EDR reads the
    // Authenticode result off the binary, and the console must not contradict it.
    // Prefer the explicit raw field (process.signed / file.signed / code_signature.*)
    // over the heuristic; only when the log is silent do we fall back to it (a
    // known-bad hash or a binary from a user-writable path is treated as unsigned,
    // the classic payload tell; system/Program Files binaries as signed). Displaying
    // "Signed: Yes" in green on a binary the log marks unsigned is the one finding
    // that can teach a wrong habit, so the log always wins.
    const rawSigned =
      (e.raw?.["process.signed"] ?? e.raw?.["file.signed"] ?? e.raw?.["code_signature.signed"] ??
       e.raw?.["process.code_signature.exists"] ?? e.raw?.["file.code_signature.valid"]) as unknown;
    const signed = rawSigned != null
      ? !/^(false|no|0|unsigned|invalid)$/i.test(String(rawSigned).trim())
      : !malicious && !userWritable;
    const verdict: Verdict = malicious
      ? "malicious"
      : (e.mitre_technique && (e.severity === "critical" || e.severity === "high")) || userWritable
        ? "suspicious"
        : "benign";
    procByPid.set(p.pid, {
      pid: p.pid,
      ppid: p.parent_pid ?? 0,
      name: p.name,
      cmdline: p.cmdline ?? p.name,
      user: normUser(p.user ?? e.user_email ?? e.user?.email),
      path: imagePath,
      signed,
      sha256,
      startedAt: hhmmss(e.ts),
      verdict,
      note: verdict === "benign" ? undefined : whyItStandsOut(p, { signed, malicious, userWritable, imagePath }),
      network: [],
      files: [],
    });
  };
  for (const e of procEvents) {
    seedProcess(e);
    const p = e.process!;
    if (p.parent_pid != null && !procByPid.has(p.parent_pid)) {
      // A parent we never saw a create event for — add a benign stub so the
      // tree connects (real consoles show the ancestor even without its own row).
      // Resolve its image path to the canonical location too, so the tree root shows
      // "C:\Windows\explorer.exe", not a bare "explorer.exe".
      const parentName = p.parent_name ?? "process";
      const parentPath = imagePathOf({ pid: p.parent_pid, name: parentName, cmdline: parentName }, { malicious: false });
      procByPid.set(p.parent_pid, {
        pid: p.parent_pid, ppid: 0, name: parentName,
        cmdline: p.parent_name ?? "—", user: normUser(p.user),
        path: parentPath, signed: true, startedAt: hhmmss(e.ts), verdict: "benign",
        network: [], files: [],
      });
    }
  }

  // R-12: a process that never legitimately sits at the root of a tree on a real host —
  // cmd.exe, WINWORD.EXE, chrome.exe, powershell.exe, svchost.exe — must not appear with
  // ppid 0 (which is the System Idle Process). Give each such orphan the parent it would
  // really have: explorer.exe for user apps, services.exe for svchost — or, on a Linux/
  // container host, the shell (bash), never a Windows explorer.exe. One shared parent per
  // kind keeps the tree from sprouting a forest of identical roots.
  const LEGIT_ROOTS = new Set([
    // Windows
    "explorer.exe", "userinit.exe", "wininit.exe", "services.exe", "smss.exe", "csrss.exe",
    "lsass.exe", "system", "kernel_task", "w3wp.exe",
    // Unix / container
    "systemd", "init", "launchd", "sshd", "bash", "sh", "zsh", "dash", "dockerd",
    "containerd", "cron", "crond", "kubelet", "containerd-shim",
  ]);
  let synthPid = 90000;
  const sharedParent = new Map<string, number>();
  const ensureParent = (name: string, user: string, startedAt: string): number => {
    const existing = sharedParent.get(name);
    if (existing != null) return existing;
    const pid = synthPid++;
    sharedParent.set(name, pid);
    procByPid.set(pid, {
      pid, ppid: 0, name, cmdline: name, user,
      path: imagePathOf({ pid, name, cmdline: name }, { malicious: false }),
      signed: true, startedAt, verdict: "benign", network: [], files: [],
    });
    return pid;
  };
  for (const p of [...procByPid.values()]) {
    if (p.ppid !== 0) continue;
    const n = p.name.toLowerCase();
    if (LEGIT_ROOTS.has(n)) continue;
    const parentName = isLinux ? "bash" : n === "svchost.exe" ? "services.exe" : "explorer.exe";
    p.ppid = ensureParent(parentName, p.user, p.startedAt);
  }

  const processes = [...procByPid.values()];

  // ── Payload = the process to flag. Prefer a known-bad hash; else the highest-
  //    severity endpoint detection; else the last-started suspicious process. ──
  const byHash = processes.filter(p => p.sha256 && lookupHash(p.sha256!)?.malicious);
  const payload =
    byHash.sort((a, b) => tsSort(a.startedAt, b.startedAt)).at(-1)
    ?? processes.filter(p => p.verdict !== "benign").sort((a, b) => tsSort(a.startedAt, b.startedAt)).at(-1)
    ?? null;
  // R-04: the process to flag is not always "malicious". A signed system binary or
  // LOLBin (powershell.exe, cmd.exe, sqlservr.exe, rundll32.exe…) with no known-bad
  // hash that is the payload is being ABUSED, not itself malware — a real EDR colours
  // it distinctly and puts the malice on its command line and parent. Only an unsigned
  // binary, or one whose hash matches a known-bad sample, is labelled malicious.
  if (payload) {
    const badHash = !!(payload.sha256 && lookupHash(payload.sha256)?.malicious);
    payload.verdict = badHash ? "malicious"
      : (payload.signed || isLolBin(payload.name)) ? "abused"
      : "malicious";
  }

  // R-07: a two-node tree (payload + its parent) makes "flag the payload" a statement,
  // not a decision — the one flagged node already wears a red ATT&CK tag. Seed a couple
  // of BENIGN look-twice siblings — real signed background processes an untrained eye
  // might suspect (OneDrive, Teams, a Google updater, the AV engine) — so the analyst
  // has to actually rule them out. They carry the genuine benign tells (signed, from a
  // real install path, no bad hash, no detection), so a careful reader clears them; they
  // are never the answer. Deterministic per case, and only when the tree is thin AND
  // there is a real payload (an all-benign FP case needs no manufactured suspects).
  if (payload && processes.length <= 2) {
    const anchorPpid = payload.ppid || processes.find(p => p.ppid !== 0)?.ppid || 0;
    const startedAt = payload.startedAt;
    const hash = (() => { let x = 2166136261; for (const c of story.id) { x ^= c.charCodeAt(0); x = Math.imul(x, 16777619); } return Math.abs(x); })();
    const chosen = [DISTRACTOR_POOL[hash % DISTRACTOR_POOL.length], DISTRACTOR_POOL[(hash + 1) % DISTRACTOR_POOL.length]];
    let dpid = 70000;
    for (const d of chosen) {
      if (processes.some(p => p.name.toLowerCase() === d.name.toLowerCase())) continue; // don't duplicate a real one
      const proc = { pid: dpid++, ppid: anchorPpid, name: d.name, cmdline: d.cmdline, user: payload.user,
        path: d.path, signed: true, startedAt, verdict: "benign" as Verdict, network: [], files: [] };
      procByPid.set(proc.pid, proc);
      processes.push(proc);
    }
  }

  // ── Attach network / file activity to the owning process (orphans → payload) ──
  // The host's own IP — needed to tell an INBOUND request (someone connecting TO the
  // host) from an OUTBOUND one (the host reaching out). Computed here so R-05 works.
  const hostIp = mostCommon(procEvents.map(e => e.src_ip)) ?? mostCommon(events.map(e => e.src_ip));
  // R-06: orphan network events (a firewall/proxy line with no process) must still land
  // somewhere or the console's netstat is empty — worst on a network-only case like a
  // drive-by browser miner or an RDP brute force, whose correct verdict is "benign/FP"
  // (so there is no payload) yet whose whole story IS the network traffic. Fall back to
  // the browser / most-relevant real process so the analyst can actually see it.
  const orphanOwner = payload
    ?? processes.find(p => p.ppid !== 0)   // a real (non-root-stub) process — the app that browsed
    ?? processes[0]
    ?? null;
  for (const e of events) {
    const owner = (e.process?.pid != null && procByPid.get(e.process.pid)) || orphanOwner;
    if (!owner) continue;
    const net = e.network;
    // R-06: a DNS query IS network activity — surface it (a DNS-tunnelling case is
    // nothing BUT DNS). Pull the queried name from the structured dns/network fields
    // or the vendor raw block, so `netstat` in the console is never empty when the
    // story carried DNS or connection telemetry.
    const isDns = e.source === "dns" || e.event_type === "dns_query" || (e.event_type ?? "").includes("dns");
    const domain = net?.domain ?? hostOf(net?.url) ?? e.dns?.query
      ?? pickRaw(e.raw, ["dns.question.name", "dns.query", "question.name", "query", "dns_query"]);
    if ((domain || net?.url || e.dst_ip) && owner.network!.length < 8) {
      // R-05: a connection whose DESTINATION is our own host is an INBOUND request (a
      // web server receiving a scan or exploit), so the remote party is the SOURCE, not
      // the host "connecting to itself". Otherwise the host is reaching out (C2/exfil).
      const inbound = !!(e.dst_ip && hostIp && e.dst_ip === hostIp);
      const remote_ip = inbound ? (e.src_ip ?? "—") : (e.dst_ip ?? "—");
      // R-08: transport protocol (tcp/udp/icmp) goes in `proto`; the layer-7 protocol
      // (TLS/HTTP/DNS) goes in its own `application` column — no netstat prints "TLS"
      // in the protocol field.
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
      owner.network!.push({
        ts: hhmmss(e.ts),
        direction: inbound ? "inbound" : "outbound",
        remote_ip,
        remote_port: port,
        domain,
        proto,
        application,
        bytes: inbound ? (net?.bytes_in ?? net?.bytes_out) : (net?.bytes_out ?? net?.bytes_in),
        method: net?.method,
        status: net?.status,
        url: net?.url,
      });
    }
    if (e.file?.path && owner.files!.length < 8) {
      const action: EdrFileOp["action"] =
        e.event_type === "file_delete" ? "delete" :
        e.event_type === "file_rename" ? "rename" :
        e.event_type === "file_access" ? "read" : "write";
      owner.files!.push({ ts: hhmmss(e.ts), action, path: e.file.path });
    }
  }

  // ── Detections ────────────────────────────────────────────────────────────
  // E-03: map EVERY EDR-source detection to a console detection, not only the ones
  // carrying a MITRE technique. A CrowdStrike prevention/quarantine event (Kill
  // Process + Quarantine File, pattern_disposition 128) is the decisive detection of
  // the case yet carries no technique_id; excluding it made the console report fewer
  // detections than the SIEM feed, score the incident a whole band too low (a
  // critical read as Medium), and undercount the "Investigate in EDR" badge. Now the
  // detection set == the EDR events the analyst saw in the feed, so score, severity
  // band and count line up with the SIEM.
  const ACTION_LABEL: Record<string, string> = {
    quarantine: "Quarantine", kill: "Kill Process", block: "Prevention", prevent: "Prevention",
  };
  // R-10: the detection NAME the analyst reads. The old derivation split the
  // description on ANY ".", so "r.avraham ran…" became the one-character name "r" (and
  // the long ones were chopped mid-word at 80). Prefer the authored rule name, then a
  // vendor threat name, then the first real CLAUSE of the description — split only on a
  // sentence break (". ") / dash / semicolon, never a bare dot, so dotted usernames and
  // domains survive. Never returns a sub-4-character name.
  const detectionName = (e: TelemetryEvent): string => {
    const rule = e.rule?.name?.trim();
    if (rule && rule.length >= 4) return rule.slice(0, 80);
    const threat = pickRaw(e.raw, ["threat.name", "crowdstrike.detection.name", "s1.threat_name", "detection_name", "alert.name"]);
    if (threat && threat.length >= 4) return threat.slice(0, 80);
    const d = (e.description ?? "").trim();
    if (d) {
      const clause = d.split(/(?:\.\s)|[—;]/)[0].trim();
      return (clause.length >= 8 ? clause : d).slice(0, 80);
    }
    return e.mitre_technique ? `Detection ${e.mitre_technique}` : (e.event_type ?? "EDR Detection");
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
  const seenDet = new Set<string>();
  const detections: EdrDetection[] = [];
  for (const e of events) {
    const pid = e.process?.pid;
    if (pid == null) continue;
    const sevOk = e.severity === "critical" || e.severity === "high" || e.severity === "medium";
    // R-03: an EDR-source event carrying a MITRE technique is a detection the analyst saw
    // in the feed AT ANY SEVERITY — a low-severity T1204.002 process-create still fired a
    // rule. Require medium+ only for non-EDR technique events (a firewall/AD line), so the
    // console's detection set matches the EDR events shown in the SIEM feed.
    const techniqueDet = !!e.mitre_technique && (sevOk || e.source === "edr");
    const edrDet = e.source === "edr" && isDetectionEvent(e);
    if (!techniqueDet && !edrDet) continue;
    // A technique row keys on pid+technique; a techniqueless prevention keys on its
    // action so it never collapses into a technique row — and so a kill AND a
    // quarantine on the same pid both count.
    const action = detectionKind(e);
    const key = `${pid}:${e.mitre_technique ?? `${e.event_type}:${action ?? String(e.raw?.["action_result"] ?? "")}`}`;
    if (seenDet.has(key)) continue;
    seenDet.add(key);
    const technique = e.mitre_technique ?? (action ? ACTION_LABEL[action] : "EDR Detection");
    const severity = (["critical", "high", "medium", "low"].includes(e.severity as string)
      ? e.severity : "high") as EdrDetection["severity"];
    detections.push({
      pid,
      technique,
      name: detectionName(e),
      severity,
      ioa: e.description,
    });
  }

  // ── Autoruns / persistence (E-04) — from THIS case's own registry telemetry ──
  // The RTR shell's `reg query Run` reads these; when the case has none it truthfully
  // reports "no autorun entries found" instead of a hard-coded key from another host.
  const autoruns = events
    .filter(e => (e.event_type ?? "").startsWith("registry") && e.registry)
    .map(e => ({
      key: e.registry!.path ?? e.registry!.key ?? "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      value: e.registry!.value ?? e.process?.cmdline ?? "(unnamed)",
    }));

  // ── Timeline (chronological, capped) ──
  const timeline: EdrTimelineEvent[] = events
    .slice()
    .sort((a, b) => (a.ts ?? "").localeCompare(b.ts ?? ""))
    .slice(0, 20)
    .map(e => ({
      at: hhmmss(e.ts),
      kind: timelineKind(e),
      pid: e.process?.pid,
      text: e.description ?? e.event_type.replace(/_/g, " "),
    }));

  // ── Host header ── (isLinux computed once, above, so the OS label matches the tree)
  const host = {
    name: mostCommon(procEvents.map(e => e.hostname)) ?? mostCommon(events.map(e => e.hostname)) ?? "endpoint",
    os: isLinux ? "Linux" : "Windows",
    ip: mostCommon(procEvents.map(e => e.src_ip)) ?? mostCommon(events.map(e => e.src_ip)) ?? "—",
    user: mostCommon(procEvents.map(e => e.process?.user ?? e.user_email)) ?? "—",
  };

  const explanation = payload
    ? payload.verdict === "abused"
      ? `${payload.name} (pid ${payload.pid}) is the process to flag — but note it is a legitimate, signed binary being ABUSED, not malware itself. The malice is in what it was made to do: "${payload.cmdline}". Contain it and its parent chain, but in your report name the technique (living-off-the-land), not the binary, as the threat — ${payload.name} is trusted and will run again.`
      : `${payload.name} (pid ${payload.pid}) is the payload of this attack: ${payload.signed ? "" : "an unsigned binary "}running "${payload.cmdline}"${payload.sha256 && lookupHash(payload.sha256)?.malicious ? ", with a hash that matches a known-bad sample" : ""}. It is the process in the chain that carried the malicious behaviour — the parents above it are the delivery chain that launched it.`
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
 */
export function buildInvestigationsFromScenario(
  bundle: { title?: string; events: TelemetryEvent[] },
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
    const inv = buildInvestigationFromStory({ id: incidentId, title: bundle.title ?? incidentId, events });
    if (!inv) continue; // no process tree to walk
    inv.id = incidentId;
    inv.title = `${bundle.title ?? "Incident"} — endpoint view`;
    out.push(inv);
  }
  return out;
}
