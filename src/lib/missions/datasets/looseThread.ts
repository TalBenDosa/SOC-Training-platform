/**
 * Room 61 "Operation Loose Thread" (St Aldric's Hospice Group): the Sentinel
 * workspace the learner pivots through, hop by hop, from one phishing mail to
 * the data that left. Native table and column names (EmailEvents,
 * UrlClickEvents, DeviceProcessEvents, DeviceNetworkEvents, CommonSecurityLog
 * as a Zscaler NSS web log) plus one custom table, CrmAudit_CL, the donor CRM's
 * own audit export. Fictional values only.
 *
 * The case spine is the SAME in both copies, because each hop pivots on a value
 * the last hop handed over (the sender domain from the mail, the C2 address from
 * the process, the laptop's address from the host): m.oduya, SAH-BRS-LT14
 * (10.10.4.37), probate-registry-uk.example, 203.0.113.164, the click at
 * 08:52:31Z. What the SHADOW changes is what each pivot FINDS: other recipients
 * and clickers, an extra child process, a second C2 address, a second host
 * calling the C2, another record count and another upload site. So every
 * reference result differs, and a query that types in the visible answer fails.
 *
 * Visible timeline (2026-04-14, UTC): mail 08:41:17, click 08:52:31, mshta
 * 08:53:04, powershell 08:53:10 and C2 from 08:53:12, CRM login 09:12:40,
 * Legacy Register export 09:15:02 (2,140 records), ten PUTs to
 * filedrop-share.example 09:31:10-09:44:20 (1,405,353,984 bytes, about 1.4 GB).
 *
 * Decoys: a solicitor's genuine mail about the same estate; a later blocked
 * click; an Intune PowerShell on another host one minute after the click and an
 * earlier management PowerShell on the laptop itself; a neighbour address
 * 203.0.113.165; an older 12-record export by the legacy officer and a Gift Aid
 * export by finance; a 150 MB OneDrive upload from the laptop BEFORE the export
 * and a 220 MB video upload from a Halifax laptop.
 */
import type { MissionDataset, MissionTable } from "../types";
import type { KqlType } from "@/lib/kql/types";

const NOW = "2026-04-14T12:00:00Z";
const DAY = "2026-04-14";
const DOMAIN = "staldrics.example";

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

type R = () => number;
const pick = <T,>(r: R, xs: readonly T[]): T => xs[Math.floor(r() * xs.length)];
const int = (r: R, lo: number, hi: number) => lo + Math.floor(r() * (hi - lo + 1));
const pad = (n: number) => String(n).padStart(2, "0");

/** ISO time on `day` at a number of seconds after midnight UTC. */
function iso(sec: number, day = DAY): string {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  return `${day}T${pad(h)}:${pad(m)}:${pad(s)}Z`;
}
/** "08:52:31" -> seconds after midnight. */
const sec = (hms: string) => { const [h, m, s] = hms.split(":").map(Number); return h * 3600 + m * 60 + (s ?? 0); };
const at = (hms: string, day = DAY) => iso(sec(hms), day);

function hex(r: R, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) s += "0123456789abcdef"[Math.floor(r() * 16)];
  return s;
}
function guid(r: R): string {
  const h = hex(r, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

const u = (name: string) => `${name}@${DOMAIN}`;
const col = (spec: [string, KqlType][]): MissionTable["columns"] => spec.map(([name, type]) => ({ name, type }));

// ─── The people, the machines, the spine ──────────────────────────────────────

/** Staff laptop/PC, its address and its user. The first is the case's laptop. */
const DEVICES: { name: string; ip: string; user: string }[] = [
  { name: "SAH-BRS-LT14", ip: "10.10.4.37", user: "m.oduya" },
  { name: "SAH-BRS-LT09", ip: "10.10.4.21", user: "j.pellow" },
  { name: "SAH-BRS-WS22", ip: "10.10.4.52", user: "a.fairweather" },
  { name: "SAH-BRS-LT17", ip: "10.10.4.44", user: "l.tran" },
  { name: "SAH-HFX-WS07", ip: "10.30.2.17", user: "c.mbatha" },
  { name: "SAH-HFX-LT03", ip: "10.30.2.33", user: "d.hollis" },
  { name: "SAH-PER-WS12", ip: "10.50.3.12", user: "r.gallagher" },
  { name: "SAH-PER-LT05", ip: "10.50.3.25", user: "k.osei" },
];
const OTHER_STAFF = ["p.ruiz", "s.whitlock", "h.moss", "t.adeyemi", "e.marsh", "n.kowal", "b.ferris", "f.quint"];
const STAFF = [...DEVICES.map(d => d.user), ...OTHER_STAFF];

const VICTIM = "m.oduya";
const HOST = DEVICES[0];
const PHISH_DOMAIN = "probate-registry-uk.example";
const PHISH_FROM = `notice@${PHISH_DOMAIN}`;
const PHISH_IP = "198.51.100.77";
const PHISH_URL = `https://${PHISH_DOMAIN}/case/8841/view`;
const PHISH_SUBJECT = "Estate of the late R. Penhaligon: legacy notice, case 8841";
const C2 = "203.0.113.164";
const CLICK = "08:52:31";
const EXPORT_AT = "09:15:02";
/** Public egress address of each hospice (Safe Links sees the click from here). */
const EGRESS: Record<string, string> = { BRS: "198.51.100.40", HFX: "198.51.100.41", PER: "198.51.100.42" };
const siteOf = (device: string) => device.split("-")[1];

interface Cast {
  phish: { to: string; action: "Delivered" | "Junked" | "Blocked"; location: string }[];
  clicks: { upn: string; action: "ClickAllowed" | "ClickBlocked"; at: string }[];
  /** Processes on the laptop in the two minutes after the click. */
  chain: { at: string; file: string; folder: string; cmd: string; parent: string; parentCmd: string }[];
  /** Where the hidden PowerShell on the laptop connected. */
  c2: { ip: string; port: number }[];
  /** Other devices that called the C2 address. */
  otherC2: { device: string; at: string }[];
  exportRecords: number;
  upload: { host: string; path: string; chunks: [string, number][] };
}

const ENC = "JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAFUAcwBlAHIALQBBAGcAZQBuAHQAIgAsACIATQBvAHoAaQBsAGwAYQAvADUALgAwACIAKQA=";
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const EDGE_CMD = `"msedge.exe" --single-argument ${PHISH_URL}`;
const HTA = "C:\\Users\\m.oduya\\Downloads\\Estate_Notice_8841.hta";

const CHAIN_BASE: Cast["chain"] = [
  { at: "08:53:04", file: "mshta.exe", folder: "C:\\Windows\\System32\\mshta.exe", cmd: `"C:\\Windows\\System32\\mshta.exe" "${HTA}" {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}`, parent: "msedge.exe", parentCmd: EDGE_CMD },
  { at: "08:53:10", file: "powershell.exe", folder: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", cmd: `powershell.exe -nop -w hidden -enc ${ENC}`, parent: "mshta.exe", parentCmd: `"C:\\Windows\\System32\\mshta.exe" "${HTA}"` },
  { at: "08:53:10", file: "conhost.exe", folder: "C:\\Windows\\System32\\conhost.exe", cmd: "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1", parent: "powershell.exe", parentCmd: `powershell.exe -nop -w hidden -enc ${ENC}` },
];

const VISIBLE: Cast = {
  phish: [
    { to: VICTIM, action: "Delivered", location: "Inbox/folder" },
    { to: "j.pellow", action: "Junked", location: "Junk folder" },
    { to: "a.fairweather", action: "Junked", location: "Junk folder" },
  ],
  clicks: [
    { upn: VICTIM, action: "ClickAllowed", at: CLICK },
    { upn: "j.pellow", action: "ClickBlocked", at: "09:20:05" },
  ],
  chain: CHAIN_BASE,
  c2: [{ ip: C2, port: 443 }],
  otherC2: [],
  exportRecords: 2140,
  upload: {
    host: "filedrop-share.example", path: "/u/7Qk2rX/part",
    chunks: [
      ["09:31:10", 141557760], ["09:32:38", 139460608], ["09:34:05", 143654912], ["09:35:33", 138412032], ["09:37:01", 140509184],
      ["09:38:29", 142606336], ["09:39:57", 137363456], ["09:41:25", 141557760], ["09:42:52", 139460608], ["09:44:20", 140771328],
    ],
  },
};

const SHADOW: Cast = {
  phish: [
    { to: VICTIM, action: "Delivered", location: "Inbox/folder" },
    { to: "c.mbatha", action: "Junked", location: "Junk folder" },
    { to: "d.hollis", action: "Blocked", location: "Quarantine" },
    { to: "s.whitlock", action: "Junked", location: "Junk folder" },
  ],
  clicks: [
    { upn: VICTIM, action: "ClickAllowed", at: CLICK },
    { upn: "c.mbatha", action: "ClickBlocked", at: "09:24:41" },
  ],
  chain: [
    ...CHAIN_BASE,
    { at: "08:54:02", file: "whoami.exe", folder: "C:\\Windows\\System32\\whoami.exe", cmd: "\"C:\\Windows\\system32\\whoami.exe\" /all", parent: "powershell.exe", parentCmd: `powershell.exe -nop -w hidden -enc ${ENC}` },
  ],
  c2: [{ ip: C2, port: 443 }, { ip: "198.51.100.212", port: 443 }],
  otherC2: [{ device: "SAH-HFX-WS07", at: "10:05:12" }],
  exportRecords: 1870,
  upload: {
    host: "dropvault-files.example", path: "/put/k81z/blk",
    chunks: [["09:33:40", 183500800], ["09:36:12", 179306496], ["09:38:51", 186646528], ["09:41:20", 181403648], ["09:43:58", 184549376], ["09:46:30", 177209344]],
  },
};

// ─── Mail: EmailEvents and UrlClickEvents ─────────────────────────────────────

const SENDERS: { from: string; ip: string; subjects: string[]; junk?: boolean; urls: string[] }[] = [
  { from: "events@charity-times.example", ip: "203.0.113.21", subjects: ["This week in the sector: hospice funding", "Charity Times daily brief"], junk: true, urls: ["https://news.charity-times.example/brief/0414", "https://news.charity-times.example/jobs"] },
  { from: "orders@clinical-supplies.example", ip: "198.51.100.120", subjects: ["Order 55102 dispatched", "Invoice INV-77412 for St Aldric's"], urls: ["https://portal.clinical-supplies.example/orders/55102"] },
  { from: "noreply@giftaid-portal.example", ip: "198.51.100.131", subjects: ["Your Gift Aid claim has been received", "Claim reference GA-20931 update"], urls: ["https://giftaid-portal.example/claims/GA-20931"] },
  { from: "volunteers@helping-hands.example", ip: "203.0.113.33", subjects: ["Volunteer rota for the Bristol shop", "Thank you from the volunteer team"], urls: ["https://helping-hands.example/rota"] },
  { from: "bookings@venue-halls.example", ip: "203.0.113.48", subjects: ["Booking confirmed: spring fundraising dinner"], urls: ["https://venue-halls.example/booking/4471"] },
];
const INTERNAL_SUBJECTS = ["Ward 3 handover notes", "Shop takings for Monday", "Re: legacy pledge follow-up", "Training reminder: safeguarding", "Fundraising team stand-up", "Re: donor thank-you letters", "Rota swap Thursday"];
const AUTH_PASS = "{\"SPF\":\"pass\",\"DKIM\":\"pass\",\"DMARC\":\"pass\",\"CompAuth\":\"pass\"}";
const AUTH_INTERNAL = "{\"SPF\":\"none\",\"DKIM\":\"none\",\"DMARC\":\"none\",\"CompAuth\":\"none\"}";

const EMAIL_COLUMNS = col([
  ["Timestamp", "datetime"], ["NetworkMessageId", "string"], ["InternetMessageId", "string"], ["SenderFromAddress", "string"], ["SenderFromDomain", "string"],
  ["SenderMailFromAddress", "string"], ["SenderIPv4", "string"], ["RecipientEmailAddress", "string"], ["Subject", "string"], ["EmailDirection", "string"],
  ["DeliveryAction", "string"], ["DeliveryLocation", "string"], ["AttachmentCount", "int"], ["UrlCount", "int"], ["ThreatTypes", "string"], ["AuthenticationDetails", "string"],
]);

interface MailOut { rows: Record<string, unknown>[]; clicks: Record<string, unknown>[] }

function mail(c: Cast): MailOut {
  const r = rng(6101);
  const rows: Record<string, unknown>[] = [];
  const clicks: Record<string, unknown>[] = [];
  const egress = (name: string) => EGRESS[siteOf(DEVICES.find(d => d.user === name)?.name ?? "SAH-BRS-X")] ?? EGRESS.BRS;
  // Noise: newsletters, suppliers, internal mail, over today's morning and yesterday.
  for (let i = 0; i < 96; i++) {
    const day = i % 4 === 0 ? "2026-04-13" : DAY;
    const t = iso(int(r, sec("06:00:00"), sec("11:58:00")), day);
    const to = pick(r, STAFF);
    const nmid = guid(r);
    if (r() < 0.35) {
      const from = pick(r, STAFF.filter(s => s !== to));
      rows.push({ Timestamp: t, NetworkMessageId: nmid, InternetMessageId: `<${hex(r, 12)}@SAH-EXCH01.${DOMAIN}>`, SenderFromAddress: u(from), SenderFromDomain: DOMAIN, SenderMailFromAddress: u(from), SenderIPv4: "10.10.1.30", RecipientEmailAddress: u(to), Subject: pick(r, INTERNAL_SUBJECTS), EmailDirection: "Intra-org", DeliveryAction: "Delivered", DeliveryLocation: "Inbox/folder", AttachmentCount: int(r, 0, 1), UrlCount: 0, ThreatTypes: "", AuthenticationDetails: AUTH_INTERNAL });
      continue;
    }
    const s = pick(r, SENDERS);
    const junk = !!s.junk && r() < 0.4;
    const domain = s.from.split("@")[1];
    rows.push({ Timestamp: t, NetworkMessageId: nmid, InternetMessageId: `<${hex(r, 16)}@${domain}>`, SenderFromAddress: s.from, SenderFromDomain: domain, SenderMailFromAddress: `bounce@${domain}`, SenderIPv4: s.ip, RecipientEmailAddress: u(to), Subject: pick(r, s.subjects), EmailDirection: "Inbound", DeliveryAction: junk ? "Junked" : "Delivered", DeliveryLocation: junk ? "Junk folder" : "Inbox/folder", AttachmentCount: 0, UrlCount: s.urls.length, ThreatTypes: junk ? "Spam" : "", AuthenticationDetails: AUTH_PASS });
    if (!junk && r() < 0.85) {
      const ct = new Date(Date.parse(t) + int(r, 60, 3000) * 1000).toISOString().replace(".000Z", "Z");
      clicks.push({ Timestamp: ct, Url: pick(r, s.urls), ActionType: "ClickAllowed", AccountUpn: u(to), Workload: "Email", NetworkMessageId: nmid, IPAddress: egress(to), IsClickedThrough: false, ThreatTypes: "", UrlChain: "" });
    }
  }
  // Decoy: the family's solicitor writes about the same estate, genuinely.
  rows.push({ Timestamp: at("07:58:41"), NetworkMessageId: guid(r), InternetMessageId: `<${hex(r, 16)}@penhaligon-law.example>`, SenderFromAddress: "c.trevelyan@penhaligon-law.example", SenderFromDomain: "penhaligon-law.example", SenderMailFromAddress: "c.trevelyan@penhaligon-law.example", SenderIPv4: "203.0.113.57", RecipientEmailAddress: u("l.tran"), Subject: "Estate of the late R. Penhaligon: your letter of 9 April", EmailDirection: "Inbound", DeliveryAction: "Delivered", DeliveryLocation: "Inbox/folder", AttachmentCount: 1, UrlCount: 0, ThreatTypes: "", AuthenticationDetails: AUTH_PASS });
  // The lure: one message, several recipients, one shared InternetMessageId.
  const imid = "<20260414084109.8841.4471@probate-registry-uk.example>";
  c.phish.forEach((p, i) => {
    const nmid = guid(r);
    rows.push({ Timestamp: iso(sec("08:41:17") + i), NetworkMessageId: nmid, InternetMessageId: imid, SenderFromAddress: PHISH_FROM, SenderFromDomain: PHISH_DOMAIN, SenderMailFromAddress: PHISH_FROM, SenderIPv4: PHISH_IP, RecipientEmailAddress: u(p.to), Subject: PHISH_SUBJECT, EmailDirection: "Inbound", DeliveryAction: p.action, DeliveryLocation: p.location, AttachmentCount: 1, UrlCount: 1, ThreatTypes: p.action === "Delivered" ? "" : "Phish", AuthenticationDetails: AUTH_PASS });
    const click = c.clicks.find(k => k.upn === p.to);
    if (click) clicks.push({ Timestamp: at(click.at), Url: PHISH_URL, ActionType: click.action, AccountUpn: u(click.upn), Workload: "Email", NetworkMessageId: nmid, IPAddress: egress(click.upn), IsClickedThrough: click.action === "ClickAllowed", ThreatTypes: click.action === "ClickBlocked" ? "Phish" : "", UrlChain: "" });
  });
  rows.sort((a, b) => String(a.Timestamp).localeCompare(String(b.Timestamp)));
  clicks.sort((a, b) => String(a.Timestamp).localeCompare(String(b.Timestamp)));
  return { rows, clicks };
}

const CLICK_COLUMNS = col([
  ["Timestamp", "datetime"], ["Url", "string"], ["ActionType", "string"], ["AccountUpn", "string"], ["Workload", "string"],
  ["NetworkMessageId", "string"], ["IPAddress", "string"], ["IsClickedThrough", "bool"], ["ThreatTypes", "string"], ["UrlChain", "string"],
]);

// ─── Endpoint: DeviceProcessEvents and DeviceNetworkEvents ────────────────────

const APPS: { file: string; folder: string; cmd: string; parent: string; parentCmd: string }[] = [
  { file: "OUTLOOK.EXE", folder: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", cmd: "\"OUTLOOK.EXE\"", parent: "explorer.exe", parentCmd: "C:\\Windows\\Explorer.EXE" },
  { file: "msedge.exe", folder: EDGE, cmd: "\"msedge.exe\" --profile-directory=Default", parent: "explorer.exe", parentCmd: "C:\\Windows\\Explorer.EXE" },
  { file: "ms-teams.exe", folder: "C:\\Program Files\\WindowsApps\\MSTeams_8wekyb3d8bbwe\\ms-teams.exe", cmd: "\"ms-teams.exe\" --system-initiated", parent: "svchost.exe", parentCmd: "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p" },
  { file: "OneDrive.exe", folder: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", cmd: "\"OneDrive.exe\" /background", parent: "explorer.exe", parentCmd: "C:\\Windows\\Explorer.EXE" },
  { file: "EXCEL.EXE", folder: "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", cmd: "\"EXCEL.EXE\" /dde", parent: "explorer.exe", parentCmd: "C:\\Windows\\Explorer.EXE" },
  { file: "WINWORD.EXE", folder: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", cmd: "\"WINWORD.EXE\" /n", parent: "OUTLOOK.EXE", parentCmd: "\"OUTLOOK.EXE\"" },
  { file: "AcroRd32.exe", folder: "C:\\Program Files (x86)\\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe", cmd: "\"AcroRd32.exe\" /n", parent: "OUTLOOK.EXE", parentCmd: "\"OUTLOOK.EXE\"" },
];
const INTUNE_PS = "powershell.exe -NoProfile -executionPolicy bypass -file \"C:\\Program Files (x86)\\Microsoft Intune Management Extension\\Policies\\Scripts\\b7d1c0e2_9a41.ps1\"";

const PROC_COLUMNS = col([
  ["Timestamp", "datetime"], ["DeviceName", "string"], ["ActionType", "string"], ["FileName", "string"], ["FolderPath", "string"], ["ProcessCommandLine", "string"],
  ["SHA256", "string"], ["AccountName", "string"], ["InitiatingProcessFileName", "string"], ["InitiatingProcessCommandLine", "string"], ["InitiatingProcessAccountName", "string"],
]);

/** Laptop activity is kept outside 08:48-08:58 so a loose window around the click still holds only the chain. */
const quiet = (device: string, s: number) => device === HOST.name && s >= sec("08:48:00") && s <= sec("08:58:00");

function processes(c: Cast): Record<string, unknown>[] {
  const r = rng(6102);
  const rows: Record<string, unknown>[] = [];
  const hashes = new Map(APPS.map(a => [a.file, hex(r, 64)]));
  for (let i = 0; i < 118; i++) {
    const d = DEVICES[i % DEVICES.length];
    let s = int(r, sec("06:30:00"), sec("11:55:00"));
    if (quiet(d.name, s)) s += 900;
    const a = pick(r, APPS);
    rows.push({ Timestamp: iso(s), DeviceName: d.name, ActionType: "ProcessCreated", FileName: a.file, FolderPath: a.folder, ProcessCommandLine: a.cmd, SHA256: hashes.get(a.file), AccountName: d.user, InitiatingProcessFileName: a.parent, InitiatingProcessCommandLine: a.parentCmd, InitiatingProcessAccountName: d.user });
  }
  const psHash = hex(r, 64);
  const agent = { InitiatingProcessFileName: "AgentExecutor.exe", InitiatingProcessCommandLine: "\"AgentExecutor.exe\" -powershell", InitiatingProcessAccountName: "system" };
  // Decoys: Intune scripts, one on the laptop before the click, one elsewhere a minute after it.
  rows.push({ Timestamp: at("07:58:02"), DeviceName: HOST.name, ActionType: "ProcessCreated", FileName: "powershell.exe", FolderPath: CHAIN_BASE[1].folder, ProcessCommandLine: INTUNE_PS, SHA256: psHash, AccountName: "system", ...agent });
  rows.push({ Timestamp: at("08:53:20"), DeviceName: "SAH-HFX-WS07", ActionType: "ProcessCreated", FileName: "powershell.exe", FolderPath: CHAIN_BASE[1].folder, ProcessCommandLine: INTUNE_PS, SHA256: psHash, AccountName: "system", ...agent });
  // The chain on the laptop.
  for (const p of c.chain) {
    rows.push({ Timestamp: at(p.at), DeviceName: HOST.name, ActionType: "ProcessCreated", FileName: p.file, FolderPath: p.folder, ProcessCommandLine: p.cmd, SHA256: p.file === "powershell.exe" ? psHash : hex(r, 64), AccountName: VICTIM, InitiatingProcessFileName: p.parent, InitiatingProcessCommandLine: p.parentCmd, InitiatingProcessAccountName: VICTIM });
  }
  if (c.otherC2.length) {
    for (const o of c.otherC2) {
      const dev = DEVICES.find(d => d.name === o.device)!;
      rows.push({ Timestamp: iso(sec(o.at) - 6), DeviceName: dev.name, ActionType: "ProcessCreated", FileName: "powershell.exe", FolderPath: CHAIN_BASE[1].folder, ProcessCommandLine: CHAIN_BASE[1].cmd, SHA256: psHash, AccountName: dev.user, InitiatingProcessFileName: "mshta.exe", InitiatingProcessCommandLine: "\"mshta.exe\"", InitiatingProcessAccountName: dev.user });
    }
  }
  return rows.sort((a, b) => String(a.Timestamp).localeCompare(String(b.Timestamp)));
}

const SERVICES: { url: string; ip: string; app: string }[] = [
  { url: "outlook.office365.com", ip: "203.0.113.12", app: "OUTLOOK.EXE" },
  { url: "teams.microsoft.com", ip: "203.0.113.14", app: "ms-teams.exe" },
  { url: "staldrics-my.sharepoint.com", ip: "203.0.113.18", app: "OneDrive.exe" },
  { url: "www.google.com", ip: "198.51.100.105", app: "msedge.exe" },
  { url: "donate.staldrics.example", ip: "198.51.100.110", app: "msedge.exe" },
  { url: "news.charity-times.example", ip: "203.0.113.21", app: "msedge.exe" },
  { url: "giftaid-portal.example", ip: "198.51.100.131", app: "msedge.exe" },
  { url: "crm.staldrics.example", ip: "10.50.1.10", app: "msedge.exe" },
];

const NET_COLUMNS = col([
  ["Timestamp", "datetime"], ["DeviceName", "string"], ["ActionType", "string"], ["LocalIP", "string"], ["RemoteIP", "string"], ["RemotePort", "int"],
  ["RemoteUrl", "string"], ["RemoteIPType", "string"], ["Protocol", "string"], ["InitiatingProcessFileName", "string"], ["InitiatingProcessCommandLine", "string"], ["InitiatingProcessAccountName", "string"],
]);

function network(c: Cast): Record<string, unknown>[] {
  const r = rng(6103);
  const rows: Record<string, unknown>[] = [];
  const conn = (s: number, d: { name: string; ip: string }, remote: string, port: number, url: string, file: string, cmd: string, acct: string, action = "ConnectionSuccess") => rows.push({
    Timestamp: iso(s), DeviceName: d.name, ActionType: action, LocalIP: d.ip, RemoteIP: remote, RemotePort: port, RemoteUrl: url,
    RemoteIPType: /^10\./.test(remote) ? "Private" : "Public", Protocol: "Tcp", InitiatingProcessFileName: file, InitiatingProcessCommandLine: cmd, InitiatingProcessAccountName: acct,
  });
  for (let i = 0; i < 112; i++) {
    const d = DEVICES[i % DEVICES.length];
    let s = int(r, sec("06:30:00"), sec("11:55:00"));
    if (quiet(d.name, s)) s += 900;
    const sv = pick(r, SERVICES);
    const app = APPS.find(a => a.file === sv.app) ?? APPS[1];
    conn(s, d, sv.ip, 443, sv.url, sv.app, app.cmd, d.user, r() < 0.04 ? "ConnectionFailed" : "ConnectionSuccess");
  }
  // Decoys: the laptop's Intune script talks to the management server; a Perth PC loads fonts from the C2's neighbour.
  conn(sec("07:58:05"), HOST, "10.10.2.15", 443, "mgmt01.staldrics.example", "powershell.exe", INTUNE_PS, "system");
  conn(sec("08:12:44"), DEVICES[6], "203.0.113.165", 443, "cdn.charity-fonts.example", "msedge.exe", APPS[1].cmd, DEVICES[6].user);
  conn(sec("10:31:09"), DEVICES[6], "203.0.113.165", 443, "cdn.charity-fonts.example", "msedge.exe", APPS[1].cmd, DEVICES[6].user);
  // The hidden PowerShell beacons every 3 minutes from 08:53:12 to the end of the morning.
  const ps = CHAIN_BASE[1].cmd;
  c.c2.forEach((dst, k) => {
    for (let s = sec("08:53:12") + k * 47; s < sec("09:50:00"); s += 180) conn(s, HOST, dst.ip, dst.port, "", "powershell.exe", ps, VICTIM);
  });
  for (const o of c.otherC2) {
    const dev = DEVICES.find(d => d.name === o.device)!;
    for (let s = sec(o.at); s < sec(o.at) + 900; s += 180) conn(s, dev, C2, 443, "", "powershell.exe", ps, dev.user);
  }
  return rows.sort((a, b) => String(a.Timestamp).localeCompare(String(b.Timestamp)));
}

// ─── The donor CRM's audit export: CrmAudit_CL ────────────────────────────────

const CRM_COLUMNS = col([
  ["TimeGenerated", "datetime"], ["UserName", "string"], ["Operation", "string"], ["EntityName", "string"], ["RecordCount", "int"],
  ["ClientIP", "string"], ["ClientHostName", "string"], ["Result", "string"], ["SessionId", "string"],
]);
const CRM_USERS = ["m.oduya", "l.tran", "r.gallagher", "k.osei", "p.ruiz", "h.moss", "t.adeyemi"];
const ENTITIES = ["Donors", "Donors", "LegacyRegister", "GiftAidClaims", "Events"];

function crm(c: Cast): Record<string, unknown>[] {
  const r = rng(6104);
  const rows: Record<string, unknown>[] = [];
  const row = (t: string, user: string, op: string, entity: string, n: number, dev: { name: string; ip: string }, session: string, result = "Success") =>
    rows.push({ TimeGenerated: t, UserName: user.includes("@") ? user : u(user), Operation: op, EntityName: entity, RecordCount: n, ClientIP: dev.ip, ClientHostName: dev.name, Result: result, SessionId: session });
  const devOf = (name: string) => DEVICES.find(d => d.user === name) ?? { name: "SAH-BRS-WS30", ip: "10.10.4.60" };
  // Ten days of ordinary work: sign in, search, read, update.
  for (let day = 9; day >= 0; day--) {
    const date = new Date(Date.parse(`${DAY}T00:00:00Z`) - day * 86400000).toISOString().slice(0, 10);
    rows.push({ TimeGenerated: `${date}T02:00:0${day % 10}Z`, UserName: u("svc-crmsync"), Operation: "SyncRecords", EntityName: "Donors", RecordCount: int(r, 40, 160), ClientIP: "10.50.1.11", ClientHostName: "SAH-PER-CRM02", Result: "Success", SessionId: guid(r) });
    for (let k = 0; k < 4; k++) {
      const user = pick(r, CRM_USERS);
      const dev = devOf(user);
      let s = int(r, sec("07:30:00"), sec("11:30:00"));
      if (day === 0 && user === VICTIM) s = Math.min(s, sec("08:30:00"));
      const session = guid(r);
      const entity = pick(r, ENTITIES);
      row(iso(s, date), user, "Login", "", 0, dev, session);
      row(iso(s + int(r, 30, 200), date), user, "SearchRecords", entity, int(r, 1, 40), dev, session);
      row(iso(s + int(r, 220, 600), date), user, "ReadRecord", entity, 1, dev, session);
      if (r() < 0.5) row(iso(s + int(r, 620, 900), date), user, "UpdateRecord", entity, 1, dev, session);
    }
  }
  // A failed login from a mistyped password, and the decoy exports.
  row(at("07:41:09"), "h.moss", "Login", "", 0, devOf("h.moss"), guid(r), "Failure");
  row(at("14:22:51", "2026-04-08"), "l.tran", "ExportRecords", "LegacyRegister", 12, devOf("l.tran"), guid(r));
  row(at("10:02:37"), "r.gallagher", "ExportRecords", "GiftAidClaims", 380, devOf("r.gallagher"), guid(r));
  // The officer's genuine morning, then the session that took the register.
  const own = guid(r);
  row(at("08:05:12"), VICTIM, "Login", "", 0, HOST, own);
  row(at("08:06:40"), VICTIM, "ReadRecord", "LegacyRegister", 1, HOST, own);
  const bad = guid(r);
  row(at("09:12:40"), VICTIM, "Login", "", 0, HOST, bad);
  row(at("09:13:55"), VICTIM, "SearchRecords", "LegacyRegister", c.exportRecords, HOST, bad);
  row(at(EXPORT_AT), VICTIM, "ExportRecords", "LegacyRegister", c.exportRecords, HOST, bad);
  row(at("09:16:30"), VICTIM, "Logout", "", 0, HOST, bad);
  return rows.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

// ─── The web proxy: CommonSecurityLog (Zscaler NSS web log over CEF) ──────────

const PROXY_COLUMNS = col([
  ["TimeGenerated", "datetime"], ["DeviceVendor", "string"], ["DeviceProduct", "string"], ["DeviceAction", "string"], ["SourceIP", "string"], ["SourceUserName", "string"],
  ["DestinationHostName", "string"], ["DestinationIP", "string"], ["DestinationPort", "int"], ["RequestURL", "string"], ["RequestMethod", "string"],
  ["RequestClientApplication", "string"], ["SentBytes", "long"], ["ReceivedBytes", "long"],
]);
const BROWSE: { host: string; ip: string; path: string }[] = [
  { host: "www.google.com", ip: "198.51.100.105", path: "/search" },
  { host: "donate.staldrics.example", ip: "198.51.100.110", path: "/give/monthly" },
  { host: "news.charity-times.example", ip: "203.0.113.21", path: "/brief/0414" },
  { host: "giftaid-portal.example", ip: "198.51.100.131", path: "/claims/GA-20931" },
  { host: "portal.clinical-supplies.example", ip: "198.51.100.120", path: "/orders/55102" },
  { host: "venue-halls.example", ip: "203.0.113.48", path: "/booking/4471" },
  { host: "staldrics-my.sharepoint.com", ip: "203.0.113.18", path: "/personal/sync" },
];
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36 Edg/123.0.2420.97";

function proxy(c: Cast): Record<string, unknown>[] {
  const r = rng(6105);
  const rows: Record<string, unknown>[] = [];
  const hit = (s: number, d: { ip: string; user: string }, host: string, ip: string, path: string, method: string, sent: number, recv: number, ua = UA) => rows.push({
    TimeGenerated: iso(s), DeviceVendor: "Zscaler", DeviceProduct: "NSSWeblog", DeviceAction: "Allowed", SourceIP: d.ip, SourceUserName: u(d.user),
    DestinationHostName: host, DestinationIP: ip, DestinationPort: 443, RequestURL: `https://${host}${path}`, RequestMethod: method, RequestClientApplication: ua, SentBytes: sent, ReceivedBytes: recv,
  });
  for (let i = 0; i < 120; i++) {
    const d = DEVICES[i % DEVICES.length];
    let s = int(r, sec("06:30:00"), sec("11:55:00"));
    if (quiet(d.name, s)) s += 900;
    const b = pick(r, BROWSE);
    hit(s, d, b.host, b.ip, b.path, r() < 0.15 ? "POST" : "GET", int(r, 420, 4800), int(r, 2000, 900000));
  }
  // Decoys: a big but sanctioned OneDrive upload from the laptop BEFORE the export; a Halifax video upload.
  hit(sec("08:20:14"), { ip: HOST.ip, user: VICTIM }, "staldrics-my.sharepoint.com", "203.0.113.18", "/personal/m_oduya/_api/web/upload", "PUT", 157286400, 2310);
  hit(sec("10:10:47"), { ip: DEVICES[5].ip, user: DEVICES[5].user }, "upload.video-host.example", "198.51.100.150", "/v1/media", "POST", 230686720, 1880);
  // The C2 address seen through the proxy: small, steady posts.
  for (let s = sec("08:53:15"); s < sec("09:50:00"); s += 360) hit(s, { ip: HOST.ip, user: VICTIM }, C2, C2, "/api/v2/sync", "POST", int(r, 900, 3200), int(r, 300, 1400), "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-GB) WindowsPowerShell/5.1.19041.4291");
  // The register leaves.
  c.upload.chunks.forEach(([t, bytes], i) => hit(sec(t), { ip: HOST.ip, user: VICTIM }, c.upload.host, c.upload.host.startsWith("filedrop") ? "203.0.113.190" : "198.51.100.190", `${c.upload.path}${i + 1}`, "PUT", bytes, int(r, 400, 900)));
  return rows.sort((a, b) => String(a.TimeGenerated).localeCompare(String(b.TimeGenerated)));
}

// ─── Assembly ─────────────────────────────────────────────────────────────────

function build(c: Cast): MissionDataset {
  const m = mail(c);
  return {
    now: NOW,
    tables: [
      { name: "EmailEvents", columns: EMAIL_COLUMNS, rows: m.rows },
      { name: "UrlClickEvents", columns: CLICK_COLUMNS, rows: m.clicks },
      { name: "DeviceProcessEvents", columns: PROC_COLUMNS, rows: processes(c) },
      { name: "DeviceNetworkEvents", columns: NET_COLUMNS, rows: network(c) },
      { name: "CrmAudit_CL", columns: CRM_COLUMNS, rows: crm(c) },
      { name: "CommonSecurityLog", columns: PROXY_COLUMNS, rows: proxy(c) },
    ],
  };
}

export const LOOSE_THREAD = { visible: () => build(VISIBLE), shadow: () => build(SHADOW) };

/** The visible case's facts, for the missions' accepted values and the tests. */
export const LOOSE_THREAD_FACTS = {
  victim: u(VICTIM), host: HOST.name, hostIp: HOST.ip, phishDomain: PHISH_DOMAIN, phishFrom: PHISH_FROM, phishIp: PHISH_IP, url: PHISH_URL, c2: C2,
  click: `${DAY}T${CLICK}Z`, exportAt: `${DAY}T${EXPORT_AT}Z`, records: VISIBLE.exportRecords, uploadHost: VISIBLE.upload.host,
  uploadBytes: VISIBLE.upload.chunks.reduce((a, [, b]) => a + b, 0), firstUpload: `${DAY}T${VISIBLE.upload.chunks[0][0]}Z`, lastUpload: `${DAY}T${VISIBLE.upload.chunks[VISIBLE.upload.chunks.length - 1][0]}Z`,
};
