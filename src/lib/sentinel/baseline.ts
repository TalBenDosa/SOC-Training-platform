/**
 * The ordinary life of the session's organization: a week of sign-ins, logons, mail, files, processes,
 * connections and DNS for every person and host, so that a query about a quiet user gets a real answer.
 *
 * Rendering: each kind of activity is rendered once by the native module the session's stack selects,
 * then mapped like a feed record, so identifiers (DeviceId, AccountSid, object ids, hashes) and product
 * formats are the feed's own. The row is then stamped at each time it happens.
 *
 * Rules this file holds to:
 *  - It reads only public inputs: the directory (company data, session identity, the feed so far).
 *  - Everyone gets the same shape, so nothing here tells a compromised user from a quiet one.
 *  - Only the office location and egress, documentation addresses and .example or tenant names.
 *  - It raises nothing: rows are added after the rules have run.
 *  - Times depend on the session's start and the entity alone: every poll gives the same rows.
 */
import { nativeView, stackFor, type NativeIdentity, type Stack } from "@/lib/logs/native";
import { makeCtx } from "@/lib/logs/native/ctx";
import { COMPANY_HQ, countryInfo, entraObjectId } from "@/lib/logs/native/sources/_identity-common";
import { accountSid } from "@/lib/logs/native/sources/_proc-identity";
import { egressIp } from "@/lib/logs/native/sources/firewall-shared";
import type { NativeCtx } from "@/lib/logs/native/types";
import type { KqlRow, KqlTable } from "@/lib/kql/types";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { Directory, Host, HostOs, Person } from "./directory";
import { reconcileRow } from "./fallback";
import { mapRow, type MapContext } from "./mapRow";
import { columnType } from "./tables";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const HISTORY_DAYS = 7;

const fnv = (s: string) => { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; };
const iso = (ms: number) => new Date(ms).toISOString();
const hex = (seed: string, n: number) => { let o = ""; for (let i = 0; o.length < n; i++) o += fnv(`${seed}#${i}`).toString(16).padStart(8, "0"); return o.slice(0, n); };
const uuid = (seed: string) => { const h = hex(seed, 32); return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`; };

// ── Templates ───────────────────────────────────────────────────────────────

type IdKind = "uuid" | "num" | "hex";

/** Columns that differ on every occurrence of an activity. */
const ID_COLUMNS: Record<string, [string, IdKind][]> = {
  SigninLogs: [["Id", "uuid"], ["OriginalRequestId", "uuid"], ["CorrelationId", "uuid"], ["UniqueTokenIdentifier", "hex"]],
  AuditLogs: [["Id", "uuid"], ["CorrelationId", "uuid"]],
  OfficeActivity: [["OfficeId", "uuid"]],
  SecurityEvent: [["EventRecordId", "num"]],
  DeviceProcessEvents: [["ReportId", "num"], ["ProcessId", "num"]], DeviceNetworkEvents: [["ReportId", "num"], ["LocalPort", "num"]], DeviceFileEvents: [["ReportId", "num"]], DeviceLogonEvents: [["ReportId", "num"]],
  OktaV2_CL: [["EventOriginalUid", "uuid"], ["TransactionId", "hex"]],
  CommonSecurityLog: [["ExtID", "num"], ["DeviceCustomNumber1", "num"], ["SourcePort", "num"]],
  GoogleWorkspaceReports: [["IdUniqueQualifier", "num"]],
  AWSCloudTrail: [["AwsEventId", "uuid"], ["AwsRequestId", "uuid"]],
  AzureActivity: [["CorrelationId", "uuid"]],
  GCPAuditLogs: [["InsertId", "hex"]],
  Syslog: [["ProcessID", "num"]],
};

interface Template { table: string; row: KqlRow; t0: number; dates: [string, number][]; texts: string[]; ids: [string, IdKind][] }

/** Long enough to find a date stamped into a text column (a sign-in's step time, a syslog header). */
const stampText = (ms: number) => iso(ms).slice(0, 16);

function template(table: string, row: KqlRow, t0: number): Template {
  const dates: [string, number][] = [];
  const texts: string[] = [];
  const prefix = stampText(t0);
  const slash = prefix.replace(/-/g, "/").replace("T", " ");
  for (const [col, v] of Object.entries(row)) {
    if (typeof v !== "string") continue;
    if (columnType(table, col) === "datetime") dates.push([col, Date.parse(v) - t0]);
    else if (v.includes(prefix) || v.includes(slash)) texts.push(col);
  }
  return { table, row, t0, dates, texts, ids: ID_COLUMNS[table] ?? [] };
}

function stamp(t: Template, ms: number, seed: string): KqlRow {
  const row: KqlRow = { ...t.row };
  for (const [col, off] of t.dates) row[col] = iso(ms + off);
  row.TimeGenerated = iso(ms);
  if (t.texts.length) {
    const from = stampText(t.t0), to = stampText(ms);
    const fromS = from.replace(/-/g, "/").replace("T", " "), toS = to.replace(/-/g, "/").replace("T", " ");
    for (const col of t.texts) row[col] = String(row[col]).split(from).join(to).split(fromS).join(toS);
  }
  for (const [col, kind] of t.ids) {
    if (row[col] === undefined) continue;
    const s = `${seed}:${col}`;
    row[col] = kind === "uuid" ? uuid(s) : kind === "hex" ? hex(s, 22) : col === "ProcessId" ? 1000 + (fnv(s) % 16000) * 4 : col === "LocalPort" || col === "SourcePort" ? 49152 + (fnv(s) % 16000) : col === "ProcessID" ? 1000 + (fnv(s) % 60000) : (typeof row[col] === "string" ? String(fnv(s)) : fnv(s));
  }
  return row;
}

// ── Session ─────────────────────────────────────────────────────────────────

/** Documentation addresses that stand for the outside world. A range the scenario packs do not use. */
const OUTSIDE = ["192.0.2.201", "192.0.2.204", "192.0.2.208", "192.0.2.212", "192.0.2.217", "192.0.2.222", "192.0.2.226", "192.0.2.231"];
const SITES = ["cdn.vendor.example", "updates.software.example", "telemetry.vendor.example", "docs.partner.example", "assets.supplier.example", "status.service.example"];

interface Session {
  companyId: string;
  stack?: Stack;
  eff: Stack;
  identity?: NativeIdentity;
  ctx: NativeCtx;
  map: MapContext;
  anchor: number;
  /** The render time of every template. */
  t0: number;
  /** Local time minus UTC at the company's head office. */
  tz: number;
  /** Most recent working-hours moment before the session started. */
  recent: number;
  egress: string;
  geo: TelemetryEvent["geo"];
  entities: Map<string, Cached>;
}

interface Cached { signature: string; rows: [string, KqlRow, number][] }

function offsetOf(timeZone: string, at: number): number {
  try {
    const p = new Intl.DateTimeFormat("en-US", { timeZone, hour12: false, year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric" }).formatToParts(at);
    const g = (t: string) => Number(p.find(x => x.type === t)?.value);
    return Date.UTC(g("year"), g("month") - 1, g("day"), g("hour") % 24, g("minute")) - Math.floor(at / 60_000) * 60_000;
  } catch { return 0; }
}

function lastWorkingMoment(anchor: number, tz: number): number {
  for (let t = anchor - HOUR; t > anchor - DAY; t -= HOUR / 2) {
    const h = (((t + tz) % DAY) + DAY) % DAY / HOUR;
    if (h >= 8.5 && h <= 18) return t;
  }
  return anchor - 2 * HOUR;
}

function openSession(companyId: string, stack: Stack | undefined, identity: NativeIdentity | undefined, tenantId: string, anchor: number): Session {
  const ctx = makeCtx(companyId, identity ?? {});
  const eff = stackFor(companyId, stack);
  const tz = offsetOf(ctx.timeZone, anchor);
  const hq = countryInfo(COMPANY_HQ[companyId] ?? "IL");
  return {
    companyId, stack, eff, identity, ctx, map: { tenantId, cloud: eff.cloud }, anchor, t0: Math.floor(anchor / 60_000) * 60_000 - DAY, tz, recent: lastWorkingMoment(anchor, tz), egress: egressIp(ctx),
    geo: hq ? { country: hq.iso, city: hq.city, latitude: hq.lat, longitude: hq.lon } : undefined, entities: new Map(),
  };
}

const SESSIONS = new Map<string, Session>();
const MAX_SESSIONS = 4;

function sessionFor(companyId: string, stack: Stack | undefined, identity: NativeIdentity | undefined, orgName: string | undefined, tenantId: string, anchor: number): Session {
  const key = JSON.stringify([companyId, stack ?? {}, identity ?? null, orgName ?? "", anchor]);
  let s = SESSIONS.get(key);
  if (s) { SESSIONS.delete(key); SESSIONS.set(key, s); return s; }
  s = openSession(companyId, stack, identity, tenantId, anchor);
  SESSIONS.set(key, s);
  if (SESSIONS.size > MAX_SESSIONS) SESSIONS.delete(SESSIONS.keys().next().value as string);
  return s;
}

// ── Activity plans ──────────────────────────────────────────────────────────

/** One kind of recurring activity. */
interface Plan {
  cls: string;
  templates: Template[];
  /** Occurrences on a working day, on a weekend day. */
  weekday: number; weekend: number;
  /** Local hours it happens in. */
  from: number; to: number;
}

function renderOne(s: Session, seed: string, ev: Partial<TelemetryEvent> & Pick<TelemetryEvent, "source" | "event_type">, person?: Person): Template | null {
  const e = { id: `bl${hex(`${s.companyId}:${seed}`, 12)}`, ts: iso(s.t0), severity: "informational", ...ev } as TelemetryEvent;
  const view = nativeView(e, s.companyId, s.stack, s.identity);
  if (!view) return null;
  const m = mapRow(view.log, s.map);
  if (!m) return null;
  reconcileRow(m.table, m.row, e);
  if (person) {
    // The SID the feed prints for this person, where a record authored one.
    const derived = accountSid(s.ctx, person.name);
    if (derived !== person.sid) for (const [k, v] of Object.entries(m.row)) if (typeof v === "string" && v.includes(derived)) m.row[k] = v.split(derived).join(person.sid);
  }
  return template(m.table, m.row, s.t0);
}

const present = (t: (Template | null)[]) => t.filter((x): x is Template => !!x);

const SIGNIN_APPS = ["Microsoft Teams", "Office 365 Exchange Online", "Office 365 SharePoint Online", "OfficeHome"];

function personPlans(s: Session, p: Person, host: Host | undefined): Plan[] {
  const who = { user_email: p.upn, user: { email: p.upn, full_name: p.display, title: p.title || undefined, department: p.department }, hostname: host?.name };
  const office = { ...who, src_ip: s.egress, geo: s.geo };
  const plans: Plan[] = [];
  const seed = `p:${p.upn}`;
  const render = (sess: Session, tag: string, ev: Parameters<typeof renderOne>[2]) => renderOne(sess, tag, ev, p);

  const apps = [0, 1, 2].map(i => SIGNIN_APPS[(fnv(p.upn) + i) % SIGNIN_APPS.length]);
  plans.push({
    cls: "signin", weekday: 3, weekend: 1, from: 8, to: 18,
    templates: present(apps.map(app => render(s, `${seed}:signin:${app}`, {
      ...office, source: "o365", vendor: "Microsoft Entra ID", event_type: "auth_success",
      raw: {
        "azure.signinlogs.properties.appDisplayName": app, "azure.signinlogs.properties.isInteractive": !p.service, "azure.signinlogs.properties.deviceDetail.isManaged": true, "azure.signinlogs.properties.deviceDetail.isCompliant": true,
        ...(p.service ? { "okta.eventType": "app.oauth2.as.token.grant", "okta.target.displayName": app } : {}),
      },
    }))),
  });

  plans.push({
    cls: "office-mail", weekday: 2, weekend: 1, from: 8, to: 18,
    templates: present([render(s, `${seed}:mail`, { ...office, source: "exchange", vendor: "Microsoft 365", event_type: "email_sent" })]),
  }, {
    cls: "office-file", weekday: 2, weekend: 0, from: 9, to: 17,
    templates: present(["Weekly-notes.docx", "Team-plan.xlsx"].map(f => render(s, `${seed}:file:${f}`, { ...office, source: "sharepoint", vendor: "Microsoft 365", event_type: "sharepoint_access", file: { name: f, path: `/sites/${p.department.replace(/\W/g, "")}/Shared Documents/${f}` } }))),
  }, {
    cls: "audit", weekday: 0.2, weekend: 0, from: 9, to: 17,
    templates: s.eff.idp === "okta" ? [] : present([render(s, `${seed}:audit`, { ...office, source: "o365", vendor: "Microsoft Entra ID", event_type: "account_modify", raw: { "azure.auditlogs.properties.activity_display_name": "Update user", "azure.auditlogs.operation_name": "Update user", "data.office365.Operation": "Update user." } })]),
  });

  if (host && host.os !== "Appliance") {
    const local = { ...who, src_ip: host.ip };
    plans.push({
      cls: "mde-logon", weekday: 1, weekend: 1, from: 8, to: 10,
      templates: present([render(s, `${seed}:mde-logon:${host.key}`, { ...local, source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "auth_success", authentication: { logon_type: p.service ? 5 : 2, result: "success" } })]),
    });
    if (host.os === "Windows" || host.os === "WindowsServer") {
      const logonType = p.service ? "5" : "2";
      const win = (id: string) => render(s, `${seed}:win${id}:${host.key}`, {
        ...local, source: "windows_security", vendor: "Windows Security", event_type: "auth_success", authentication: { logon_type: Number(logonType), result: "success" }, raw: { "winlog.event_id": id, "winlog.event_data.LogonType": logonType },
      });
      plans.push({ cls: "logon", weekday: 1, weekend: 1, from: 8, to: 10, templates: present([win("4624")]) }, { cls: "logoff", weekday: 1, weekend: 1, from: 16, to: 18, templates: present([win("4634")]) });
    } else {
      plans.push({ cls: "logon", weekday: 1, weekend: 1, from: 8, to: 10, templates: present([render(s, `${seed}:ssh:${host.key}`, { ...local, source: "linux_audit", vendor: "Linux auditd", event_type: "ssh_login" })]) });
    }
  }

  // Cloud consoles: the people whose work is there, whoever they are.
  if (["IT", "Engineering"].includes(p.department)) {
    if (s.eff.cloud === "aws_cloudtrail") {
      plans.push({
        cls: "cloud", weekday: 1, weekend: 0, from: 9, to: 17,
        templates: present(["DescribeAlarms", "GetMetricData"].map(api => render(s, `${seed}:aws:${api}`, { ...office, source: "cloudtrail", vendor: "AWS CloudTrail", event_type: "cloud_api_call", cloud: { provider: "aws", service: "monitoring.amazonaws.com", api_call: api, region: "eu-west-1" } }))),
      });
    }
    if (s.eff.cloud === "azure_activity") {
      plans.push({
        cls: "cloud", weekday: 1, weekend: 0, from: 9, to: 17,
        templates: present(["MICROSOFT.COMPUTE/VIRTUALMACHINES/READ", "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/READ"].map(op => render(s, `${seed}:azure:${op}`, { ...office, source: "cloud_azure", vendor: "Azure Activity", event_type: "cloud_api_call", raw: { "azure.activitylogs.operationName": op } }))),
      });
    }
    if (s.eff.cloud === "gcp_audit") {
      plans.push({
        cls: "cloud", weekday: 1, weekend: 0, from: 9, to: 17,
        templates: present([render(s, `${seed}:gcp`, { ...office, source: "cloud_gcp", vendor: "Google Cloud", event_type: "cloud_api_call", cloud: { provider: "gcp", service: "compute.googleapis.com", api_call: "v1.compute.instances.list" } })]),
      });
    }
  }
  return plans;
}

interface Program { name: string; path: string; parent?: string; cmd?: string; system?: boolean }

const PROGRAMS: Record<string, Program[]> = {
  Windows: [
    { name: "OUTLOOK.EXE", path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", parent: "explorer.exe" },
    { name: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent: "explorer.exe" },
    { name: "taskhostw.exe", path: "C:\\Windows\\System32\\taskhostw.exe", parent: "svchost.exe", system: true },
  ],
  WindowsServer: [
    { name: "taskhostw.exe", path: "C:\\Windows\\System32\\taskhostw.exe", parent: "svchost.exe", system: true },
    { name: "MpCmdRun.exe", path: "C:\\Program Files\\Windows Defender\\MpCmdRun.exe", parent: "svchost.exe", cmd: "\"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" SignatureUpdate", system: true },
    { name: "wuauclt.exe", path: "C:\\Windows\\System32\\wuauclt.exe", parent: "svchost.exe", system: true },
  ],
  Linux: [
    { name: "cron", path: "/usr/sbin/cron", parent: "systemd", cmd: "/usr/sbin/cron -f", system: true },
    { name: "logrotate", path: "/usr/sbin/logrotate", parent: "cron", cmd: "/usr/sbin/logrotate /etc/logrotate.conf", system: true },
    { name: "apt-get", path: "/usr/bin/apt-get", parent: "cron", cmd: "/usr/bin/apt-get -qq update", system: true },
  ],
  macOS: [
    { name: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari", parent: "launchd" },
    { name: "softwareupdated", path: "/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdated", parent: "launchd", system: true },
    { name: "mdworker", path: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mdworker_shared", parent: "launchd", system: true },
  ],
};

function hostPlans(s: Session, h: Host, primary: Person | undefined): Plan[] {
  const seed = `h:${h.key}`;
  const render = (sess: Session, tag: string, ev: Parameters<typeof renderOne>[2]) => renderOne(sess, tag, ev, primary);
  const who = primary ? { user_email: primary.upn, user: { email: primary.upn, full_name: primary.display } } : {};
  const base = { hostname: h.name, src_ip: h.ip };
  const from = h.server ? 0 : 8, to = h.server ? 24 : 18;
  const plans: Plan[] = [];
  if (h.os === "Appliance") {
    plans.push({
      cls: "syslog", weekday: 4, weekend: 4, from: 0, to: 24,
      templates: present([render(s, `${seed}:syslog`, { ...base, ...who, source: "linux_audit", vendor: "Linux auditd", event_type: "ssh_login" })]),
    });
    return plans;
  }
  const edr = (ev: Partial<TelemetryEvent> & { event_type: TelemetryEvent["event_type"] }, tag: string) => render(s, `${seed}:${tag}`, { ...base, ...who, source: "edr", vendor: "Microsoft Defender for Endpoint", ...ev });
  const programs = PROGRAMS[h.os];
  plans.push({
    cls: "process", weekday: 6, weekend: 3, from, to,
    templates: present(programs.map(p => edr({ event_type: "process_create", ...(p.system ? { user_email: undefined, user: undefined } : {}), process: { name: p.name, pid: 4000, path: p.path, parent_name: p.parent, cmdline: p.cmd ?? `"${p.path}"`, ...(p.system ? { user: h.os.startsWith("Windows") ? "NT AUTHORITY\\SYSTEM" : "root" } : {}) } }, `proc:${p.name}`))),
  });
  const outside = OUTSIDE[fnv(h.key) % OUTSIDE.length], site = SITES[fnv(h.key) % SITES.length];
  const agent = programs[programs.length > 1 ? 1 : 0];
  plans.push({
    cls: "network", weekday: 4, weekend: 2, from, to,
    templates: present([
      edr({ event_type: "net_connection", dst_ip: outside, dst_port: 443, protocol: "tcp", network: { domain: site, url: `https://${site}/` }, process: { name: agent.name, pid: 4100, path: agent.path } }, "net:out"),
      edr({ event_type: "net_connection", dst_port: 443, protocol: "tcp", network: { domain: `intranet.${s.ctx.domain}`, url: `https://intranet.${s.ctx.domain}/` }, process: { name: agent.name, pid: 4100, path: agent.path } }, "net:in"),
    ]),
  });
  if (h.os === "Windows" && primary) {
    plans.push({
      cls: "file", weekday: 1, weekend: 0, from: 9, to: 17,
      templates: present([edr({ event_type: "file_create", file: { name: "Meeting-notes.docx", path: `C:\\Users\\${primary.name}\\Documents\\Meeting-notes.docx` }, process: { name: "WINWORD.EXE", pid: 4200 } }, "file")]),
    });
  }
  plans.push({
    cls: "dns", weekday: 4, weekend: 2, from, to,
    templates: present([site, `intranet.${s.ctx.domain}`].map(q => render(s, `${seed}:dns:${q}`, { ...base, source: "dns", vendor: "Windows DNS", event_type: "dns_query", dns: { query: q, query_type: "A", response: q === site ? outside : h.ip, rcode: "NOERROR" } }))),
  });
  plans.push({
    cls: "firewall", weekday: 3, weekend: 2, from, to,
    templates: present([render(s, `${seed}:fw`, { ...base, ...who, source: "firewall", vendor: "Firewall", event_type: "net_connection", dst_ip: outside, dst_port: 443, protocol: "tcp", network: { bytes_out: 4_000, bytes_in: 60_000 } })]),
  });
  if (s.eff.proxy) {
    plans.push({
      cls: "proxy", weekday: 3, weekend: 1, from, to,
      templates: present([render(s, `${seed}:proxy`, { ...base, ...who, source: "proxy", vendor: "Zscaler Internet Access", event_type: "http_request", dst_ip: outside, dst_port: 443, network: { url: `https://${site}/`, domain: site, method: "GET", status: 200 }, raw: { "zscaler.urlcategory": "Professional Services" } })]),
    });
  }
  if (h.os === "Linux") {
    plans.push({
      cls: "syslog", weekday: 3, weekend: 2, from: 0, to: 24,
      templates: present([render(s, `${seed}:ssh`, { ...base, ...who, source: "linux_audit", vendor: "Linux auditd", event_type: "ssh_login", src_ip: h.ip })]),
    });
  }
  return plans;
}

// ── Scheduling ──────────────────────────────────────────────────────────────

function occurrences(s: Session, key: string, plans: Plan[]): [string, KqlRow, number][] {
  const out: [string, KqlRow, number][] = [];
  const firstDay = Math.floor((s.anchor + s.tz) / DAY);
  for (const plan of plans) {
    if (!plan.templates.length) continue;
    const put = (ms: number, tag: string) => {
      const t = plan.templates[fnv(`${tag}:t`) % plan.templates.length];
      out.push([t.table, stamp(t, ms, tag), ms]);
    };
    for (let d = HISTORY_DAYS; d >= 0; d--) {
      const day = firstDay - d;
      const weekend = (((day + 4) % 7) + 7) % 7 >= 5;   // day 0 was a Thursday
      const count = weekend ? plan.weekend : plan.weekday;
      for (let i = 0; i < Math.ceil(count); i++) {
        const tag = `${s.companyId}|${key}|${plan.cls}|${day}|${i}`;
        if (count < 1 && fnv(tag) % 100 >= count * 100) continue;
        const ms = day * DAY - s.tz + plan.from * HOUR + fnv(`${tag}:m`) % ((plan.to - plan.from) * HOUR);
        if (ms >= s.anchor - HISTORY_DAYS * DAY) put(ms, tag);
      }
    }
    // Every class has a row in the last day, whatever day of the week the session starts on.
    if (plan.weekday >= 1 || plan.cls === "signin") {
      const tag = `${s.companyId}|${key}|${plan.cls}|recent`;
      put(s.recent - fnv(`${tag}:m`) % (2 * HOUR), tag);
    }
  }
  return out;
}

function cached(s: Session, key: string, signature: string, make: () => [string, KqlRow, number][]): [string, KqlRow, number][] {
  const hit = s.entities.get(key);
  if (hit && hit.signature === signature) return hit.rows;
  const rows = make();
  s.entities.set(key, { signature, rows });
  return rows;
}

// ── Inventory ───────────────────────────────────────────────────────────────

const DEVICE_OS: Record<HostOs, { platform: string; version: string; type: string }> = {
  Windows: { platform: "Windows10", version: "10.0", type: "Workstation" }, WindowsServer: { platform: "WindowsServer2022", version: "10.0", type: "Server" },
  Linux: { platform: "Linux", version: "22.04", type: "Server" }, macOS: { platform: "macOS", version: "14.5", type: "Workstation" }, Appliance: { platform: "Other", version: "", type: "NetworkDevice" },
};

export function deviceIdOf(ctx: NativeCtx, companyId: string, name: string): string {
  return ctx.hex(`${companyId}:${name.toLowerCase()}`, 40);
}

function identityRow(s: Session, p: Person, at: number): KqlRow {
  const hq = countryInfo(COMPANY_HQ[s.companyId] ?? "IL");
  const parts = p.display.split(" ");
  return {
    TimeGenerated: iso(at), Type: "IdentityInfo", TenantId: s.map.tenantId, SourceSystem: "Azure", AccountUPN: p.upn, AccountName: p.name, AccountDomain: s.ctx.domain, AccountDisplayName: p.display, AccountTenantId: s.map.tenantId,
    AccountObjectId: entraObjectId(s.ctx, p.upn), AccountSID: p.sid, SAMAccountName: p.name, MailAddress: p.upn, GivenName: parts[0], Surname: parts.slice(1).join(" "), Department: p.department,
    JobTitle: p.title, Country: hq?.name, City: hq?.city, IsAccountEnabled: true, IsServiceAccount: p.service, UserType: "Member", UserState: "Active", CompanyName: s.ctx.org, LastSeenDate: iso(at),
    ...(p.noHistory ? { Tags: "New account" } : {}),
  };
}

function deviceRows(s: Session, h: Host, at: number, lastSeen: number | undefined, sidOf: (upn: string) => string | undefined): [string, KqlRow][] {
  const os = DEVICE_OS[h.os];
  const id = deviceIdOf(s.ctx, s.companyId, h.name);
  const reportId = fnv(`${s.companyId}:${h.key}:report`);
  const common = { TimeGenerated: iso(at), Timestamp: iso(at), TenantId: s.map.tenantId, SourceSystem: "Azure", DeviceId: id, DeviceName: h.name, MachineGroup: "Default", ReportId: reportId };
  const users = h.users.map(u => ({ UserName: u.split("@")[0], DomainName: s.ctx.netbios, Sid: sidOf(u) }));
  return [
    ["DeviceInfo", {
      ...common, Type: "DeviceInfo", OSPlatform: os.platform, OSVersion: os.version, DeviceType: os.type, PublicIP: s.egress, LoggedOnUsers: users, OnboardingStatus: h.os === "Appliance" ? "Unsupported" : "Onboarded",
      SensorHealthState: h.os === "Appliance" ? undefined : "Active", IsAzureADJoined: h.os === "Windows", JoinType: h.os === "Windows" ? "Azure AD joined" : undefined, Vendor: h.os === "macOS" ? "Apple" : undefined,
      AdditionalFields: { PrivateIP: h.ip, LastSeen: iso(Math.max(at, lastSeen ?? at)) },
    }],
    ["DeviceNetworkInfo", { ...common, Type: "DeviceNetworkInfo", IPAddresses: [h.ip, ...h.otherIps].map(IPAddress => ({ IPAddress, SubnetPrefix: 24, AddressType: "Private" })), NetworkAdapterStatus: "Up", NetworkAdapterType: "Ethernet", MacAddress: hex(`${s.companyId}:${h.key}:mac`, 12).toUpperCase() }],
  ];
}

// ── Public ──────────────────────────────────────────────────────────────────

export interface BaselineInput {
  companyId: string;
  stack?: Stack;
  identity?: NativeIdentity;
  orgName?: string;
  tenantId: string;
  /** The first released event's time: the start of the shift. */
  anchorMs: number;
  /** The workspace clock. */
  clockMs: number;
  directory: Directory;
  /** Last time the feed showed each host (lower-case short name). */
  hostLastSeen: Map<string, number>;
}

/** A firewall or proxy appliance names itself on its rows: it is in the inventory too. */
function networkDevices(tables: Record<string, KqlTable>, dir: Directory): string[] {
  const seen = new Map<string, string>();
  for (const r of tables.CommonSecurityLog.rows) {
    if (typeof r.DeviceName === "string" && r.DeviceName && !dir.hosts.has(r.DeviceName.toLowerCase().split(".")[0])) seen.set(r.DeviceName.toLowerCase(), r.DeviceName);
  }
  return [...seen.values()];
}

/** Adds inventory and background rows to the workspace's tables. Returns the number of rows added. */
export function addBaseline(tables: Record<string, KqlTable>, input: BaselineInput): number {
  const s = sessionFor(input.companyId, input.stack, input.identity, input.orgName, input.tenantId, input.anchorMs);
  const { directory: dir, clockMs } = input;
  const at = input.anchorMs - HOUR / 2;
  let added = 0;
  const add = (table: string, row: KqlRow) => { tables[table].rows.push(row); added++; };
  const addAll = (rows: [string, KqlRow, number][]) => {
    for (const [table, row, ms] of rows) if (ms <= clockMs) add(table, row);
  };

  for (const p of dir.people.values()) {
    add("IdentityInfo", identityRow(s, p, at));
    if (p.noHistory) continue;
    const host = dir.hosts.get(p.host.toLowerCase().split(".")[0]);
    const sig = JSON.stringify([p.sid, p.display, p.title, p.department, p.service, host?.name, host?.ip, host?.os]);
    addAll(cached(s, `p:${p.upn}`, sig, () => occurrences(s, `p:${p.upn}`, personPlans(s, p, host))));
  }
  for (const h of dir.hosts.values()) {
    for (const [t, row] of deviceRows(s, h, at, input.hostLastSeen.get(h.key), u => dir.people.get(u)?.sid)) {
      for (const k of Object.keys(row)) if (row[k] === undefined) delete row[k];
      add(t, row);
    }
    const primary = h.users.map(u => dir.people.get(u)).find(Boolean);
    const sig = JSON.stringify([h.name, h.ip, h.os, primary?.upn, primary?.sid]);
    addAll(cached(s, `h:${h.key}`, sig, () => occurrences(s, `h:${h.key}`, hostPlans(s, h, primary))));
  }
  for (const name of networkDevices(tables, dir)) {
    const h: Host = { name, key: name.toLowerCase(), os: "Appliance", server: true, ip: "", otherIps: [], users: [] };
    const row = deviceRows(s, h, at, undefined, () => undefined)[0][1];
    for (const k of Object.keys(row)) if (row[k] === undefined) delete row[k];
    add("DeviceInfo", row);
  }
  return added;
}

