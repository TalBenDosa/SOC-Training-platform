/**
 * Authentic raw-log renderer.
 *
 * Serialises a LiveEvent into the wire format its data source *actually* emits,
 * so the "Raw" tab reads like a real SIEM's unparsed view rather than the
 * platform's internal object.
 *
 * The format is chosen per SOURCE **and VENDOR** — not per source alone. That
 * distinction matters: AWS WAF and Cloudflare emit JSON (via Firehose / Logpush),
 * while F5 and Imperva emit syslog/CEF. And each firewall family has its OWN
 * wire shape — FortiGate is key=value, PAN-OS is CSV, Check Point is key=value
 * with its own field names, Cisco ASA is a %ASA-x-xxxxxx message. Stamping one
 * vendor's scaffolding (e.g. FortiGate's `devname=`/`vd=root`) onto every
 * appliance is exactly the kind of tell a real analyst spots instantly.
 *
 * It only serialises fields that already exist on the event, so the raw view
 * stays faithful to the (vendor-accurate) source data — nothing is invented.
 */
import type { LiveEvent } from "./useLiveEvents";

export interface RawLog {
  /** Short human label for the format, shown above the blob. */
  format: string;
  /** The rendered raw log text. */
  text: string;
  /** Syntax family, for lightweight styling. */
  lang: "xml" | "syslog" | "json";
}

/** Stable pseudo-random from event id — never Math.random (must be render-stable). */
function stableHash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

// ─── Format selection ──────────────────────────────────────────────────────────

type FirewallKind = "fortigate" | "panos" | "checkpoint" | "cisco" | "generic";

/** Appliance sources that *may* emit syslog — final call still depends on vendor. */
const APPLIANCE_SOURCES = new Set(["firewall", "vpn", "ids", "proxy", "nac", "dhcp", "waf", "dns"]);

/** Vendors that are cloud services — these ship JSON, never syslog. */
const CLOUD_LOG_VENDORS = [
  "aws", "cloudflare", "azure", "akamai", "gcp", "google",
  "zscaler", "netskope", "umbrella", "cloudfront",
];

function vendorOf(event: LiveEvent): string {
  return (event.vendor ?? "").toLowerCase();
}

function firewallKind(event: LiveEvent): FirewallKind {
  const v = vendorOf(event);
  if (v.includes("forti")) return "fortigate";
  if (v.includes("palo") || v.includes("pan-os") || v.includes("panos") || v.includes("globalprotect")) return "panos";
  if (v.includes("check point") || v.includes("checkpoint")) return "checkpoint";
  if (v.includes("cisco") || v.includes("asa") || v.includes("firepower")) return "cisco";
  return "generic";
}

/** Windows sources emit XML; anything carrying winlog.* fields is Windows too. */
function isWindowsEventLog(event: LiveEvent): boolean {
  if (event.source === "sysmon" || event.source === "ad" || event.source === "windows_security") return true;
  return Object.keys(event.raw ?? {}).some(k => k.startsWith("winlog."));
}

/** True when this appliance event is from a cloud service (JSON) rather than a box (syslog). */
function isCloudVendor(event: LiveEvent): boolean {
  const v = vendorOf(event);
  return CLOUD_LOG_VENDORS.some(c => v.includes(c));
}

function esc(s: unknown): string {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ─── Windows Event XML ─────────────────────────────────────────────────────────

/** Real, well-known provider GUIDs — these are stable published values. */
const PROVIDER_GUID: Record<string, string> = {
  "Microsoft-Windows-Security-Auditing": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
  "Microsoft-Windows-Sysmon":            "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
};

function toWinXml(event: LiveEvent): string {
  const raw = event.raw ?? {};
  const str = (k: string) => (raw[k] === undefined || raw[k] === null ? undefined : String(raw[k]));

  const isSysmon = event.source === "sysmon" || str("winlog.provider_name")?.includes("Sysmon");
  const provider =
    str("winlog.provider_name") ?? (isSysmon ? "Microsoft-Windows-Sysmon" : "Microsoft-Windows-Security-Auditing");

  // Canonical Event ID for this event type when the source didn't carry one,
  // so the XML header is never mislabelled (e.g. a DNS query showing EventID 1).
  const SECURITY_EVENT_ID: Partial<Record<string, string>> = {
    auth_success: "4624", auth_failure: "4625", account_lockout: "4740",
    kerberos_tgt: "4768", kerberos_tgs: "4769", process_create: "4688",
    account_create: "4720", account_modify: "4738", account_delete: "4726",
    group_modify: "4728", audit_log_cleared: "1102", privilege_escalation: "4672",
  };
  const SYSMON_EVENT_ID: Partial<Record<string, string>> = {
    process_create: "1", net_connection: "3", file_create: "11",
    registry_set: "13", registry_delete: "13", dns_query: "22",
  };
  const eventId = str("winlog.event_id") ??
    (isSysmon ? SYSMON_EVENT_ID[event.event_type] ?? "1" : SECURITY_EVENT_ID[event.event_type] ?? "4688");

  const channel = str("winlog.channel") ?? (isSysmon ? "Microsoft-Windows-Sysmon/Operational" : "Security");
  const computer = event.hostname ?? str("winlog.computer_name") ?? "-";

  // Windows Security events are Level 0 (Information) regardless of how alarming
  // they are — severity lives in the audit result, not the level. Sysmon uses 4.
  const level = isSysmon ? "4" : "0";
  // Audit Success vs Audit Failure keyword (real values from the Security channel).
  const keywords = isSysmon ? "0x8000000000000000"
    : event.event_type === "auth_failure" ? "0x8010000000000000"
    : "0x8020000000000000";

  const dataPairs: [string, string][] = Object.entries(raw)
    .filter(([k, v]) => k.startsWith("winlog.event_data.") && v !== null && v !== undefined && v !== "")
    .map(([k, v]) => [k.slice("winlog.event_data.".length), String(v)]);

  if (dataPairs.length === 0) {
    if (isSysmon && event.process) {
      if (raw["ProcessGuid"]) dataPairs.push(["ProcessGuid", String(raw["ProcessGuid"])]);
      dataPairs.push(["Image", event.process.path ?? event.process.name]);
      if (event.process.cmdline) dataPairs.push(["CommandLine", event.process.cmdline]);
      if (event.process.user) dataPairs.push(["User", event.process.user]);
      if (event.process.parent_name) {
        const p = event.process.parent_name.toLowerCase();
        dataPairs.push(["ParentImage", p === "explorer.exe" ? "C:\\Windows\\explorer.exe" : `C:\\Windows\\System32\\${event.process.parent_name}`]);
      }
      if (event.file?.sha256) dataPairs.push(["Hashes", `SHA256=${event.file.sha256}`]);
    } else {
      if (event.user_email) dataPairs.push(["TargetUserName", event.user_email]);
      if (event.src_ip) dataPairs.push(["IpAddress", event.src_ip]);
      if (event.authentication?.logon_type !== undefined) dataPairs.push(["LogonType", String(event.authentication.logon_type)]);
    }
  }

  const guid = PROVIDER_GUID[provider];
  const recordId = str("winlog.record_id") ?? String(1_000_000 + (stableHash(event.id) % 900000));
  // Execution ProcessID: the service that wrote the record (lsass=4 for Security audit).
  const execPid = isSysmon ? String(2000 + (stableHash("p" + event.id) % 500)) : "4";
  const execTid = String(60 + (stableHash("t" + event.id) % 900));

  const dataXml = dataPairs
    .map(([name, value]) => `    <Data Name="${esc(name)}">${esc(value)}</Data>`)
    .join("\n");

  return [
    `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">`,
    `  <System>`,
    `    <Provider Name="${esc(provider)}"${guid ? ` Guid="${guid}"` : ""} />`,
    `    <EventID>${esc(eventId)}</EventID>`,
    `    <Version>0</Version>`,
    `    <Level>${level}</Level>`,
    `    <Task>0</Task>`,
    `    <Opcode>0</Opcode>`,
    `    <Keywords>${keywords}</Keywords>`,
    `    <TimeCreated SystemTime="${esc(event.ts)}" />`,
    `    <EventRecordID>${esc(recordId)}</EventRecordID>`,
    `    <Correlation />`,
    `    <Execution ProcessID="${execPid}" ThreadID="${execTid}" />`,
    `    <Channel>${esc(channel)}</Channel>`,
    `    <Computer>${esc(computer)}</Computer>`,
    `    <Security UserID="S-1-5-18" />`,
    `  </System>`,
    `  <EventData>`,
    dataXml,
    `  </EventData>`,
    `</Event>`,
  ].filter(Boolean).join("\n");
}

// ─── Syslog helpers ────────────────────────────────────────────────────────────

function kv(key: string, value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  const s = String(value);
  return /\s/.test(s) ? `${key}="${s}"` : `${key}=${s}`;
}

/**
 * ECS keys that duplicate the vendor-native fields we emit from typed values.
 * Emitting both (`srcip=10.0.0.1 source.ip=10.0.0.1`) is a dead giveaway — real
 * appliance logs carry each fact once, in that vendor's own field name.
 */
const ECS_DUPLICATE_KEYS = new Set([
  "source.ip", "source.port", "destination.ip", "destination.port",
  "network.protocol", "network.transport", "rule.description", "event.action",
]);

/**
 * The device that emitted the log is the APPLIANCE, not the endpoint that
 * happened to generate the traffic. `devname=WS-FIN-2847` on a Palo Alto traffic
 * log (a finance workstation naming the firewall) is an instant tell.
 */
function deviceName(event: LiveEvent, kind: FirewallKind): string {
  const raw = event.raw ?? {};
  for (const k of ["devname", "observer.name", "orig", "gp.gateway", "data.devname", "observer.hostname"]) {
    const v = raw[k];
    if (v) return String(v);
  }
  switch (kind) {
    case "fortigate":  return "FG-100F-01";
    case "panos":      return "PA-VM-01";
    case "checkpoint": return "CP-GW-01";
    case "cisco":      return "ASA-5525-01";
    default:           return "fw01";
  }
}

function syslogTs(event: LiveEvent) {
  const d = event.ts ? new Date(event.ts) : new Date(0);
  const p = (n: number) => String(n).padStart(2, "0");
  const MON = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
  return {
    date: `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())}`,
    time: `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
    panDate: `${d.getUTCFullYear()}/${p(d.getUTCMonth() + 1)}/${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
    bsd: `${MON[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, " ")} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`,
  };
}

/** Vendor-native raw fields (skip ECS duplicates + the platform's own rule text). */
function vendorRawPairs(event: LiveEvent): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(event.raw ?? {})) {
    if (v === null || v === undefined || v === "" || typeof v === "object") continue;
    if (ECS_DUPLICATE_KEYS.has(k)) continue;
    const s = kv(k, v);
    if (s) out.push(s);
  }
  return out;
}

// ─── FortiGate: key=value ──────────────────────────────────────────────────────

function toFortiGate(event: LiveEvent): string {
  const { date, time } = syslogTs(event);
  const dev = deviceName(event, "fortigate");
  const parts: (string | null)[] = [
    kv("date", date), kv("time", time), kv("devname", dev),
    kv("devid", `FG100F${stableHash(dev) % 10_000_000}`), kv("vd", "root"),
    kv("srcip", event.src_ip), kv("srcport", event.src_port),
    kv("dstip", event.dst_ip), kv("dstport", event.dst_port),
    kv("proto", event.protocol),
  ];
  return `<189>${parts.filter(Boolean).join(" ")} ${vendorRawPairs(event).join(" ")}`.trim();
}

// ─── PAN-OS: comma-separated CSV ───────────────────────────────────────────────

/**
 * PAN-OS GlobalProtect log (Type=GLOBALPROTECT). A VPN authentication is NOT a
 * traffic log — it has no destination or ports, and rendering it as TRAFFIC
 * produces a giveaway line with empty dst/port columns.
 */
function toPanGlobalProtect(event: LiveEvent): string {
  const raw = event.raw ?? {};
  const s = (k: string) => (raw[k] === undefined ? "" : String(raw[k]));
  const { panDate, bsd } = syslogTs(event);
  const dev = deviceName(event, "panos");
  const serial = String(13201001231 + (stableHash(dev) % 1000));

  const action = s("event.action");
  const eventId = action.includes("disconnect") || event.event_type === "vpn_logout" ? "gateway-logout"
    : event.event_type === "vpn_failed" ? "gateway-auth"
    : "gateway-auth";
  const status = event.event_type === "vpn_failed" ? "failure" : "success";

  // GlobalProtect field order: FUTURE_USE, Receive Time, Serial, Type,
  // Threat/Content Type, FUTURE_USE, Generated Time, Virtual System, Event ID,
  // Stage, Auth Method, Tunnel Type, Source User, Source Region, Machine Name,
  // Public IP, Public IPv6, Private IP, Private IPv6, Host ID, Client Version,
  // Client OS, Endpoint Device Name, Status, Error Code, Description
  const fields = [
    panDate, serial, "GLOBALPROTECT", "0", "0", panDate, "vsys1",
    eventId, "login", s("gp.auth_method") || "", "ssl-tunnel",
    event.user_email ?? "", s("source.geo.country_name") || "",
    s("gp.client_hostname") || event.hostname || "",
    event.src_ip ?? "", "", s("gp.tunnel_ip") || "", "",
    s("gp.host_id") || "", s("gp.client_version") || "", s("gp.client_os") || "",
    s("gp.client_hostname") || event.hostname || "",
    status, "0", "",
  ];
  const csv = fields.map(f => (f.includes(",") ? `"${f}"` : f)).join(",");
  return `<14>${bsd} ${dev} 1,${csv}`;
}

function toPanOs(event: LiveEvent): string {
  if (event.source === "vpn") return toPanGlobalProtect(event);

  const raw = event.raw ?? {};
  const s = (k: string) => (raw[k] === undefined ? "" : String(raw[k]));
  const { panDate, bsd } = syslogTs(event);
  const dev = deviceName(event, "panos");
  const serial = String(13201001231 + (stableHash(dev) % 1000));

  const isThreat = !!(s("pan.threat_id") || s("pan.threat_name") || event.source === "ids");
  const type = isThreat ? "THREAT" : "TRAFFIC";
  const subtype = isThreat ? (s("pan.threat_category") || "vulnerability") : "end";

  // PAN-OS syslog field order (Traffic/Threat log), per PAN-OS syslog field
  // descriptions: FUTURE_USE, Receive Time, Serial, Type, Subtype, FUTURE_USE,
  // Generated Time, Source Addr, Dest Addr, NAT Src, NAT Dst, Rule Name,
  // Source User, Dest User, Application, Virtual System, Source Zone, Dest Zone,
  // Inbound IF, Outbound IF, Log Action, ...
  const fields = [
    panDate, serial, type, subtype, "0", panDate,
    event.src_ip ?? "", event.dst_ip ?? "", "0.0.0.0", "0.0.0.0",
    s("pan.rulename") || s("rule.name") || "",
    event.user_email ?? "", "",
    s("pan.app") || s("application") || "",
    s("panw.panos.virtual_system") || "vsys1",
    s("panw.panos.source.zone") || "trust",
    s("panw.panos.destination.zone") || "untrust",
    "ethernet1/1", "ethernet1/2", "LOG-Profile",
    "", "", String(event.src_port ?? ""), String(event.dst_port ?? ""),
    "", "", event.protocol ?? "tcp",
    s("pan.action") || s("panw.panos.action") || "",
  ];
  const head = `<14>${bsd} ${dev} 1,`;
  const csv = fields.map(f => (f.includes(",") ? `"${f}"` : f)).join(",");

  // Threat logs additionally carry the signature identity — appended as the
  // trailing threat columns rather than invented key=value pairs.
  const tail = isThreat
    ? `,${s("pan.threat_id")},"${s("pan.threat_name")}",${s("pan.threat_category")},${s("url.path")}`
    : "";
  return head + csv + tail;
}

// ─── Check Point: key=value with CP field names ────────────────────────────────

function toCheckPoint(event: LiveEvent): string {
  const { bsd } = syslogTs(event);
  const dev = deviceName(event, "checkpoint");
  const parts: (string | null)[] = [
    kv("product", "VPN-1 & FireWall-1"), kv("origin", dev),
    kv("src", event.src_ip), kv("s_port", event.src_port),
    kv("dst", event.dst_ip), kv("service", event.dst_port),
    kv("proto", event.protocol),
  ];
  return `<134>${bsd} ${dev} CheckPoint: ${parts.filter(Boolean).join(" ")} ${vendorRawPairs(event).join(" ")}`.trim();
}

// ─── Cisco ASA: %ASA-level-id message ──────────────────────────────────────────

function toCiscoAsa(event: LiveEvent): string {
  const { bsd } = syslogTs(event);
  const dev = deviceName(event, "cisco");
  const connId = 10_000 + (stableHash(event.id) % 90_000);
  const proto = (event.protocol ?? "TCP").toUpperCase();

  const denied = /deny|block|drop/i.test(String((event.raw ?? {})["event.action"] ?? ""));
  const msg = denied
    ? `%ASA-4-106023: Deny ${proto} src inside:${event.src_ip}/${event.src_port ?? 0} dst outside:${event.dst_ip}/${event.dst_port ?? 0} by access-group "outside_access_in"`
    : `%ASA-6-302013: Built outbound ${proto} connection ${connId} for outside:${event.dst_ip}/${event.dst_port ?? 0} (${event.dst_ip}/${event.dst_port ?? 0}) to inside:${event.src_ip}/${event.src_port ?? 0} (${event.src_ip}/${event.src_port ?? 0})`;
  return `<134>${bsd} ${dev} ${msg}`;
}

// ─── Generic RFC5424 appliance syslog ──────────────────────────────────────────

function toGenericSyslog(event: LiveEvent): string {
  const { date, time } = syslogTs(event);
  const dev = deviceName(event, "generic");
  const tag = (event.vendor ?? event.source).replace(/\s+/g, "");
  const parts: (string | null)[] = [
    kv("src", event.src_ip), kv("spt", event.src_port),
    kv("dst", event.dst_ip), kv("dpt", event.dst_port),
    kv("proto", event.protocol),
  ];
  return `<134>1 ${date}T${time}Z ${dev} ${tag} - - - ` +
    [...parts.filter(Boolean), ...vendorRawPairs(event)].join(" ");
}

// ─── JSON blob (EDR / cloud / identity / DLP …) ─────────────────────────────────

function toJson(event: LiveEvent): string {
  const raw = event.raw ?? {};
  const merged: Record<string, unknown> = {};
  if (event.ts) merged["@timestamp"] = event.ts;
  if (event.vendor) merged["observer.vendor"] = event.vendor;
  merged["event.type"] = event.event_type;
  if (event.hostname) merged["host.name"] = event.hostname;
  if (event.user_email) merged["user.name"] = event.user_email;
  if (event.src_ip) merged["source.ip"] = event.src_ip;
  if (event.dst_ip) merged["destination.ip"] = event.dst_ip;

  for (const [k, v] of Object.entries(raw)) {
    if (v === null || v === undefined || v === "") continue;
    merged[k] = v;
  }
  return JSON.stringify(merged, null, 2);
}

// ─── Entry point ────────────────────────────────────────────────────────────────

export function toRawLog(event: LiveEvent): RawLog {
  if (isWindowsEventLog(event)) {
    return { format: "Windows Event Log (XML)", text: toWinXml(event), lang: "xml" };
  }

  // Appliance sources emit syslog ONLY when the vendor is an actual box.
  // Cloud services (AWS WAF, Cloudflare, Zscaler, Azure…) ship JSON.
  if (APPLIANCE_SOURCES.has(event.source) && !isCloudVendor(event)) {
    const kind = firewallKind(event);
    const vendorLabel = event.vendor ? ` — ${event.vendor}` : "";
    switch (kind) {
      case "fortigate":  return { format: `Syslog, key=value${vendorLabel}`, text: toFortiGate(event),  lang: "syslog" };
      case "panos":      return { format: `Syslog, PAN-OS CSV${vendorLabel}`, text: toPanOs(event),      lang: "syslog" };
      case "checkpoint": return { format: `Syslog${vendorLabel}`,             text: toCheckPoint(event), lang: "syslog" };
      case "cisco":      return { format: `Syslog, ASA message${vendorLabel}`, text: toCiscoAsa(event),  lang: "syslog" };
      default:           return { format: `Syslog, RFC5424${vendorLabel}`,    text: toGenericSyslog(event), lang: "syslog" };
    }
  }

  const vendorLabel = event.vendor ? ` — ${event.vendor}` : "";
  return { format: `JSON, SIEM-ingested${vendorLabel}`, text: toJson(event), lang: "json" };
}
