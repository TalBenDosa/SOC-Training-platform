/**
 * Palo Alto Networks GlobalProtect — PAN-OS GLOBALPROTECT log type (PAN-OS 9.1+).
 * Card: docs/log-schemas/vpn-globalprotect.md
 *
 * Text-native: the record is a FLAT object keyed by the PAN-OS syslog variable
 * names (all values strings, as on the wire); `rawLine` is the syslog CSV line
 * rebuilt from the same values in the documented column order. The two
 * FUTURE_USE columns appear only in the raw line, never as keys.
 *
 * Renders every VPN event of the platform (GlobalProtect-, AnyConnect- and
 * FortiGate-authored) as the GP record a PA firewall would write:
 *   auth failure / MFA denied → portal-auth / gateway-auth  status=failure
 *   MFA challenge             → portal-auth status=success (first factor accepted at the
 *                               portal; the second factor is then evaluated at gateway-auth)
 *   login                     → gateway-connected (tunnel IP known) or gateway-auth
 *   logout                    → gateway-logout with login_duration
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import {
  vpnFacts, company, homeCountry, isPrivateIp, privateRange, panTime, panHiRes, bsdTime, digits,
  corpDeviceName, unmanagedDeviceName, osFamily, userKey, HIGH_RISK_ISO, type VpnFacts,
} from "./remote-access-shared";

/** Wire column order (FUTURE_USE columns excluded — they are emitted only in the raw line). */
export const GP_COLUMNS = [
  "receive_time", "serial", "type", "subtype", "time_generated", "vsys", "eventid", "stage", "auth_method",
  "tunnel_type", "srcuser", "srcregion", "machinename", "public_ip", "public_ipv6", "private_ip", "private_ipv6",
  "hostid", "serialnumber", "client_ver", "client_os", "client_os_ver", "repeatcnt", "reason", "error", "opaque",
  "status", "location", "login_duration", "connect_method", "error_code", "portal", "seqno", "actionflags",
  "high_res_timestamp", "selection_type", "response_time", "priority", "attempted_gateways", "gateway",
  "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
  "vsys_id", "cluster_name",
] as const;

/** Documented GlobalProtect event IDs (card §3). Same column set for every event. */
const EVENT_IDS = [
  "portal-prelogin", "portal-auth", "portal-getconfig", "gateway-prelogin", "gateway-auth", "gateway-getconfig",
  "gateway-register", "gateway-hip-check", "gateway-hip-report", "gateway-setup-ipsec", "gateway-setup-ssl",
  "gateway-switch-to-ssl", "gateway-tunnel-latency", "gateway-connected", "gateway-config-release", "gateway-logout",
];

const kind = (): KindSchema => ({ required: [...GP_COLUMNS], optional: ["raw"] /* card representation carries the raw line too */ });

const schema: SourceSchema = {
  sourceId: "globalprotect",
  category: "vpn",
  card: "vpn-globalprotect.md",
  product: "Palo Alto Networks GlobalProtect",
  format: "csv",
  vendorMatch: ["globalprotect", "palo alto"],
  telemetrySources: ["vpn"],
  kinds: Object.fromEntries(EVENT_IDS.map(e => [e, kind()])),
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.type !== "GLOBALPROTECT") return null;
  return typeof record.eventid === "string" && EVENT_IDS.includes(record.eventid) ? record.eventid : null;
}

function gpAuthMethod(raw: string | undefined): string {
  const s = (raw ?? "").toLowerCase();
  if (/azure|saml|okta|entra|sso/.test(s)) return "SAML";
  if (/kerberos/.test(s)) return "Kerberos";
  if (/local/.test(s)) return "Local DB";
  if (/otp|totp|duo|radius|push|phoneapp|token/.test(s)) return "RADIUS";
  if (/ldap/.test(s)) return "LDAP";
  return raw ? "Other" : "LDAP";
}

function osStrings(os: string | undefined): { client_os: string; client_os_ver: string } {
  const fam = osFamily(os);
  const s = os ?? "";
  if (fam === "linux") return { client_os: "Linux", client_os_ver: /ubuntu/i.test(s) ? s : "Ubuntu 22.04.4 LTS" };
  if (fam === "mac") return { client_os: "Apple Mac OS X", client_os_ver: "macOS 14.6" };
  if (fam === "ios") return { client_os: "Apple iOS", client_os_ver: "iOS 17.6" };
  if (fam === "android") return { client_os: "Android", client_os_ver: "Android 14" };
  if (/server/i.test(s)) return { client_os: "Microsoft Windows", client_os_ver: "Microsoft Windows Server 2022 , 64-bit" };
  if (/\b10\b/.test(s)) return { client_os: "Microsoft Windows", client_os_ver: "Microsoft Windows 10 Pro , 64-bit" };
  return { client_os: "Microsoft Windows", client_os_ver: "Microsoft Windows 11 Enterprise , 64-bit" };
}

function csvCell(v: string): string {
  return /[",]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
}

export function gpRawLine(r: Record<string, string>): string {
  const cells: string[] = ["1"];
  for (const c of GP_COLUMNS) {
    const v = r[c] ?? "";
    cells.push(c === "opaque" && v !== "" ? `"${v.replace(/"/g, '""')}"` : csvCell(v)); // PAN-OS always quotes the description
    if (c === "subtype") cells.push("2817"); // FUTURE_USE column 6
  }
  const ms = Date.parse(r.high_res_timestamp);
  return `<14>${bsdTime(Number.isFinite(ms) ? ms : 0)} ${r.device_name} ${cells.join(",")}`;
}

function build(ev: TelemetryEvent, f: VpnFacts, ctx: NativeCtx): Record<string, string> {
  const co = company(ctx);
  const ms = Date.parse(ev.ts);
  const user = f.authMethod && gpAuthMethod(f.authMethod) === "SAML" ? (f.id.email ?? f.userAsLogged ?? f.id.sam) : (f.userAsLogged ?? f.id.sam ?? f.id.email);
  const srcuser = user ?? "";
  const publicIp = f.publicIp ?? "0.0.0.0";
  const region = f.publicIp && isPrivateIp(f.publicIp) ? privateRange(f.publicIp) : (f.country ?? homeCountry(ctx)).iso;
  const failing = f.phase === "auth_fail" || f.phase === "mfa_denied";
  // Attackers' scripted failures carry no client fingerprint (card 4.3); everyone else's device is known.
  const hasDevice = !(failing && !f.clientHost);
  const key = userKey(f);
  const machinename = !hasDevice ? "" : f.clientHost ?? (f.clientUnmanaged ? unmanagedDeviceName(ctx, `${ctx.companyId}:${key}:${f.publicIp}`) : corpDeviceName(ctx, key));
  const os = osStrings(f.clientOs);
  const clientVer = f.clientUnmanaged || /1909|\b10\b/.test(f.clientOs ?? "") ? "6.0.7-11" : "6.2.4-28";
  const gatewayName = f.gatewayName ?? `GP-GW-${co.short}`;
  const portalName = `GP-Portal-${co.short}`;
  const deviceName = f.gatewayHost ?? `PA-3220-${co.short}`;
  const method = gpAuthMethod(f.authMethod);
  const opaqueLogin = `Client region: ${region}, Client version: ${clientVer}, Device name: ${machinename}, Login from: ${publicIp}.`;

  const base: Record<string, string> = {
    receive_time: panTime(ms + 1000),
    serial: `0162010${digits(ctx, `${ctx.companyId}:pa-serial`, 5)}`,
    type: "GLOBALPROTECT",
    subtype: "0",
    time_generated: panTime(ms),
    vsys: "vsys1",
    eventid: "",
    stage: "",
    auth_method: "",
    tunnel_type: "",
    srcuser,
    srcregion: region,
    machinename,
    public_ip: publicIp,
    public_ipv6: "0.0.0.0",
    private_ip: "0.0.0.0",
    private_ipv6: "0.0.0.0",
    hostid: hasDevice ? ctx.uuid(`${ctx.companyId}:gp-hostid:${machinename}`) : "",
    serialnumber: !hasDevice ? "" : f.clientUnmanaged ? "" : ctx.hex(`${ctx.companyId}:hwserial:${machinename}`, 8).toUpperCase(),
    client_ver: hasDevice ? clientVer : "",
    client_os: hasDevice ? os.client_os : "",
    client_os_ver: hasDevice ? os.client_os_ver : "",
    repeatcnt: "1",
    reason: "",
    error: "",
    opaque: "",
    status: "success",
    location: "",
    login_duration: "0",
    connect_method: "",
    error_code: "0",
    portal: gatewayName,
    seqno: `7412983300${digits(ctx, `${ev.id}:gp-seqno`, 9)}`,
    actionflags: "0x0",
    high_res_timestamp: panHiRes(ms + 1000 - (ms % 1000) + ctx.int(`${ev.id}:gp-ms`, 0, 999)),
    selection_type: "",
    response_time: "0",
    priority: "",
    attempted_gateways: "",
    gateway: "",
    dg_hier_level_1: "12",
    dg_hier_level_2: "0",
    dg_hier_level_3: "0",
    dg_hier_level_4: "0",
    vsys_name: "",
    device_name: deviceName,
    vsys_id: "1",
    cluster_name: "",
  };

  switch (f.phase) {
    case "auth_fail":
    case "mfa_denied": {
      const atGateway = f.phase === "mfa_denied" || !!f.gatewayName && !/portal/i.test(f.gatewayName) && !!f.clientHost;
      Object.assign(base, {
        eventid: atGateway ? "gateway-auth" : "portal-auth",
        stage: "login",
        auth_method: method,
        error: "Authentication failed: Invalid username or password",
        opaque: hasDevice ? opaqueLogin : `Client region: ${region}, Login from: ${publicIp}, Source region: ${region}.`,
        status: "failure",
        portal: atGateway ? gatewayName : portalName,
      });
      break;
    }
    case "mfa_challenge":
      Object.assign(base, { eventid: "portal-auth", stage: "login", auth_method: method, opaque: opaqueLogin, portal: portalName });
      break;
    case "login":
      if (f.tunnelIp) {
        const ssl = /ssl/i.test(`${f.sessionType ?? ""} ${f.fgtTunnelType ?? ""}`);
        Object.assign(base, {
          eventid: "gateway-connected",
          stage: "tunnel",
          tunnel_type: ssl ? "SSLVPN" : "IPSec",
          private_ip: f.tunnelIp,
          connect_method: f.clientUnmanaged ? "on-demand" : "user-logon",
          selection_type: "auto",
          response_time: String(ctx.int(`${ev.id}:gp-rt`, 20, 120)),
          priority: "1",
          attempted_gateways: gatewayName,
          gateway: gatewayName,
        });
      } else {
        Object.assign(base, {
          eventid: "gateway-auth",
          stage: "login",
          auth_method: method,
          opaque: opaqueLogin,
          connect_method: f.clientUnmanaged ? "on-demand" : "user-logon",
          selection_type: "auto",
          response_time: String(ctx.int(`${ev.id}:gp-rt`, 20, 120)),
          priority: "1",
          gateway: gatewayName,
        });
      }
      break;
    case "logout":
      Object.assign(base, {
        eventid: "gateway-logout",
        stage: "logout",
        tunnel_type: "IPSec",
        private_ip: f.tunnelIp ?? "0.0.0.0",
        opaque: "Logout reason: client logout.", // wording UNVERIFIED (card 4.6)
        login_duration: String(f.durationSec ?? 0),
        connect_method: "user-logon",
        gateway: gatewayName,
      });
      break;
  }
  return base;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = vpnFacts(ev);
  if (!f) return null;
  const record = build(ev, f, ctx);
  return { sourceId: "globalprotect", kind: record.eventid, format: "csv", record, rawLine: gpRawLine(record), timeMs: Date.parse(ev.ts) };
}

const AUTH_EVENTS = ["portal-auth", "gateway-auth"];
const SESSION_START = ["gateway-connected", "gateway-auth", "portal-auth"];

const useCases: UseCase[] = [
  {
    id: "globalprotect.portal_password_spray",
    title: "GlobalProtect portal password spray (many users, one source IP)",
    sourceId: "globalprotect",
    kinds: AUTH_EVENTS,
    severity: "high",
    mitre: ["T1110.003", "T1133"],
    description: "One public IP fails GlobalProtect authentication for five or more different usernames inside 10 minutes. Real users mistype their own password; a script tries one password against many accounts. Check whether the same public_ip later shows status=success — that account is compromised.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect eventid IN (portal-auth, gateway-auth) status=failure | bin _time span=10m | stats dc(srcuser) AS users values(srcuser) BY public_ip srcregion _time | where users>=5",
    match: { all: [{ field: "status", op: "eq", value: "failure" }, { field: "public_ip", op: "notCidr", value: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] }] },
    threshold: { groupBy: ["public_ip"], count: 5, windowSec: 600, distinct: "srcuser" },
    falsePositives: ["Shared egress IP (carrier-grade NAT, hotel Wi-Fi) where several employees genuinely mistype", "Vulnerability scanner hitting the portal during an authorised test"],
  },
  {
    id: "globalprotect.portal_brute_force_single_user",
    title: "GlobalProtect brute force against one account",
    sourceId: "globalprotect",
    kinds: AUTH_EVENTS,
    severity: "medium",
    mitre: ["T1110.001"],
    description: "Ten or more failed GlobalProtect logins for the same srcuser within 10 minutes. Either the user's saved credential is stale (a client retry loop) or someone is guessing that account's password. Compare public_ip and machinename with the user's normal device.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect status=failure eventid IN (portal-auth, gateway-auth) | bin _time span=10m | stats count values(public_ip) BY srcuser _time | where count>=10",
    match: { field: "status", op: "eq", value: "failure" },
    threshold: { groupBy: ["srcuser"], count: 10, windowSec: 600 },
    falsePositives: ["Password recently changed while the GlobalProtect app keeps retrying the cached one"],
  },
  {
    id: "globalprotect.login_from_high_risk_region",
    title: "Successful GlobalProtect login from a high-risk region",
    sourceId: "globalprotect",
    kinds: SESSION_START,
    severity: "high",
    mitre: ["T1078", "T1133"],
    description: "A GlobalProtect authentication or tunnel succeeded from a region where the company has no staff (srcregion is the firewall's GeoIP of public_ip). Valid credentials used from an unexpected country are the classic sign of stolen VPN credentials. Check the device fingerprint (machinename, hostid, client_ver) against the user's usual device.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect status=success eventid IN (gateway-connected, gateway-auth, portal-auth) srcregion IN (RU, BY, CN, KP, IR, NG, SY) | table _time srcuser public_ip srcregion machinename client_ver",
    match: { all: [{ field: "status", op: "eq", value: "success" }, { field: "srcregion", op: "in", value: HIGH_RISK_ISO }] },
    falsePositives: ["Approved business travel (check HR travel calendar)", "Employee using a commercial VPN that exits in that country"],
  },
  {
    id: "globalprotect.concurrent_sessions_two_regions",
    title: "Same user connected from two regions (concurrent session / impossible travel)",
    sourceId: "globalprotect",
    kinds: SESSION_START,
    severity: "high",
    mitre: ["T1078"],
    description: "The same srcuser authenticates or brings up a tunnel from two different srcregion values within 4 hours. Unless one is a corporate egress or a known VPN-on-VPN setup, nobody travels that fast — one of the sessions is using stolen credentials. Different hostid/machinename on the second session confirms a second device.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect status=success eventid IN (gateway-connected, gateway-auth) | stats dc(srcregion) AS regions values(srcregion) values(public_ip) values(machinename) BY srcuser span=4h | where regions>1",
    match: { all: [{ field: "status", op: "eq", value: "success" }, { field: "srcuser", op: "exists" }] },
    threshold: { groupBy: ["srcuser"], count: 2, windowSec: 4 * 3600, distinct: "srcregion" },
    falsePositives: ["Mobile device roaming through a carrier that egresses in another country", "User switching from home ISP to a personal VPN"],
  },
  {
    id: "globalprotect.unmanaged_device_login",
    title: "GlobalProtect login from an unmanaged device",
    sourceId: "globalprotect",
    kinds: SESSION_START,
    severity: "medium",
    mitre: ["T1078", "T1133"],
    description: "A successful GlobalProtect connection whose machinename is a Windows default name (DESKTOP-xxxxxxx / WIN-xxxxxxx) or whose hardware serialnumber is empty or a VM serial. Corporate laptops follow the naming standard; an attacker's VM does not.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect status=success (machinename=\"DESKTOP-*\" OR machinename=\"WIN-*\" OR serialnumber=\"\" OR serialnumber=\"VMware-*\") | table _time srcuser machinename serialnumber client_ver public_ip srcregion",
    match: { all: [
      { field: "status", op: "eq", value: "success" },
      { any: [{ field: "machinename", op: "regex", value: "^(DESKTOP|WIN)-" }, { field: "serialnumber", op: "regex", value: "^VMware-" }] },
    ] },
    falsePositives: ["BYOD contractors allowed on a dedicated portal", "Freshly re-imaged laptop before the rename step"],
  },
  {
    id: "globalprotect.success_after_failures_same_ip",
    title: "Successful login from an IP that just failed authentication",
    sourceId: "globalprotect",
    kinds: [...AUTH_EVENTS, "gateway-connected"],
    severity: "medium",
    mitre: ["T1110", "T1078"],
    description: "Within 30 minutes the same public_ip has both failed and successful GlobalProtect events. After a spray this means a guessed password worked; for a single user it is usually just a typo. Look at how many failures and how many different usernames preceded the success.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect eventid IN (portal-auth, gateway-auth, gateway-connected) | stats dc(status) AS outcomes values(srcuser) count BY public_ip span=30m | where outcomes=2",
    match: { field: "status", op: "in", value: ["success", "failure"] },
    threshold: { groupBy: ["public_ip"], count: 2, windowSec: 1800, distinct: "status" },
    falsePositives: ["User mistypes the password or declines an MFA push once, then succeeds"],
  },
  {
    id: "globalprotect.off_hours_login",
    title: "GlobalProtect login between 00:00 and 05:59",
    sourceId: "globalprotect",
    kinds: SESSION_START,
    severity: "low",
    mitre: ["T1078"],
    description: "A successful VPN session started in the middle of the night (firewall time). On its own it is weak, but combined with a new region, an outdated client_ver or an unmanaged machinename it is how many intrusions through stolen VPN credentials begin.",
    logic: "SPL: index=pan sourcetype=pan:globalprotect status=success | eval hour=tonumber(strftime(_time,\"%H\")) | where hour<6 | table _time srcuser public_ip srcregion machinename",
    match: { all: [{ field: "status", op: "eq", value: "success" }, { field: "time_generated", op: "regex", value: " 0[0-5]:" }] },
    falsePositives: ["On-call engineers and staff in other time zones"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
