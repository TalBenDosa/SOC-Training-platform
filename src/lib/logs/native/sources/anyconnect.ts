/**
 * Cisco Secure Client (AnyConnect) terminating on a Cisco ASA — VPN syslog messages.
 * Card: docs/log-schemas/vpn-cisco-anyconnect.md
 *
 * Text-native: one numbered ASA message per event. The record is a FLAT object with
 * the syslog header keys (`timestamp`, `hostname`, `severity`, `message_id`) followed by
 * the message's own printed labels as keys (`Group`, `User`, `IP`, `Session Type`,
 * `Bytes xmt`, `user IP` …), values verbatim. `rawLine` is the syslog line rebuilt
 * from the same values (newer-ASA bracketed style `Group <X> User <Y> IP <Z>`).
 *
 * Kind = ASA message ID. Rendering of the platform's VPN events:
 *   auth failure / MFA denied → 113005 (AAA reject; 113015 when the author logged a local-DB reject)
 *   login                     → 722051 (pool address assigned — carries public + tunnel IP) when the
 *                               tunnel IP is known, else 113039 (AnyConnect parent session started);
 *                               an ASA-authored message ID (113039/722022/722051/722055/716001/113004) is kept.
 *   logout                    → 113019 (session disconnected: Duration, Bytes xmt/rcv, Reason)
 *   MFA challenge             → null: the ASA logs only the final RADIUS accept/reject, never the
 *                               Access-Challenge round trip.
 * Device config modelled: `logging timestamp`, `logging device-id hostname`, and
 * `no logging hide username` (so rejected usernames are printed, as in card §4.2 last line);
 * `*****` is printed only when the authored event carries no username at all.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { vpnFacts, company, asaTime, asaDuration, typedUser, osFamily, type VpnFacts } from "./remote-access-shared";

const HEADER = ["timestamp", "hostname", "severity", "message_id"];
const LABELS: Record<string, string[]> = {
  "113004": ["server", "user"],
  "113005": ["reason", "server", "user", "user IP"],
  "113015": ["reason", "user", "user IP"],
  "113039": ["Group", "User", "IP"],
  "113019": ["Group", "Username", "IP", "Session Type", "Duration", "Bytes xmt", "Bytes rcv", "Reason"],
  "734001": ["User", "Addr", "Connection", "DAP records"],
  "722051": ["Group", "User", "IP", "IPv4 Address", "IPv6 address"],
  "722055": ["Group", "User", "IP", "Client Type"],
  "722022": ["Group", "User", "IP", "Protocol", "Compression"],
  "722023": ["Group", "User", "IP", "Protocol", "Compression"],
  "722037": ["Group", "User", "IP", "Reason"],
  "716001": ["Group", "User", "IP"],
  "716002": ["Group", "User", "IP", "Reason"],
};
const SEVERITY: Record<string, number> = { "113019": 4, "722037": 5 };

const schema: SourceSchema = {
  sourceId: "anyconnect",
  category: "vpn",
  card: "vpn-cisco-anyconnect.md",
  product: "Cisco Secure Client (AnyConnect) on ASA",
  format: "syslog",
  vendorMatch: ["anyconnect", "cisco asa", "secure client"],
  telemetrySources: ["vpn"],
  kinds: Object.fromEntries(Object.entries(LABELS).map(([id, labels]): [string, KindSchema] =>
    [id, { required: [...HEADER, ...labels], optional: ["raw"] /* card representation carries the raw line too */ }])),
};

export function kindOf(record: Record<string, unknown>): string | null {
  const id = String(record.message_id ?? "");
  return LABELS[id] ? id : null;
}

/** Message text after `%ASA-<sev>-<id>: ` (bracketed variant). */
export function asaText(r: Record<string, unknown>): string {
  const g = (k: string) => String(r[k] ?? "");
  const gui = `Group <${g("Group")}> User <${g("User")}> IP <${g("IP")}>`;
  switch (g("message_id")) {
    case "113004": return `AAA user authentication Successful : server = ${g("server")} : user = ${g("user")}`;
    case "113005": return `AAA user authentication Rejected : reason = ${g("reason")} : server = ${g("server")} : user = ${g("user")} : user IP = ${g("user IP")}`;
    case "113015": return `AAA user authentication Rejected : reason = ${g("reason")} : local database : user = ${g("user")} : user IP = ${g("user IP")}`;
    case "113039": return `${gui} AnyConnect parent session started.`;
    case "113019": return `Group = ${g("Group")}, Username = ${g("Username")}, IP = ${g("IP")}, Session disconnected. Session Type: ${g("Session Type")}, Duration: ${g("Duration")}, Bytes xmt: ${g("Bytes xmt")}, Bytes rcv: ${g("Bytes rcv")}, Reason: ${g("Reason")}`;
    case "734001": return `DAP: User ${g("User")}, Addr ${g("Addr")}, Connection ${g("Connection")}: The following DAP records were selected for this connection: ${g("DAP records")}`;
    case "722051": return `${gui} IPv4 Address <${g("IPv4 Address")}> IPv6 address <${g("IPv6 address")}> assigned to session`;
    case "722055": return `${gui} Client Type: ${g("Client Type")}`;
    case "722022": return `${gui} ${g("Protocol")} SVC connection established ${g("Compression")} compression`;
    case "722023": return `${gui} ${g("Protocol")} SVC connection terminated ${g("Compression")} compression`;
    case "722037": return `${gui} SVC closing connection: ${g("Reason")}.`;
    case "716001": return `${gui} WebVPN session started.`;
    case "716002": return `${gui} WebVPN session terminated: ${g("Reason")}.`;
    default: return "";
  }
}
export function asaRawLine(r: Record<string, unknown>): string {
  const sev = Number(r.severity);
  return `<${160 + sev}>${r.timestamp} ${r.hostname} : %ASA-${sev}-${r.message_id}: ${asaText(r)}`;
}

const REJECT_REASONS = ["AAA failure", "Invalid password", "User was not found", "Account has been locked out", "Password has expired", "Password is expiring", "Password malformed", "Unspecified"];
function rejectReason(raw: string | undefined): string {
  if (!raw) return "AAA failure";
  const exact = REJECT_REASONS.find(r => r.toLowerCase() === raw.toLowerCase());
  if (exact) return exact;
  if (/lock/i.test(raw)) return "Account has been locked out";
  if (/not found|unknown user/i.test(raw)) return "User was not found";
  return "AAA failure"; // RADIUS/Duo reject, expired OTP token, generic "authentication failed"
}
const SESSION_TYPES = ["AnyConnect-Parent", "SSL", "DTLS", "IKEv2", "IPsec", "WebVPN", "LAN-to-LAN"];
function disconnectReason(raw: string | undefined): string {
  const s = (raw ?? "").toLowerCase();
  if (/idle/.test(s)) return "Idle Timeout";
  if (/preempt|simultaneous/.test(s)) return "Port Preempted";
  if (/admin/.test(s)) return "Administrator Reset";
  if (/max time/.test(s)) return "Max time exceeded";
  if (/lost/.test(s)) return "Lost Service";
  return "User Requested";
}
function clientType(f: VpnFacts): string {
  if (f.clientVersion) {
    const m = /(\d+\.\d+\.\d+(\.\d+)?)/.exec(f.clientVersion);
    const fam = osFamily(f.clientOs);
    const os = fam === "linux" ? "Linux" : fam === "mac" ? "Mac OS X" : "Windows";
    return `${/secure client/i.test(f.clientVersion) ? "Cisco Secure Client" : "Cisco AnyConnect VPN Agent"} for ${os} ${m ? m[1] : "5.1.4.74"}`;
  }
  const fam = osFamily(f.clientOs);
  if (fam === "linux") return "Cisco AnyConnect VPN Agent for Linux 4.10.07073";
  if (fam === "mac") return "Cisco AnyConnect VPN Agent for Mac OS X 5.1.4.74";
  return "Cisco AnyConnect VPN Agent for Windows 5.1.4.74";
}

function build(ev: TelemetryEvent, f: VpnFacts, ctx: NativeCtx): Record<string, unknown> | null {
  const co = company(ctx);
  const ms = Date.parse(ev.ts);
  const user = typedUser(f);
  const ip = f.publicIp ?? "0.0.0.0";
  const groupPolicy = f.groupPolicy ?? f.tunnelGroup ?? `GP-${co.short}-Users`;
  const tunnelGroup = f.tunnelGroup ?? `TG-${co.short}-AnyConnect`;
  const aaaServer = `10.${ctx.int(`${ctx.companyId}:aaa-net`, 10, 60)}.1.20`;
  const head = (id: string) => ({ timestamp: asaTime(ms), hostname: f.gatewayHost ?? "asa-vpn-01", severity: SEVERITY[id] ?? 6, message_id: id });

  switch (f.phase) {
    case "mfa_challenge":
      return null;
    case "auth_fail":
    case "mfa_denied": {
      const reason = f.phase === "mfa_denied" ? "AAA failure" : rejectReason(f.reason);
      if (f.asaMessageId === "113015") return { ...head("113015"), reason, user: user ?? "*****", "user IP": ip };
      return { ...head("113005"), reason, server: aaaServer, user: user ?? "*****", "user IP": ip };
    }
    case "logout": {
      const dur = f.durationSec ?? ctx.int(`${ev.id}:asa-dur`, 1800, 32400);
      const st = f.sessionType && SESSION_TYPES.includes(f.sessionType) ? f.sessionType : "AnyConnect-Parent";
      return {
        ...head("113019"), Group: tunnelGroup, Username: user ?? "*****", IP: ip, "Session Type": st, Duration: asaDuration(dur),
        "Bytes xmt": String(f.bytesToClient ?? ctx.int(`${ev.id}:asa-xmt`, 5_000_000, 80_000_000)),
        "Bytes rcv": String(f.bytesFromClient ?? ctx.int(`${ev.id}:asa-rcv`, 1_000_000, 20_000_000)),
        Reason: disconnectReason(f.reason),
      };
    }
    case "login": {
      if (!user) return null;
      const authored = f.asaMessageId;
      const id = authored && ["113039", "722022", "722051", "722055", "716001", "113004"].includes(authored)
        ? authored : f.tunnelIp ? "722051" : "113039";
      const gui = { Group: groupPolicy, User: user, IP: ip };
      switch (id) {
        case "113004": return { ...head(id), server: aaaServer, user };
        case "722051": return { ...head(id), ...gui, "IPv4 Address": f.tunnelIp ?? `10.250.${ctx.int(`${ev.id}:pool3`, 0, 15)}.${ctx.int(`${ev.id}:pool4`, 2, 250)}`, "IPv6 address": "::" };
        case "722055": return { ...head(id), ...gui, "Client Type": clientType(f) };
        case "722022": return { ...head(id), ...gui, Protocol: /dtls/i.test(f.sessionType ?? "") ? "UDP" : "TCP", Compression: "without" };
        default: return { ...head(id), ...gui };
      }
    }
  }
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = vpnFacts(ev);
  if (!f) return null;
  const record = build(ev, f, ctx);
  if (!record) return null;
  return { sourceId: "anyconnect", kind: String(record.message_id), format: "syslog", record, rawLine: asaRawLine(record), timeMs: Date.parse(ev.ts) };
}

const SESSION_KINDS = ["113039", "722051", "722022", "722055", "716001"];

const useCases: UseCase[] = [
  {
    id: "anyconnect.aaa_brute_force_from_ip",
    title: "AnyConnect AAA rejections burst from one source IP",
    sourceId: "anyconnect",
    kinds: ["113005", "113015"],
    severity: "high",
    mitre: ["T1110", "T1133"],
    description: "Ten or more 113005/113015 'AAA user authentication Rejected' messages from the same `user IP` inside 10 minutes. Usernames are often masked (*****) on the ASA, so pivot on the source IP and pull the usernames from the RADIUS/NPS or IdP logs. A following 113039 from that IP means a guess worked.",
    logic: "SPL: index=asa (message_id=113005 OR message_id=113015) | rex \"user IP = (?<src>\\S+)\" | bin _time span=10m | stats count values(reason) BY src _time | where count>=10",
    match: { field: "reason", op: "exists" },
    threshold: { groupBy: ["user IP"], count: 10, windowSec: 600 },
    falsePositives: ["A misconfigured RADIUS server rejecting everyone (all source IPs fail, not one)", "Authorised penetration test of the VPN portal"],
  },
  {
    id: "anyconnect.username_enumeration",
    title: "AnyConnect logins for non-existent users (username enumeration / spray)",
    sourceId: "anyconnect",
    kinds: ["113005", "113015"],
    severity: "medium",
    mitre: ["T1110.003", "T1589.001"],
    description: "Three or more rejections with reason 'User was not found' from one source IP in 10 minutes. Employees know their own username; a list of guessed names (admin, test, vpn, first.last) is a spray or enumeration run.",
    logic: "SPL: index=asa message_id IN (113005,113015) reason=\"User was not found\" | bin _time span=10m | stats count values(user) BY \"user IP\" _time | where count>=3",
    match: { field: "reason", op: "eq", value: "User was not found" },
    threshold: { groupBy: ["user IP"], count: 3, windowSec: 600 },
    falsePositives: ["New hire whose account is not yet provisioned in the AAA backend"],
  },
  {
    id: "anyconnect.account_locked_out",
    title: "VPN account locked out by repeated failures",
    sourceId: "anyconnect",
    kinds: ["113005", "113015"],
    severity: "medium",
    mitre: ["T1110"],
    description: "The AAA server answered 'Account has been locked out'. Lockout is the end of a guessing burst against a real account — find the burst (same user IP) and confirm with the user whether it was them.",
    logic: "SPL: index=asa message_id=113005 reason=\"Account has been locked out\" | table _time user \"user IP\" server",
    match: { field: "reason", op: "eq", value: "Account has been locked out" },
    falsePositives: ["User with a stale password cached on a phone or second laptop"],
  },
  {
    id: "anyconnect.concurrent_sessions_two_ips",
    title: "Same user starts AnyConnect sessions from two public IPs",
    sourceId: "anyconnect",
    kinds: SESSION_KINDS,
    severity: "high",
    mitre: ["T1078"],
    description: "Two session-start messages (113039 parent session / 722051 address assignment / 722022 tunnel) for the same `User` from different public `IP` within 4 hours. Enrich both IPs with geo/ASN — two countries in that window is impossible travel; a hosting-provider ASN is an attacker VPS.",
    logic: "SPL: index=asa message_id IN (113039,722051,722022) | stats dc(IP) AS ips values(IP) BY User span=4h | where ips>1 | iplocation IP",
    match: { field: "User", op: "exists" },
    threshold: { groupBy: ["User"], count: 2, windowSec: 4 * 3600, distinct: "IP" },
    falsePositives: ["Laptop moving between home Wi-Fi and a phone hotspot (same country, residential ASNs)"],
  },
  {
    id: "anyconnect.session_preempted",
    title: "AnyConnect session preempted by a second login",
    sourceId: "anyconnect",
    kinds: ["113019"],
    severity: "medium",
    mitre: ["T1078"],
    description: "113019 with Reason 'Port Preempted' — with vpn-simultaneous-logins 1 a NEW login for the same Username kicked the existing session off. If the user did not log in again from another device, someone else has their credentials.",
    logic: "SPL: index=asa message_id=113019 Reason=\"Port Preempted\" | table _time Username IP Duration",
    match: { field: "Reason", op: "eq", value: "Port Preempted" },
    falsePositives: ["User reconnecting from a second device they own"],
  },
  {
    id: "anyconnect.non_standard_client",
    title: "Non-standard AnyConnect client (Linux / legacy 4.x) on a Windows fleet",
    sourceId: "anyconnect",
    kinds: ["722055"],
    severity: "medium",
    mitre: ["T1133"],
    description: "722055 'Client Type' shows a Linux agent or an outdated 4.x client. The corporate image ships the current Windows client, so this is a personal or attacker-controlled machine using valid credentials.",
    logic: "SPL: index=asa message_id=722055 (\"Client Type\"=\"*Linux*\" OR \"Client Type\"=\"* 4.*\") | table _time User IP \"Client Type\"",
    match: { field: "Client Type", op: "regex", value: "Linux| 4\\.\\d" },
    falsePositives: ["Engineering staff with an approved Linux workstation"],
  },
  {
    id: "anyconnect.off_hours_parent_session",
    title: "AnyConnect parent session started between 00:00 and 05:59",
    sourceId: "anyconnect",
    kinds: ["113039", "722051"],
    severity: "low",
    mitre: ["T1078"],
    description: "A VPN session that starts in the middle of the night (device time). Weak alone, but a strong amplifier next to an unusual client type, a new IP, or a preceding burst of 113005 rejections.",
    logic: "SPL: index=asa message_id IN (113039,722051) | eval h=tonumber(strftime(_time,\"%H\")) | where h<6 | table _time User IP",
    match: { field: "timestamp", op: "regex", value: " 0[0-5]:\\d\\d:\\d\\d$" },
    falsePositives: ["On-call staff and night shifts (clinical staff in healthcare)"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
