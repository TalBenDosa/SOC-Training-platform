/**
 * Fortinet FortiGate SSL-VPN — FortiOS event log, type=event subtype=vpn.
 * Card: docs/log-schemas/vpn-fortigate-sslvpn.md
 *
 * Text-native: the record is a FLAT object with the FortiOS keys unchanged, quoted
 * values as strings and bare numbers as numbers (except `eventtime`, a 19-digit
 * nanosecond epoch kept as a string — card §2). `rawLine` is the key=value line.
 *
 * Kind = logid. Rendering of the platform's VPN events:
 *   auth failure / MFA denied → 0101039426 ssl-login-fail (tunneltype ssl-web, tunnelid 0)
 *   login                     → 0101039947 tunnel-up ssl-tunnel (tunnelip) when a tunnel IP is
 *                               known, else 0101039424 tunnel-up ssl-web "login successfully"
 *                               (an author's explicit ssl-web / 39424 is kept)
 *   logout                    → 0101039948 tunnel-down (duration, sentbyte, rcvdbyte)
 *   MFA challenge             → null: FortiOS logs only the final login result.
 * Era: FortiOS 7.0–7.4 (SSL-VPN tunnel mode removed in 7.6.x, card §2).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { vpnFacts, homeCountry, isPrivateIp, isoDate, hms, digits, typedUser, HIGH_RISK_FORTINET, type VpnFacts } from "./remote-access-shared";

const BASE = ["date", "time", "devname", "devid", "eventtime", "tz", "logid", "type", "subtype", "level", "vd", "logdesc", "action", "tunneltype", "tunnelid", "remip", "user", "group", "dst_host", "reason", "msg"];
const k = (required: string[], optional: string[]): KindSchema => ({ required: [...BASE, ...required], optional: [...optional, "raw" /* card representation carries the raw line too */] });

const schema: SourceSchema = {
  sourceId: "fortigate_sslvpn",
  category: "vpn",
  card: "vpn-fortigate-sslvpn.md",
  product: "Fortinet FortiGate SSL-VPN",
  format: "kv",
  vendorMatch: ["fortigate ssl-vpn", "fortigate sslvpn", "fortinet ssl"],
  telemetrySources: ["vpn"],
  kinds: {
    "0101039943": k([], []),                                   // SSL VPN new connection
    "0101039424": k([], ["srccountry"]),                       // SSL VPN tunnel up (web / login step)
    // srccountry on 39947 is UNVERIFIED (the card documents it on 39424 per the 7.6 reference); it is
    // emitted because a tunnel-mode login otherwise carries no geo, which the geo use cases need.
    "0101039947": k(["tunnelip"], ["fctuid", "srccountry"]),   // SSL VPN tunnel up (tunnel mode)
    "0101039948": k(["duration", "sentbyte", "rcvdbyte"], ["tunnelip"]), // SSL VPN tunnel down
    "0101039425": k([], ["duration", "sentbyte", "rcvdbyte"]), // SSL VPN tunnel down (web)
    "0101039426": k([], []),                                   // SSL VPN login fail
  },
};

export function kindOf(record: Record<string, unknown>): string | null {
  if (record.type !== "event" || record.subtype !== "vpn") return null;
  const id = String(record.logid ?? "");
  return schema.kinds[id] ? id : null;
}

/** Keys FortiOS prints bare (numbers, IPs, date/time); everything else is double-quoted. */
const BARE = new Set(["date", "time", "eventtime", "tunnelid", "remip", "tunnelip", "duration", "sentbyte", "rcvdbyte"]);
export function fgtRawLine(r: Record<string, unknown>): string {
  return Object.entries(r).filter(([key]) => key !== "raw").map(([key, v]) => BARE.has(key) ? `${key}=${v}` : `${key}="${String(v).replace(/"/g, '\\"')}"`).join(" ");
}

function build(ev: TelemetryEvent, f: VpnFacts, ctx: NativeCtx): Record<string, unknown> | null {
  const ms = Date.parse(ev.ts);
  const user = typedUser(f);
  const remip = f.publicIp ?? "0.0.0.0";
  const country = f.publicIp && isPrivateIp(f.publicIp) ? "Reserved" : (f.country ?? homeCountry(ctx)).fortinet;
  const head = (logid: string, level: string, logdesc: string) => ({
    date: isoDate(ms), time: hms(ms), devname: f.gatewayHost ?? "FGT-HQ-01", devid: `FG200FT9219${digits(ctx, `${ctx.companyId}:fgt-devid`, 5)}`,
    eventtime: `${ms}${String(ctx.int(`${ev.id}:fgt-ns`, 0, 999999)).padStart(6, "0")}`, tz: "+0000",
    logid, type: "event", subtype: "vpn", level, vd: "root", logdesc,
  });
  const sessionSeed = `${ctx.companyId}:fgt-tunnel:${user ?? ""}:${remip}`;
  const tunnelId = f.fgtTunnelId ?? ctx.int(sessionSeed, 1_900_000, 1_999_998);
  const group = f.fgtGroup ?? f.tunnelGroup ?? "VPN-Employees";

  switch (f.phase) {
    case "mfa_challenge":
      return null;
    case "auth_fail":
    case "mfa_denied": {
      const reason = /not found|unknown/i.test(f.reason ?? "") ? "sslvpn_login_unknown_user" : "sslvpn_login_permission_denied";
      return {
        ...head("0101039426", "alert", "SSL VPN login fail"), action: "ssl-login-fail", tunneltype: "ssl-web", tunnelid: 0, remip,
        user: user ?? "N/A", group: "N/A", dst_host: "N/A", reason, msg: "SSL user failed to logged in",
      };
    }
    case "login": {
      if (!user) return null;
      const web = f.fgtLogid === "0101039424" || f.fgtTunnelType === "ssl-web" || !f.tunnelIp;
      if (web) {
        return {
          ...head("0101039424", f.fgtLevel ?? "information", "SSL VPN tunnel up"), action: "tunnel-up", tunneltype: "ssl-web", tunnelid: tunnelId, remip,
          srccountry: country, user, group, dst_host: "N/A", reason: "login successfully", msg: "SSL tunnel established",
        };
      }
      return {
        ...head("0101039947", f.fgtLevel ?? "information", "SSL VPN tunnel up"), action: "tunnel-up", tunneltype: "ssl-tunnel", tunnelid: f.fgtTunnelId ?? tunnelId + 1, remip,
        tunnelip: f.tunnelIp, srccountry: country, user, group, dst_host: "N/A", reason: "tunnel established", msg: "SSL tunnel established",
        fctuid: ctx.hex(`${ctx.companyId}:fctuid:${f.clientHost ?? user}`, 32).toUpperCase(),
      };
    }
    case "logout": {
      const r: Record<string, unknown> = {
        ...head("0101039948", "information", "SSL VPN tunnel down"), action: "tunnel-down", tunneltype: "ssl-tunnel", tunnelid: f.fgtTunnelId ?? tunnelId + 1, remip,
      };
      if (f.tunnelIp) r.tunnelip = f.tunnelIp;
      Object.assign(r, {
        user: user ?? "N/A", group, dst_host: "N/A", reason: "N/A",
        duration: f.durationSec ?? ctx.int(`${ev.id}:fgt-dur`, 1800, 32400),
        sentbyte: f.bytesToClient ?? ctx.int(`${ev.id}:fgt-sent`, 5_000_000, 80_000_000),
        rcvdbyte: f.bytesFromClient ?? ctx.int(`${ev.id}:fgt-rcvd`, 1_000_000, 20_000_000),
        msg: "SSL tunnel shutdown",
      });
      return r;
    }
  }
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = vpnFacts(ev);
  if (!f) return null;
  const record = build(ev, f, ctx);
  if (!record) return null;
  return { sourceId: "fortigate_sslvpn", kind: String(record.logid), format: "kv", record, rawLine: fgtRawLine(record), timeMs: Date.parse(ev.ts) };
}

const UP = ["0101039424", "0101039947"];

const useCases: UseCase[] = [
  {
    id: "fortigate_sslvpn.password_spray",
    title: "SSL-VPN password spray (many usernames from one remote IP)",
    sourceId: "fortigate_sslvpn",
    kinds: ["0101039426"],
    severity: "high",
    mitre: ["T1110.003", "T1133"],
    description: "Five or more different `user` values fail SSL-VPN login (action=ssl-login-fail, logid 0101039426) from the same `remip` within 10 minutes. Spray tools rotate usernames with one common password; then look for action=tunnel-up from the same remip.",
    logic: "SPL: index=fortigate type=event subtype=vpn action=ssl-login-fail | bin _time span=10m | stats dc(user) AS users values(user) values(reason) BY remip _time | where users>=5",
    match: { field: "action", op: "eq", value: "ssl-login-fail" },
    threshold: { groupBy: ["remip"], count: 5, windowSec: 600, distinct: "user" },
    falsePositives: ["Shared NAT egress of a partner site with several users mistyping", "Authorised external pentest"],
  },
  {
    id: "fortigate_sslvpn.brute_force_single_user",
    title: "SSL-VPN brute force against one account",
    sourceId: "fortigate_sslvpn",
    kinds: ["0101039426"],
    severity: "medium",
    mitre: ["T1110.001"],
    description: "Ten or more ssl-login-fail events for the same `user` in 10 minutes — a password-guessing run against a single account (or FortiClient retrying a stale saved password).",
    logic: "SPL: index=fortigate subtype=vpn action=ssl-login-fail user!=\"N/A\" | bin _time span=10m | stats count values(remip) BY user _time | where count>=10",
    match: { all: [{ field: "action", op: "eq", value: "ssl-login-fail" }, { field: "user", op: "neq", value: "N/A" }] },
    threshold: { groupBy: ["user"], count: 10, windowSec: 600 },
    falsePositives: ["Password changed while FortiClient keeps a saved credential"],
  },
  {
    id: "fortigate_sslvpn.default_account_probe",
    title: "SSL-VPN login attempt with a default / generic account name",
    sourceId: "fortigate_sslvpn",
    kinds: ["0101039426"],
    severity: "medium",
    mitre: ["T1110.001", "T1078.001"],
    description: "Failed SSL-VPN login for admin / administrator / vpn / test / guest / root / support. No employee logs in as these; internet scanners try them against every exposed FortiGate portal.",
    logic: "SPL: index=fortigate subtype=vpn action=ssl-login-fail user IN (admin, administrator, vpn, test, guest, root, support, fortinet) | stats count BY remip user",
    match: { all: [{ field: "action", op: "eq", value: "ssl-login-fail" }, { field: "user", op: "in", value: ["admin", "administrator", "vpn", "test", "guest", "root", "support", "fortinet"] }] },
    falsePositives: ["Internal admin mistakenly using the appliance admin name on the user portal"],
  },
  {
    id: "fortigate_sslvpn.login_high_risk_country",
    title: "SSL-VPN tunnel up from a high-risk country",
    sourceId: "fortigate_sslvpn",
    kinds: UP,
    severity: "high",
    mitre: ["T1078", "T1133"],
    description: "action=tunnel-up with `srccountry` (FortiGate GeoIP of remip) in a country where the company has no staff. Valid credentials used from there = stolen credentials until proven otherwise; pivot on `tunnelip` into FortiGate traffic logs (srcip, srcintf=ssl.root) to see what the session touched.",
    logic: "SPL: index=fortigate subtype=vpn action=tunnel-up srccountry IN (\"Russian Federation\", Belarus, China, \"Korea, Democratic People's Republic of\", \"Iran, Islamic Republic of\", Nigeria) | table _time user remip srccountry tunnelip",
    match: { all: [{ field: "action", op: "eq", value: "tunnel-up" }, { field: "srccountry", op: "in", value: HIGH_RISK_FORTINET }] },
    falsePositives: ["Approved travel", "User on a commercial VPN exiting in that country"],
  },
  {
    id: "fortigate_sslvpn.concurrent_tunnels_two_ips",
    title: "Same user has SSL-VPN tunnels from two remote IPs",
    sourceId: "fortigate_sslvpn",
    kinds: UP,
    severity: "high",
    mitre: ["T1078"],
    description: "Two tunnel-up events for the same `user` from different `remip` within 4 hours (and no tunnel-down of the first tunnelid in between). Different srccountry values make it impossible travel; one of the sessions is not the user.",
    logic: "SPL: index=fortigate subtype=vpn action=tunnel-up | stats dc(remip) AS ips values(remip) values(srccountry) values(tunnelid) BY user span=4h | where ips>1",
    match: { all: [{ field: "action", op: "eq", value: "tunnel-up" }, { field: "user", op: "neq", value: "N/A" }] },
    threshold: { groupBy: ["user"], count: 2, windowSec: 4 * 3600, distinct: "remip" },
    falsePositives: ["Laptop switching between home broadband and a phone hotspot"],
  },
  {
    id: "fortigate_sslvpn.large_tunnel_transfer",
    title: "SSL-VPN session moved more than 1 GB from the client",
    sourceId: "fortigate_sslvpn",
    kinds: ["0101039948", "0101039425"],
    severity: "medium",
    mitre: ["T1048", "T1030"],
    description: "A tunnel-down log whose `rcvdbyte` exceeds 1 GB — the FortiGate received over a gigabyte from the client during the session (uploads into the network) . Check the session's tunnelip in traffic logs for what was transferred, and whether the session itself was suspicious (country, hour).",
    logic: "SPL: index=fortigate subtype=vpn action=tunnel-down rcvdbyte>1000000000 | eval GB=round(rcvdbyte/1024/1024/1024,2) | table _time user remip tunnelip duration GB",
    match: { all: [{ field: "action", op: "eq", value: "tunnel-down" }, { field: "rcvdbyte", op: "gt", value: 1_000_000_000 }] },
    falsePositives: ["Developers pushing large builds or VM images over the VPN"],
  },
  {
    id: "fortigate_sslvpn.off_hours_tunnel",
    title: "SSL-VPN tunnel established between 00:00 and 05:59",
    sourceId: "fortigate_sslvpn",
    kinds: UP,
    severity: "low",
    mitre: ["T1078"],
    description: "A tunnel-up in the middle of the night (device time). Weak alone; strong next to a new country, a contractor group, or a preceding ssl-login-fail burst from the same remip.",
    logic: "SPL: index=fortigate subtype=vpn action=tunnel-up | eval h=tonumber(substr(time,1,2)) | where h<6 | table date time user remip srccountry",
    match: { all: [{ field: "action", op: "eq", value: "tunnel-up" }, { field: "time", op: "regex", value: "^0[0-5]:" }] },
    falsePositives: ["On-call engineers, staff in other time zones"],
  },
  {
    id: "fortigate_sslvpn.success_after_failures_same_ip",
    title: "SSL-VPN success from a remote IP that just failed",
    sourceId: "fortigate_sslvpn",
    kinds: ["0101039426", ...UP],
    severity: "medium",
    mitre: ["T1110", "T1078"],
    description: "Within 30 minutes the same `remip` produced both ssl-login-fail and tunnel-up. After a spray this is the moment a guessed password worked; for a single user it is usually a typo.",
    logic: "SPL: index=fortigate subtype=vpn action IN (ssl-login-fail, tunnel-up) | stats dc(action) AS outcomes values(user) count BY remip span=30m | where outcomes=2",
    match: { field: "action", op: "in", value: ["ssl-login-fail", "tunnel-up"] },
    threshold: { groupBy: ["remip"], count: 2, windowSec: 1800, distinct: "action" },
    falsePositives: ["User mistyped the password once"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
