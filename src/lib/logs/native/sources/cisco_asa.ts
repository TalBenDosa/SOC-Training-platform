/**
 * Cisco ASA (and FTD's LINA engine) core connection messages — 106023 (ACL deny),
 * 302013 (built TCP), 302014 (teardown TCP) — rendered per docs/log-schemas/fw-cisco.md
 * §ASA: `timestamp`, `device_id`, `Level`, `Message_number` and the free-text
 * `Message_text` kept VERBATIM in Cisco's message pattern. ASA defines no key names
 * for the body, so none are invented (no src_ip / dst_port keys).
 *
 * What an ASA cannot show truthfully → null:
 *  - IPS / URL-category / file verdicts that BLOCKED a session (a plain ASA has no
 *    such engines; on an ASA-only edge that session would have been allowed),
 *  - allowed UDP / ICMP sessions (302015/302016/302020/302021 are not on the card),
 *  - passive-sensor (Zeek) records and firewall admin events.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { asaTime, egressIp, extractFacts, hmsDuration, isSnat, natPort, rawGet, sessionNumber, type FwFacts } from "./firewall-shared";

const REQ = ["timestamp", "device_id", "Level", "Message_number", "Message_text"];
export const schema: SourceSchema = {
  sourceId: "cisco_asa",
  category: "firewall",
  card: "fw-cisco.md",
  product: "Cisco ASA",
  format: "syslog",
  vendorMatch: ["cisco asa", "adaptive security appliance"],
  telemetrySources: ["firewall", "ids"],
  kinds: { "106023": { required: REQ, optional: [] }, "302013": { required: REQ, optional: [] }, "302014": { required: REQ, optional: [] } },
};

export function kindOf(record: Record<string, unknown>): string | null {
  const m = String(record.Message_number ?? "");
  return schema.kinds[m] && "Message_text" in record ? m : null;
}

const LEVEL: Record<string, string> = { "106023": "4", "302013": "6", "302014": "6" };
/** nameif of each side: [initiator interface, responder interface]. */
function ifaces(f: FwFacts): [string, string] {
  if (f.dir === "outbound") return ["inside", "outside"];
  if (f.dir === "internal") return ["inside", "servers"];
  return ["outside", [80, 443, 8080, 8443, 25].includes(f.dport) ? "dmz" : "inside"];
}
function teardownReason(f: FwFacts): string {
  const r = rawGet((f.ev.raw ?? {}) as Record<string, unknown>, "pan.session_end_reason");
  if (r === "tcp-rst-from-client") return f.dir === "inbound" ? "TCP Reset-O" : "TCP Reset-I";
  if (r === "tcp-rst-from-server") return f.dir === "inbound" ? "TCP Reset-I" : "TCP Reset-O";
  if (r === "aged-out") return "Conn-timeout";
  return "TCP FINs";
}

function render(f: FwFacts, ctx: NativeCtx): { num: string; text: string } | null {
  const [ii, oi] = ifaces(f);
  if (f.blocked) {
    if (f.cls !== "traffic") return null; // content verdict (IPS/URL/file) — not an ASA capability
    if (f.proto === "icmp") return null;
    const acl = `${ii}_access_in`;
    const h = `0x${ctx.hex(`${ctx.companyId}:asa:acl:${f.rule}`, 8)}`;
    return { num: "106023", text: `Deny ${f.proto} src ${ii}:${f.src}/${f.sport} dst ${oi}:${f.dst}/${f.dport} by access-group "${acl}" [${h}, 0x0]` };
  }
  if (f.proto !== "tcp") return null;
  const id = sessionNumber(f, ctx, 100000000, 999999999);
  // Mapped (post-NAT) address of the inside host for outbound PAT; inbound shows real = mapped (no DNAT modelled).
  const srcMapped = isSnat(f) ? `${egressIp(ctx)}/${natPort(f, ctx)}` : `${f.src}/${f.sport}`;
  if (f.startOnly) {
    if (f.dir === "inbound") return { num: "302013", text: `Built inbound TCP connection ${id} for ${ii}:${f.src}/${f.sport} (${f.src}/${f.sport}) to ${oi}:${f.dst}/${f.dport} (${f.dst}/${f.dport})` };
    return { num: "302013", text: `Built outbound TCP connection ${id} for ${oi}:${f.dst}/${f.dport} (${f.dst}/${f.dport}) to ${ii}:${f.src}/${f.sport} (${srcMapped})` };
  }
  const total = f.bytesOut + f.bytesIn; // 302014 reports the sum of both directions
  const dur = hmsDuration(f.elapsed);
  const from = f.dir === "inbound" ? "outside" : "inside";
  if (f.dir === "inbound") return { num: "302014", text: `Teardown TCP connection ${id} for ${ii}:${f.src}/${f.sport} to ${oi}:${f.dst}/${f.dport} duration ${dur} bytes ${total} ${teardownReason(f)} from ${from}` };
  return { num: "302014", text: `Teardown TCP connection ${id} for ${oi}:${f.dst}/${f.dport} to ${ii}:${f.src}/${f.sport} duration ${dur} bytes ${total} ${teardownReason(f)} from ${from}` };
}

export function toRawLine(r: Record<string, unknown>): string {
  return `${r.timestamp} ${r.device_id} : %ASA-${r.Level}-${r.Message_number}: ${r.Message_text}`;
}

function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const f = extractFacts(ev, ctx, schema.vendorMatch);
  if (!f || f.cls === "admin") return null;
  if (f.cls === "threat" && f.blocked) return null;
  const m = render(f, ctx);
  if (!m) return null;
  const record = {
    timestamp: asaTime(f.timeMs), device_id: f.host?.role === "device" ? f.host.name : "ASA-EDGE-01",
    Level: LEVEL[m.num], Message_number: m.num, Message_text: m.text,
  };
  return { sourceId: "cisco_asa", kind: m.num, format: "syslog", record, rawLine: toRawLine(record), timeMs: f.timeMs };
}

// ── use cases (regex over the verbatim Message_text, as on a real ASA) ───────
const ADMIN_PORTS = "(22|23|445|3389|5985|5986)";
const C2_PORTS = "(4444|5555|1337|6667|9001)";
export const useCases: UseCase[] = [
  {
    id: "cisco_asa.acl-deny-burst", title: "Burst of ACL denies (scan / sweep)", sourceId: "cisco_asa", kinds: ["106023"],
    severity: "medium", mitre: ["T1046", "T1595.001"],
    description: "Ten or more distinct 106023 \"Deny … by access-group\" messages from one device within two minutes. Read the src socket in the text: the same source hitting many dst ports/addresses is a scan. (ASA bodies are free text, so the SIEM must extract the source with a regex.)",
    logic: "SPL: sourcetype=cisco:asa message_id=106023 | rex \"src \\S+:(?<src>[\\d.]+)/\\d+ dst \\S+:(?<dst>[\\d.]+)/(?<dport>\\d+)\" | bin _time span=2m | stats dc(dport) as ports by src _time | where ports>=10",
    match: { field: "Message_text", op: "startsWith", value: "Deny " },
    threshold: { groupBy: ["device_id"], count: 10, windowSec: 120, distinct: "Message_text" },
    falsePositives: ["Internal vulnerability scanners", "Broken monitoring hitting closed ports"],
  },
  {
    id: "cisco_asa.inbound-deny-admin-port", title: "Internet source denied on a remote-admin port", sourceId: "cisco_asa", kinds: ["106023"],
    severity: "medium", mitre: ["T1133", "T1110"],
    description: "106023 from the outside interface to SSH/Telnet/SMB/RDP/WinRM: someone is probing for exposed management services. Expected background noise on any edge, but a spike or a later 302013 from the same source matters.",
    logic: `SPL: sourcetype=cisco:asa message_id=106023 | regex Message_text="^Deny tcp src outside:\\S+ dst \\S+:[\\d.]+/${ADMIN_PORTS} "`,
    match: { field: "Message_text", op: "regex", value: `^Deny tcp src outside:\\S+ dst \\S+:[\\d.]+/${ADMIN_PORTS} ` },
    falsePositives: ["Internet-wide research scanners (Shodan, Censys)"],
  },
  {
    id: "cisco_asa.inbound-admin-service-allowed", title: "Inbound connection to a remote-admin service built", sourceId: "cisco_asa", kinds: ["302013", "302014"],
    severity: "high", mitre: ["T1133", "T1021.001", "T1021.004"],
    description: "A 302013/302014 for a connection initiated from outside to port 22/23/445/3389/5985: a remote-admin service is reachable from the internet and was used. Pair build and teardown by the connection id.",
    logic: `SPL: sourcetype=cisco:asa message_id IN (302013, 302014) | regex Message_text="(Built inbound TCP connection \\d+ for outside:\\S+ \\(\\S+\\) to \\S+:[\\d.]+/${ADMIN_PORTS} |Teardown TCP connection \\d+ for outside:\\S+ to \\S+:[\\d.]+/${ADMIN_PORTS} )"`,
    match: { field: "Message_text", op: "regex", value: `(^Built inbound TCP connection \\d+ for outside:\\S+ \\(\\S+\\) to \\S+:[\\d.]+/${ADMIN_PORTS} |^Teardown TCP connection \\d+ for outside:\\S+ to \\S+:[\\d.]+/${ADMIN_PORTS} )` },
    falsePositives: ["Vendor jump hosts with source-restricted ACLs"],
  },
  {
    id: "cisco_asa.outbound-suspicious-port", title: "Outbound connection to a typical C2 / reverse-shell port", sourceId: "cisco_asa", kinds: ["302013", "302014"],
    severity: "high", mitre: ["T1571"],
    description: "An inside host built a TCP connection to an outside server on a port commonly used by reverse shells and C2 implants (4444, 5555, 1337 …). Legitimate business traffic rarely uses these.",
    logic: `SPL: sourcetype=cisco:asa message_id IN (302013, 302014) | regex Message_text="for outside:[\\d.]+/${C2_PORTS} (\\(\\S+\\) )?to inside:"`,
    match: { field: "Message_text", op: "regex", value: `for outside:[\\d.]+/${C2_PORTS} (\\(\\S+\\) )?to inside:` },
    falsePositives: ["Developer tools or games using these ports"],
  },
  {
    id: "cisco_asa.large-transfer", title: "Teardown of an outbound connection that moved ≥ 100 MB", sourceId: "cisco_asa", kinds: ["302014"],
    severity: "high", mitre: ["T1048", "T1567.002"],
    description: "302014 reports the TOTAL bytes of both directions (no upload/download split — confirm direction with FTD 430003 or NetFlow). An outbound connection closing with ≥100,000,000 bytes is worth checking against the destination's reputation and the duration.",
    logic: "SPL: sourcetype=cisco:asa message_id=302014 | rex \"for outside:(?<dst>[\\d.]+)/(?<dport>\\d+) to inside:(?<src>[\\d.]+)/\\d+ duration (?<dur>\\S+) bytes (?<bytes>\\d+)\" | where bytes>=100000000",
    match: { field: "Message_text", op: "regex", value: "for outside:\\S+ to inside:\\S+ duration \\S+ bytes \\d{9,} " },
    falsePositives: ["Backups and large software downloads (download volume is included in the total)"],
  },
  {
    id: "cisco_asa.long-lived-session", title: "Outbound TCP session open for more than an hour", sourceId: "cisco_asa", kinds: ["302014"],
    severity: "medium", mitre: ["T1071"],
    description: "A teardown with duration ≥ 1:00:00 on an outbound connection: interactive tunnels, reverse shells and C2 channels keep one session open for hours.",
    logic: "SPL: sourcetype=cisco:asa message_id=302014 | regex Message_text=\"to inside:\\S+ duration [1-9]\\d*:\\d\\d:\\d\\d \"",
    match: { field: "Message_text", op: "regex", value: "to inside:\\S+ duration [1-9]\\d*:\\d\\d:\\d\\d " },
    falsePositives: ["VPN / VDI sessions, streaming, long downloads"],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
