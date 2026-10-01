/**
 * AWS VPC Flow Logs — native source module (text-native).
 *
 * Card: docs/log-schemas/cloud-aws-vpc-flow.md. A record is a single space-
 * separated line; we expose a flat JSON object keyed by AWS's own hyphenated field
 * names (missing value = `-` on the wire, `null` in JSON) and the rebuilt `rawLine`.
 * No ECS (`source.ip`/`network.bytes`) renaming, no Wazuh envelope.
 *
 * The platform has no authored VPC-flow telemetry today: flow logs are an ENI-level
 * network record that neither the CloudTrail (API-call) nor the firewall-vendor
 * events are. `fromTelemetry` therefore renders only a genuine AWS VPC flow 5-tuple
 * and returns null otherwise (per the brief — never fake a flow from an API event).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { KindSchema, NativeCtx, NativeLog, NativeSource, SourceSchema, UseCase } from "../types";
import { rs } from "./cloud-shared";

/** Default v2 field order (14 fields). */
const V2 = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"];
const EXTRA = [
  "vpc-id", "subnet-id", "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
  "region", "az-id", "sublocation-type", "sublocation-id", "pkt-src-aws-service", "pkt-dst-aws-service",
  "flow-direction", "traffic-path", "ecs-cluster-arn", "ecs-cluster-name", "ecs-task-arn",
  "reject-reason", "resource-id", "encryption-status", "interface-type",
];

const kinds: Record<string, KindSchema> = {
  flow: { required: V2, optional: EXTRA, openPrefixes: [] },
  flow_custom: { required: ["interface-id"], optional: [...V2, ...EXTRA], openPrefixes: [] },
};

const schema: SourceSchema = {
  sourceId: "aws_vpcflow",
  category: "network_flow",
  card: "cloud-aws-vpc-flow.md",
  product: "AWS VPC Flow Logs",
  format: "csv",
  vendorMatch: ["vpc flow", "vpcflow", "vpc-flow"],
  telemetrySources: ["cloudtrail", "firewall"],
  kinds,
};

export function kindOf(record: Record<string, unknown>): string | null {
  const has = (k: string) => record[k] !== undefined;
  if (has("version") && has("action") && has("log-status")) return "flow";
  if (has("interface-id") && (has("srcaddr") || has("pkt-srcaddr"))) return "flow_custom";
  return null;
}

/** Rebuild the wire line from a flat record and a field order (`-` for null/absent). */
export function rawLineOf(record: Record<string, unknown>, order: string[]): string {
  return order.map(f => { const v = record[f]; return v === null || v === undefined ? "-" : String(v); }).join(" ");
}

// ── conversion ────────────────────────────────────────────────────────────────

const PROTO: Record<string, number> = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58 };

/** Only render a genuine AWS VPC flow 5-tuple; decline everything else (never fake one). */
function fromTelemetry(ev: TelemetryEvent, ctx: NativeCtx): NativeLog | null {
  const raw = ev.raw ?? {};
  // A VPC flow must have an ENI/flow marker in the source event — none of the
  // platform's current CloudTrail / firewall events carry one.
  const eni = rs(raw, "aws.vpcflow.interface-id", "interface-id", "aws.vpcflow.interface_id");
  const isAwsFlow = !!eni || (ev.cloud?.provider === "aws" && !!ev.src_ip && !!ev.dst_ip && ev.dst_port !== undefined && !rs(raw, "aws.cloudtrail.eventName"));
  if (!isAwsFlow || !ev.src_ip || !ev.dst_ip) return null;

  const startSec = Math.floor(Date.parse(ev.ts) / 1000);
  const proto = PROTO[(ev.protocol ?? "tcp").toLowerCase()] ?? 6;
  const record: Record<string, unknown> = {
    version: "2",
    "account-id": ctx.tenant.awsAccountId,
    "interface-id": eni ?? `eni-${ctx.hex(ev.id + ":eni", 17)}`,
    srcaddr: ev.src_ip,
    dstaddr: ev.dst_ip,
    srcport: ev.src_port ?? ctx.int(ev.id + ":sport", 32768, 60999),
    dstport: ev.dst_port ?? 443,
    protocol: proto,
    packets: Math.max(1, Math.round((ev.network?.bytes_out ?? 1500) / 1200)),
    bytes: ev.network?.bytes_out ?? 1500,
    start: startSec,
    end: startSec + 60,
    action: "ACCEPT",
    "log-status": "OK",
  };
  return { sourceId: "aws_vpcflow", kind: "flow", format: "csv", record, rawLine: rawLineOf(record, V2), timeMs: Date.parse(ev.ts) };
}

// ── use cases ─────────────────────────────────────────────────────────────────

const PRIVATE = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "169.254.0.0/16"];
const MINING_PORTS = [3333, 4444, 5555, 7777, 8333, 14444, 45700];

const useCases: UseCase[] = [
  {
    id: "aws_vpcflow.inbound_admin_bruteforce",
    title: "Rejected inbound SSH/RDP (brute force / scan)",
    sourceId: "aws_vpcflow", severity: "medium", mitre: ["T1110", "T1046"],
    description: "REJECTed inbound connections to 22 (SSH) or 3389 (RDP) — attempts the security group blocked, i.e. internet-facing brute force or port scanning against an instance.",
    logic: "Athena: action='REJECT' AND dstport IN (22,3389)",
    match: { all: [{ field: "action", op: "eq", value: "REJECT" }, { field: "dstport", op: "in", value: [22, 3389] }] },
    falsePositives: ["Background internet scan noise hitting a closed port (expected; only alert on volume or on an ACCEPT that follows)."],
  },
  {
    id: "aws_vpcflow.cryptomining_pool",
    title: "Outbound connection to a mining-pool port",
    sourceId: "aws_vpcflow", severity: "high", mitre: ["T1496"],
    description: "An ACCEPTed outbound flow to a common Stratum / mining-pool port (3333/4444/5555/7777…) — the network footprint of crypto-mining on a compromised instance.",
    logic: "Athena: action='ACCEPT' AND dstport IN (3333,4444,5555,7777,14444)",
    match: { all: [{ field: "action", op: "eq", value: "ACCEPT" }, { field: "dstport", op: "in", value: MINING_PORTS }] },
    falsePositives: ["A legitimate service that happens to use one of these high ports (rare; confirm the destination)."],
  },
  {
    id: "aws_vpcflow.large_egress_external",
    title: "Large data egress to an external IP",
    sourceId: "aws_vpcflow", severity: "high", mitre: ["T1048", "T1567"],
    description: "A single ACCEPTed outbound flow moving a large byte volume (≥10 MB) to a non-RFC1918 destination — the network side of bulk data exfiltration.",
    logic: "Athena: action='ACCEPT' AND bytes>=10000000 AND NOT cidr(dstaddr, RFC1918)",
    match: { all: [
      { field: "action", op: "eq", value: "ACCEPT" },
      { field: "bytes", op: "gte", value: 10_000_000 },
      { field: "dstaddr", op: "notCidr", value: PRIVATE },
    ] },
    falsePositives: ["Legitimate bulk transfers to a partner / CDN (correlate with the destination and the owning workload)."],
  },
  {
    id: "aws_vpcflow.egress_to_internet",
    title: "Egress to the internet via the internet gateway",
    sourceId: "aws_vpcflow", severity: "low", mitre: ["T1071"],
    kinds: ["flow"],
    description: "An egress flow whose traffic-path is 8 (internet gateway) to a public destination — baseline context for whether an instance talks directly to the internet; a pivot when combined with volume or a bad-reputation destination.",
    logic: "Athena: flow-direction='egress' AND traffic-path IN (2,8)",
    match: { all: [{ field: "flow-direction", op: "eq", value: "egress" }, { field: "traffic-path", op: "in", value: [2, 8] }] },
    falsePositives: ["Normal outbound internet traffic — low on its own; use as an enrichment dimension."],
  },
];

export const source: NativeSource = { schema, fromTelemetry, useCases };
