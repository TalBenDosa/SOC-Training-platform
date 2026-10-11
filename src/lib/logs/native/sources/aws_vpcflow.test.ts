import { describe, it, expect } from "vitest";
import { source, kindOf, rawLineOf } from "./aws_vpcflow";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const V2 = ["version", "account-id", "interface-id", "srcaddr", "dstaddr", "srcport", "dstport", "protocol", "packets", "bytes", "start", "end", "action", "log-status"];

function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-aws-vpc-flow.md")) {
    if (!s || typeof s !== "object" || Array.isArray(s)) continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "aws_vpcflow", kind, format: "csv", record: rec, timeMs: (Number(rec.start) || 0) * 1000 });
  }
  return out;
}

describe("aws_vpcflow — card samples", () => {
  it("every flow sample (v2, NODATA, custom v5, NAT v6) validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(5);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("aws_vpcflow — conversion", () => {
  it("declines every CloudTrail / firewall event (none are VPC flow records) — never fakes a flow", () => {
    let rendered = 0;
    for (const c of corpusFor(source.schema.telemetrySources)) {
      if (source.fromTelemetry(c.ev, makeCtx(c.companyId))) rendered++;
    }
    console.log(`[aws_vpcflow] CloudTrail/firewall events rendered as flow: ${rendered} (expected 0 — flows are an ENI network record, not API/firewall events)`);
    expect(rendered).toBe(0);
  });

  it("renders a genuine AWS flow 5-tuple deterministically with a round-trippable rawLine", () => {
    const ev = { id: "syn_flow", ts: "2026-09-30T02:00:00.000Z", source: "firewall", vendor: "AWS VPC Flow",
      event_type: "net_connection", src_ip: "10.0.3.47", dst_ip: "203.0.113.77", dst_port: 443, protocol: "tcp",
      cloud: { provider: "aws" }, network: { bytes_out: 48217940 },
      raw: { "interface-id": "eni-0a1b2c3d4e5f60718" } } as never;
    const a = source.fromTelemetry(ev, makeCtx("rocketstack"));
    const b = source.fromTelemetry(ev, makeCtx("rocketstack"));
    expect(a).toEqual(b);
    expect(a).not.toBeNull();
    const v = validateNative(a!, source.schema);
    expect(v, JSON.stringify(v)).toEqual([]);
    // rawLine matches the record in v2 field order, evidence preserved.
    expect(a!.rawLine).toBe(rawLineOf(a!.record, V2));
    expect(a!.rawLine).toContain("10.0.3.47");
    expect(a!.rawLine).toContain("203.0.113.77");
    expect(a!.rawLine).toContain("eni-0a1b2c3d4e5f60718");
  });
});

describe("aws_vpcflow — use cases", () => {
  const attackLogs = cardLogs();
  it("each use case fires on at least one card-sample log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[aws_vpcflow] ${uc.id}: ${hits.length} hit(s)`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });
});
