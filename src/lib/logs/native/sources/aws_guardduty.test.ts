import { describe, it, expect } from "vitest";
import { source, kindOf } from "./aws_guardduty";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const ctx = makeCtx("rocketstack");

function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-aws-guardduty.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "aws_guardduty", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.createdAt ?? rec.time ?? "2026-09-30T02:00:00Z")) });
  }
  return out;
}

describe("aws_guardduty — card samples", () => {
  it("every finding + EventBridge-envelope sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(6);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} ${JSON.stringify(log.record.type ?? log.record["detail-type"])} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("aws_guardduty — corpus conversion", () => {
  const mine = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch);

  it("≥95% of GuardDuty events convert and validate clean", () => {
    let nonNull = 0;
    for (const c of mine) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      nonNull++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} → ${JSON.stringify(v)}`).toEqual([]);
    }
    const ratio = mine.length ? nonNull / mine.length : 1;
    console.log(`[aws_guardduty] GuardDuty findings: ${nonNull}/${mine.length} non-null (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThanOrEqual(0.95);
  });

  it("non-GuardDuty source events are declined", () => {
    const cross = corpusFor(source.schema.telemetrySources).filter(c => !source.schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v)));
    let rendered = 0;
    for (const c of cross) if (source.fromTelemetry(c.ev, makeCtx(c.companyId))) rendered++;
    console.log(`[aws_guardduty] cross-vendor source events: ${cross.length}, rendered ${rendered} (non-finding events declined)`);
    expect(rendered).toBe(0);
  });
});

describe("aws_guardduty — evidence & determinism", () => {
  it("preserves finding type, severity and IP evidence", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      const type = (c.ev.raw["aws.guardduty.type"] ?? c.ev.raw["aws.guardduty.finding.type"]) as string | undefined;
      if (type) expect(blob, `${c.ev.id} type`).toContain(type);
      const ip = c.ev.src_ip ?? c.ev.dst_ip;
      if (ip) expect(blob, `${c.ev.id} ip`).toContain(ip);
      const key = c.ev.raw["aws.guardduty.resource.accessKeyDetails.accessKeyId"] as string | undefined;
      if (key) expect(blob, `${c.ev.id} accessKeyId`).toContain(key);
    }
  });

  it("is deterministic", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    }
  });
});

describe("aws_guardduty — use cases", () => {
  const storyLogs = corpusFor(source.schema.telemetrySources)
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  // No AttackSequence / severity-9 finding exists in corpus or card — prove that
  // critical detection with a representative finding run through the converter.
  const attackSeq = source.fromTelemetry({
    id: "syn_attackseq", ts: "2026-09-30T03:00:00.000Z", source: "cloudtrail", vendor: "AWS GuardDuty",
    event_type: "ueba_anomaly", src_ip: "203.0.113.77",
    raw: { "aws.guardduty.type": "AttackSequence:IAM/CompromisedCredentials", "aws.guardduty.severity": 9, "aws.guardduty.title": "Potential IAM compromise sequence" },
  } as never, ctx);
  const attackLogs = [...cardLogs(), ...storyLogs, ...(attackSeq ? [attackSeq] : [])];

  it("each use case fires on at least one attack/card log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[aws_guardduty] ${uc.id}: ${hits.length} hit(s)`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });

  it("no benign GuardDuty findings exist to false-positive on", () => {
    const noise = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story")
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);
    let fired = 0;
    for (const uc of source.useCases) if (uc.severity === "high" || uc.severity === "critical") fired += runUseCase(uc, noise).length;
    console.log(`[aws_guardduty] high/critical hits on ${noise.length} benign/company findings: ${fired}`);
    expect(fired).toBe(0);
  });
});
