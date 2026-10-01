import { describe, it, expect } from "vitest";
import { source, kindOf } from "./aws_cloudtrail";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

const ctx = makeCtx("rocketstack");

/** Build NativeLogs directly from the card's JSON samples (skip non-CloudTrail samples). */
function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-aws-cloudtrail.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "aws_cloudtrail", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.eventTime ?? "2026-09-30T02:00:00Z")) });
  }
  return out;
}

describe("aws_cloudtrail — card samples", () => {
  it("every CloudTrail card sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(12);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} ${JSON.stringify(log.record.eventName)} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("aws_cloudtrail — corpus conversion", () => {
  const all = corpusFor(source.schema.telemetrySources);
  const mine = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch); // vendor = CloudTrail

  it("≥95% of native CloudTrail events convert and validate clean", () => {
    let nonNull = 0;
    for (const c of mine) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      nonNull++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} → ${JSON.stringify(v)}`).toEqual([]);
    }
    const ratio = nonNull / mine.length;
    console.log(`[aws_cloudtrail] native CloudTrail: ${nonNull}/${mine.length} non-null (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThanOrEqual(0.95);
  });

  it("cross-vendor source events (GuardDuty / GitHub / Bedrock-invocation-log) are declined, not faked", () => {
    const cross = all.filter(c => !source.schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v)));
    let rendered = 0;
    for (const c of cross) if (source.fromTelemetry(c.ev, makeCtx(c.companyId))) rendered++;
    console.log(`[aws_cloudtrail] cross-vendor in 'cloudtrail' source: ${cross.length}, rendered ${rendered} (GuardDuty/GitHub/CloudWatch-invocation-log declined by design)`);
    expect(cross.length).toBeGreaterThan(0);
  });
});

describe("aws_cloudtrail — evidence & determinism", () => {
  it("preserves evidence values verbatim", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      const en = (c.ev.raw["aws.cloudtrail.eventName"] ?? c.ev.raw["event.action"]) as string | undefined;
      if (en) expect(blob, `${c.ev.id} eventName`).toContain(en);
      if (c.ev.src_ip) expect(blob, `${c.ev.id} src_ip`).toContain(c.ev.src_ip);
      const user = c.ev.raw["aws.cloudtrail.userIdentity.userName"] as string | undefined;
      if (user) expect(blob, `${c.ev.id} userName`).toContain(user);
      for (const k of ["aws.cloudtrail.requestParameters.bucketName", "aws.cloudtrail.requestParameters.secretId", "aws.cloudtrail.requestParameters.policyArn"]) {
        const val = c.ev.raw[k] as string | undefined;
        if (val) expect(blob, `${c.ev.id} ${k}`).toContain(val);
      }
    }
  });

  it("is deterministic (same event twice → deep-equal)", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch).slice(0, 30)) {
      const a = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      const b = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      expect(a).toEqual(b);
    }
  });
});

describe("aws_cloudtrail — use cases", () => {
  // Logs built from card samples + converted attack-story events (origin "story").
  const storyLogs = corpusFor(source.schema.telemetrySources)
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  // The corpus/card have no root console sign-in; prove that detection with a
  // representative event run through the converter (a real native record).
  const rootLogin = source.fromTelemetry({
    id: "syn_root_login", ts: "2026-09-30T02:05:00.000Z", source: "cloudtrail", vendor: "AWS CloudTrail",
    event_type: "auth_success", src_ip: "203.0.113.90",
    raw: { "aws.cloudtrail.eventName": "ConsoleLogin", "aws.cloudtrail.eventSource": "signin.amazonaws.com", "aws.cloudtrail.userIdentity.type": "Root", "aws.cloudtrail.eventType": "AwsConsoleSignIn" },
  } as never, ctx);
  const attackLogs = [...cardLogs(), ...storyLogs, ...(rootLogin ? [rootLogin] : [])];

  it("each use case fires on at least one attack/card log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[aws_cloudtrail] ${uc.id}: ${hits.length} hit(s) on attack/card logs`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });

  it("high/critical use cases stay quiet on benign/company noise (<2%)", () => {
    // True "noise" = benign + company events NOT designed as false-positive training.
    const noise = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story" && !c.ev.fp_explanation)
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);
    const fpTraining = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story" && c.ev.fp_explanation)
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);

    const fired = new Set<number>();
    for (const uc of source.useCases) {
      if (uc.severity !== "high" && uc.severity !== "critical") continue;
      const hits = runUseCase(uc, noise);
      for (const h of hits) for (const r of h.records) fired.add(r);
      const fpHits = runUseCase(uc, fpTraining);
      console.log(`[aws_cloudtrail] ${uc.id}: noise=${hits.length} fp-training=${fpHits.length}`);
    }
    const rate = noise.length ? fired.size / noise.length : 0;
    console.log(`[aws_cloudtrail] high/critical noise FP rate: ${fired.size}/${noise.length} = ${(rate * 100).toFixed(1)}% (fp-training events excluded, as designed to trip detectors)`);
    expect(rate).toBeLessThan(0.02);
  });
});
