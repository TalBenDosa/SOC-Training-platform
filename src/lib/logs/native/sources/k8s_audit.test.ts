import { describe, it, expect } from "vitest";
import { source, kindOf } from "./k8s_audit";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("k8s-audit.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "k8s_audit", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.stageTimestamp ?? rec.time ?? "2026-09-30T03:00:00Z")) });
  }
  return out;
}

describe("k8s_audit — card samples", () => {
  it("every Event + AKS-wrapper sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(6);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} ${JSON.stringify(log.record.verb ?? log.record.category)} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("k8s_audit — corpus conversion", () => {
  const mine = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch);

  it("≥95% of Kubernetes audit events convert and validate clean", () => {
    let nonNull = 0;
    for (const c of mine) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      nonNull++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} → ${JSON.stringify(v)}`).toEqual([]);
    }
    const ratio = mine.length ? nonNull / mine.length : 1;
    console.log(`[k8s_audit] Kubernetes audit: ${nonNull}/${mine.length} non-null (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThanOrEqual(0.95);
  });
});

describe("k8s_audit — evidence & determinism", () => {
  it("preserves verb, resource, username and source IP", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      for (const k of ["verb", "objectRef.resource", "objectRef.name", "user.username"]) {
        const val = c.ev.raw[`kubernetes.audit.${k}`] as string | undefined;
        if (typeof val === "string" && val) expect(blob, `${c.ev.id} ${k}`).toContain(val);
      }
      const ip = c.ev.src_ip ?? (c.ev.raw["kubernetes.audit.sourceIPs[0]"] as string | undefined);
      if (ip) expect(blob, `${c.ev.id} src ip`).toContain(ip);
    }
  });

  it("is deterministic", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    }
  });
});

describe("k8s_audit — use cases", () => {
  const storyLogs = corpusFor(source.schema.telemetrySources)
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  const attackLogs = [...cardLogs(), ...storyLogs];

  it("each use case fires on at least one attack/card log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[k8s_audit] ${uc.id}: ${hits.length} hit(s)`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });

  it("high/critical use cases stay quiet on benign noise (<2%)", () => {
    const noise = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story")
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);
    const fired = new Set<number>();
    for (const uc of source.useCases) {
      if (uc.severity !== "high" && uc.severity !== "critical") continue;
      for (const h of runUseCase(uc, noise)) for (const r of h.records) fired.add(r);
    }
    const rate = noise.length ? fired.size / noise.length : 0;
    console.log(`[k8s_audit] high/critical FP rate on ${noise.length} benign events: ${fired.size} (${(rate * 100).toFixed(1)}%)`);
    expect(rate).toBeLessThan(0.02);
  });
});
