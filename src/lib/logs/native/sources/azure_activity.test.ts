import { describe, it, expect } from "vitest";
import { source, kindOf } from "./azure_activity";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples } from "../testing/corpus";
import type { NativeLog } from "../types";

function cardLogs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const s of cardSamples("cloud-azure-activity.md")) {
    if (!s || typeof s !== "object") continue;
    const rec = s as Record<string, unknown>;
    const kind = kindOf(rec);
    if (!kind) continue;
    out.push({ sourceId: "azure_activity", kind, format: "json", record: rec, timeMs: Date.parse(String(rec.time ?? "2026-09-30T02:00:00Z")) });
  }
  return out;
}

describe("azure_activity — card samples", () => {
  it("every Activity-Log + Defender-alert sample validates with zero violations", () => {
    const logs = cardLogs();
    expect(logs.length).toBeGreaterThanOrEqual(5);
    for (const log of logs) {
      const v = validateNative(log, source.schema);
      expect(v, `${log.kind} → ${JSON.stringify(v)}`).toEqual([]);
    }
  });
});

describe("azure_activity — corpus conversion", () => {
  const mine = corpusFor(source.schema.telemetrySources, source.schema.vendorMatch);

  it("≥95% of Activity-Log / Defender events convert and validate clean", () => {
    let nonNull = 0;
    for (const c of mine) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      nonNull++;
      const v = validateNative(log, source.schema);
      expect(v, `${c.ev.id} → ${JSON.stringify(v)}`).toEqual([]);
    }
    const ratio = mine.length ? nonNull / mine.length : 1;
    console.log(`[azure_activity] Activity/Defender: ${nonNull}/${mine.length} non-null (${(ratio * 100).toFixed(1)}%)`);
    expect(ratio).toBeGreaterThanOrEqual(0.95);
  });

  it("Entra sign-in and Azure OpenAI diagnostics are declined (out of card scope)", () => {
    const cross = corpusFor(source.schema.telemetrySources).filter(c => !source.schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v)));
    let rendered = 0;
    for (const c of cross) if (source.fromTelemetry(c.ev, makeCtx(c.companyId))) rendered++;
    console.log(`[azure_activity] cross-vendor cloud_azure events: ${cross.length}, rendered ${rendered} (Entra + Azure OpenAI declined by design)`);
    expect(rendered).toBe(0);
  });
});

describe("azure_activity — evidence & determinism", () => {
  it("preserves operationName / alertType, caller and IP", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      const log = source.fromTelemetry(c.ev, makeCtx(c.companyId));
      if (!log) continue;
      const blob = JSON.stringify(log.record);
      const op = c.ev.raw["azure.activitylogs.operationName"] as string | undefined;
      if (op) expect(blob, `${c.ev.id} operationName`).toContain(op);
      const at = c.ev.raw["azure.alert.alertType"] as string | undefined;
      if (at) expect(blob, `${c.ev.id} alertType`).toContain(at);
      if (c.ev.src_ip) expect(blob, `${c.ev.id} src_ip`).toContain(c.ev.src_ip);
    }
  });

  it("is deterministic", () => {
    for (const c of corpusFor(source.schema.telemetrySources, source.schema.vendorMatch)) {
      expect(source.fromTelemetry(c.ev, makeCtx(c.companyId))).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    }
  });
});

describe("azure_activity — use cases", () => {
  const storyLogs = corpusFor(source.schema.telemetrySources)
    .filter(c => c.origin === "story")
    .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
    .filter((l): l is NativeLog => !!l);
  const attackLogs = [...cardLogs(), ...storyLogs];

  it("each use case fires on at least one attack/card log", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, attackLogs);
      console.log(`[azure_activity] ${uc.id}: ${hits.length} hit(s)`);
      expect(hits.length, `${uc.id} did not fire`).toBeGreaterThan(0);
    }
  });

  it("high/critical use cases stay quiet on benign/company noise (<2%)", () => {
    const noise = corpusFor(source.schema.telemetrySources)
      .filter(c => c.origin !== "story" && !c.ev.fp_explanation)
      .map(c => source.fromTelemetry(c.ev, makeCtx(c.companyId)))
      .filter((l): l is NativeLog => !!l);
    const fired = new Set<number>();
    for (const uc of source.useCases) {
      if (uc.severity !== "high" && uc.severity !== "critical") continue;
      for (const h of runUseCase(uc, noise)) for (const r of h.records) fired.add(r);
    }
    const rate = noise.length ? fired.size / noise.length : 0;
    console.log(`[azure_activity] high/critical FP rate on ${noise.length} benign events: ${fired.size} (${(rate * 100).toFixed(1)}%)`);
    expect(rate).toBeLessThan(0.02);
  });
});
