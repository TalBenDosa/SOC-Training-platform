import { describe, it, expect } from "vitest";
import { source, kindOf } from "./securonix";
import { makeCtx } from "../ctx";
import { runUseCase } from "../engine";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { vendorRows, render, commonChecks, noLeak, expectEvidence } from "./_db-ueba.testkit";

/*
 * Inputs: every "Securonix" row (benign b_ueba_03 peer-baseline violation) plus fixtures. Fields: SNYPR
 * violation data (Securonix integration for Cortex XSOAR; ThreatQ Securonix connector search fields).
 */
const rows = vendorRows(source, /securonix/i);
const times = (l: NativeLog) => [Number(l.record.datetime)];
const mk = (id: string, raw: Record<string, unknown>) =>
  ({ id, ts: "2026-05-10T08:20:00.000Z", source: "ueba", vendor: "Securonix", event_type: "risk_score_change", severity: "low", raw }) as unknown as TelemetryEvent;

describe("securonix - every Securonix row", () => {
  it("renders on every surface, validates, follows the row's time, deterministic", () => {
    expect(rows.length).toBeGreaterThanOrEqual(1);
    commonChecks(source, rows, { timeFields: times });
    for (const r of rows) {
      const log = render(source, r)!;
      expect(kindOf(log.record)).toBe("violation");
      for (const v of Object.values(log.record)) expect(typeof v).toBe("string");
      expect(log.record.generationtime).toMatch(/^\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}$/);
      const raw = (r.c.ev.raw ?? {}) as Record<string, string>;
      expectEvidence(log, Object.entries(raw).filter(([k]) => k.startsWith("securonix.")).map(([, v]) => String(v)), r.c.ev.id);
      noLeak(log, r.c.ev);
    }
  });
  it("other UEBA products are not Securonix records", () => {
    expect(source.fromTelemetry({ ...mk("x", {}), vendor: "Exabeam" } as TelemetryEvent, makeCtx("nexacorp"))).toBeNull();
  });
});

describe("securonix - use cases", () => {
  const ctx = makeCtx("nexacorp");
  const fixtures: NativeLog[] = [
    source.fromTelemetry(mk("s1", { "securonix.violator": "Activityaccount", "securonix.entityid": "m.levi", "securonix.policyname": "Data Egress - Abnormal Upload Volume", "securonix.riskthreatname": "Abnormal amount of data egressed compared to peer", "securonix.riskscore": "92.0", "securonix.tenantname": "NexaCorp" }), ctx)!,
  ];
  const noise = rows.filter(r => !r.attack).map(r => render(source, r)!);
  it("every use case fires on rows / fixtures; high ones stay quiet on routine rows", () => {
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, [...noise, ...fixtures]).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[securonix] ${uc.id}: ${hits} hit(s), ${noiseHits}/${noise.length} on routine rows`);
      expect(hits, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
