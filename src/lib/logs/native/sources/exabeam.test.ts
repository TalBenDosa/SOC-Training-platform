import { describe, it, expect } from "vitest";
import { source, kindOf, kvLine } from "./exabeam";
import { makeCtx } from "../ctx";
import { runUseCase } from "../engine";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import type { NativeLog } from "../types";
import type { TelemetryEvent } from "@/lib/sim/types";
import { vendorRows, render, commonChecks, noLeak, expectEvidence } from "./_db-ueba.testkit";

/*
 * Inputs: every "Exabeam" row (benign b_ueba_02 session update, b_ueba_05 reprocessing job; the team
 * timeline deals the job row too) plus fixtures. Keys: Exabeam AA Administration Guide i56, "Syslog
 * Notifications Key-Value Pair Definitions".
 */
const rows = vendorRows(source, /exabeam/i);
/** No field of an Exabeam notification is the row's own instant (start_time is the session's login, before it). */
const noInstant = () => [] as number[];
const mk = (id: string, raw: Record<string, unknown>, extra: Partial<TelemetryEvent> = {}) =>
  ({ id, ts: "2026-05-10T08:10:00.000Z", source: "ueba", vendor: "Exabeam", event_type: "risk_score_change", severity: "low", raw, ...extra }) as unknown as TelemetryEvent;

describe("exabeam - every Exabeam row", () => {
  it("renders on every surface, validates, follows the row's time, deterministic", () => {
    expect(rows.length).toBeGreaterThanOrEqual(2);
    commonChecks(source, rows, { timeFields: noInstant });
    for (const r of rows) {
      const log = render(source, r)!;
      const rec = log.record as Record<string, string>;
      expect(kindOf(rec)).toBe(log.kind);
      for (const v of Object.values(rec)) expect(typeof v).toBe("string");
      expect(log.rawLine).toMatch(/^[a-z_]+="[^"]*"( [a-z_]+="[^"]*")*$/);
      const raw = (r.c.ev.raw ?? {}) as Record<string, string>;
      expectEvidence(log, Object.entries(raw).filter(([k]) => k.startsWith("exabeam.") && k !== "exabeam.start_time").map(([, v]) => String(v)), r.c.ev.id);
      noLeak(log, r.c.ev);
    }
  });
  it("a session's id, url and start_time follow the row's time and keep the authored session age", () => {
    const ev = rows.find(r => r.c.ev.id === "b_ueba_02")!.c.ev;
    const log = source.fromTelemetry(ev, makeCtx("nexacorp"))!;
    expect(log.record.start_time).toBe("2026-05-10T08:02:00+00:00");
    expect(log.record.id).toBe("k.taylor-202605100802");
    expect(String(log.record.url)).toContain(`/timeline/${log.record.id}`);
    const moved = source.fromTelemetry(withRebasedTime(ev, "2026-11-09T09:30:00.000Z"), makeCtx("nexacorp"))!;
    expect(moved.record.start_time).toBe("2026-11-09T09:22:00+00:00");
    expect(moved.record.id).toBe("k.taylor-202611090922");
    const job = source.fromTelemetry(withRebasedTime(rows.find(r => r.c.ev.id === "b_ueba_05")!.c.ev, "2026-11-09T21:05:00.000Z"), makeCtx("nexacorp"))!;
    expect(job.record.timestamp).toBe("November 9 2026, 9:05PM (UTC)");
  });
  it("other UEBA products are not Exabeam records", () => {
    expect(source.fromTelemetry(mk("x", { "behavior.score": "6" }, { vendor: "Microsoft Sentinel UEBA" }), makeCtx("nexacorp"))).toBeNull();
  });
});

describe("exabeam - use cases", () => {
  const ctx = makeCtx("nexacorp");
  const fixtures: NativeLog[] = [
    source.fromTelemetry(mk("e1", { "exabeam.user": "r.adler", "exabeam.score": "135", "exabeam.start_time": "2026-05-10T07:40:00+00:00", "exabeam.status": "open", "exabeam.reasons_count": "3", "exabeam.events_count": "412", "exabeam.alerts_count": "2", "exabeam.reasons": "It is abnormal for this user to access this asset" }), ctx)!,
    source.fromTelemetry(mk("e2", { "exabeam.job_status": "Failed", "exabeam.job_details": "Reprocess stopped", "exabeam.job_id": "5c1ace5c123b3801207481f0", "exabeam.created_by": "j.weber" }), ctx)!,
  ];
  const noise = rows.filter(r => !r.attack).map(r => render(source, r)!);
  it("every use case fires on rows / fixtures; high ones stay quiet on routine rows", () => {
    for (const f of fixtures) expect(kvLine(f.record as Record<string, string>, Object.keys(f.record))).toBe(f.rawLine);
    for (const uc of source.useCases) {
      const hits = runUseCase(uc, [...noise, ...fixtures]).length;
      const noiseHits = runUseCase(uc, noise).length;
      console.log(`[exabeam] ${uc.id}: ${hits} hit(s), ${noiseHits}/${noise.length} on routine rows`);
      expect(hits, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length), uc.id).toBeLessThan(0.02);
    }
  });
});
