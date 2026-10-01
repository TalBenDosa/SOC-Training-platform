import { describe, it, expect } from "vitest";
import { source, kindOf } from "./windows_dns";
import { corpusFor } from "../testing/corpus";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import type { NativeLog } from "../types";
import { sampleLogs, violationsOf, convertAll, contains, isNoise, flatSamples } from "./_dnsHostItsm.testkit";

/*
 * Card samples: all 7 records of dns-windows.md (256/257, 256/260, 519, 2× debug log, 1 debug burst row)
 * are supported kinds — none skipped. (The raw XML block is not JSON and is not a sample.)
 * Corpus nulls: the dns-tunneling story's "dns_baseline_aggregate" event is a per-host summary
 * (top domains / query types), not a DNS transaction — the server never logs such a record.
 */
const samples = sampleLogs(source, kindOf);
const events = corpusFor(source.schema.telemetrySources);
const converted = convertAll(source, events);
const nativeVendor = (v?: string) => source.schema.vendorMatch.some(m => (v ?? "").toLowerCase().includes(m));
const documentedNull = (c: (typeof converted)[number]) => c.c.ev.raw?.["event.action"] === "dns_baseline_aggregate";

describe("windows_dns — card samples", () => {
  it("every supported card sample validates with zero violations", () => {
    expect(samples.logs.length).toBe(flatSamples(source.schema.card).length);
    for (const l of samples.logs) expect(violationsOf(l, source), `${l.kind} ${JSON.stringify(l.record).slice(0, 80)}`).toEqual([]);
  });
});

describe("windows_dns — corpus conversion", () => {
  it("converts every DNS event (or returns null for a documented reason) with zero violations", () => {
    for (const c of converted) {
      expect(c.error).toBeUndefined();
      if (!c.log) { expect(documentedNull(c), `unexpected null ${c.c.ev.id}`).toBe(true); continue; }
      expect(violationsOf(c.log, source), c.c.ev.id).toEqual([]);
      expect(c.log.timeMs).toBe(Date.parse(c.c.ev.ts));
      expect(typeof c.log.rawLine).toBe("string");
    }
  });
  it("coverage: ≥95% for Windows-DNS-authored, cross-vendor floor", () => {
    const nat = converted.filter(c => nativeVendor(c.c.ev.vendor) && !documentedNull(c));
    const cross = converted.filter(c => !nativeVendor(c.c.ev.vendor));
    const natOk = nat.filter(c => c.log).length, crossOk = cross.filter(c => c.log).length;
    console.log(`[windows_dns] native ${natOk}/${nat.length} (+${converted.filter(documentedNull).length} documented null), cross-vendor ${crossOk}/${cross.length}`);
    expect(natOk / nat.length).toBeGreaterThanOrEqual(0.95);
    expect(crossOk / cross.length).toBeGreaterThanOrEqual(0.9);
  });
  it("evidence survives verbatim (client IP, query name, domain)", () => {
    for (const { c, log } of converted) {
      if (!log) continue;
      const ev = c.ev;
      const client = (ev.raw?.["infoblox.client_ip"] as string) ?? ev.src_ip;
      if (client) expect(contains(log.record, client), `${ev.id} client`).toBe(true);
      if (ev.dns?.query) expect(contains(log.record, ev.dns.query), `${ev.id} query`).toBe(true);
      if (ev.network?.domain) expect(contains(log.record, ev.network.domain), `${ev.id} domain`).toBe(true);
    }
  });
  it("is deterministic", () => {
    for (const c of events) {
      const ctx = makeCtx(c.companyId);
      expect(source.fromTelemetry(c.ev, ctx)).toEqual(source.fromTelemetry(c.ev, makeCtx(c.companyId)));
    }
  });
  it("debug-log rawLine matches the card's column layout", () => {
    const l = converted.find(c => c.log?.kind === "257")!.log!;
    expect(l.rawLine).toMatch(/^\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{2}:\d{2} [AP]M [0-9A-F]{4} PACKET  [0-9A-F]{16} UDP Snd [\d.]+ +[0-9a-f]{4} R Q \[(8183|8180)/);
    expect(String(l.record.QNAME)).toMatch(/\.$/);
    expect(String(l.record.TimeCreated)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$/);
  });
});

describe("windows_dns — use cases", () => {
  // DGA burst fixture built from the card's §4.1 257 NXDOMAIN record: 12 distinct random names from the
  // same client within 2 minutes (the card shows one; the detection needs the burst).
  const nx = flatSamples(source.schema.card).find(r => r.EventID === 257)!;
  const names = ["qxkzjvbtrwpmhd", "vbnrtqlzmwxkpe", "hjwqzpxkrtlmvb", "plmzqwkxrtvbnh", "zxqwvbnmlkjhgt", "rtyqzpwmxkvlbn", "mnbvzxqplkwjrt", "kqzxwvtrplmnbh", "wqzxrtvbnmlkjp", "tzqxwvplmkrnbh", "xqzrtvwbnmplkj", "bnvqzxwtrlmkph"];
  const burst: NativeLog[] = names.map((n, i) => ({ sourceId: "windows_dns", kind: "257", format: "xml", timeMs: 1_790_000_000_000 + i * 10_000, record: { ...nx, QNAME: `${n}.com.` } }));
  const story = converted.filter(c => c.c.origin === "story" && c.log).map(c => c.log!);
  const pool = [...samples.logs, ...story, ...burst];
  const noise = converted.filter(c => isNoise(c.c) && c.log).map(c => c.log!);

  it("every use case fires on card-sample / story logs; high+ stay quiet on noise", () => {
    expect(source.useCases.length).toBeGreaterThanOrEqual(4);
    for (const uc of source.useCases) {
      expect(uc.id.startsWith("windows_dns.")).toBe(true);
      const hits = runUseCase(uc, pool);
      const noiseHits = new Set(runUseCase(uc, noise).flatMap(h => h.records)).size;
      console.log(`[windows_dns] ${uc.id}: ${hits.length} hit(s) on samples+stories, ${noiseHits}/${noise.length} noise records`);
      expect(hits.length, uc.id).toBeGreaterThan(0);
      if (uc.severity === "high" || uc.severity === "critical") expect(noiseHits / Math.max(1, noise.length)).toBeLessThan(0.02);
    }
  });
});
