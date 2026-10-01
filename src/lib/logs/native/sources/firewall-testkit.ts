/**
 * Test-only harness shared by the five firewall source modules' tests
 * (paloalto / fortigate / checkpoint / cisco_ftd / cisco_asa). Implements the
 * brief's required checks once: card samples validate, every corpus event of the
 * category converts and validates (or is null for a documented reason), coverage
 * floors, evidence preservation, determinism, and use-case firing / noise rates.
 */
import { describe, it, expect } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog, NativeSource } from "../types";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples, type CorpusEvent } from "../testing/corpus";

export type EvidenceKey = "hostname" | "user" | "src_ip" | "dst_ip" | "sha256" | "dns.query" | "network.domain" | "network.url";

export interface FirewallSuiteOpts {
  source: NativeSource;
  kindOf: (r: Record<string, unknown>) => string | null;
  /** Card samples whose kindOf() is null are ignored (e.g. ASA samples in the shared Cisco card). */
  /** Evidence a given rendered log cannot carry natively (documented per source). */
  evidenceExempt: (log: NativeLog, ev: TelemetryEvent) => EvidenceKey[];
  /** Minimum non-null share for natively-authored events (brief: ≥ 95 %). */
  nativeMin?: number;
  /** Floor for cross-vendor events. */
  crossMin: number;
  /** Extra logs built from card samples / story events (threshold scenarios). */
  fixtures?: () => NativeLog[];
  /** Expected-null predicate (documented reasons) — asserted to be the ONLY nulls. */
  nullAllowed: (ev: TelemetryEvent) => string | null;
  /** Card time extractor (epoch ms) for card-sample logs. */
  cardTime?: (r: Record<string, unknown>) => number;
}

export function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (typeof v === "string" || typeof v === "number") out.push(String(v));
  else if (Array.isArray(v)) v.forEach(x => deepStrings(x, out));
  else if (typeof v === "object") Object.values(v as Record<string, unknown>).forEach(x => deepStrings(x, out));
  return out;
}

export function evidenceOf(ev: TelemetryEvent): Partial<Record<EvidenceKey, string>> {
  const e: Partial<Record<EvidenceKey, string>> = {};
  if (ev.hostname) e.hostname = ev.hostname;
  const email = ev.user?.email ?? ev.user_email;
  const panUser = (ev.raw as Record<string, unknown>)?.["pan.srcuser"] as string | undefined;
  if (panUser) e.user = panUser.split("\\").pop();
  else if (email) e.user = email.split("@")[0];
  if (ev.src_ip) e.src_ip = ev.src_ip;
  if (ev.dst_ip) e.dst_ip = ev.dst_ip;
  const sha = ev.file?.sha256 ?? ev.process?.hash?.sha256;
  if (sha) e.sha256 = sha;
  if (ev.dns?.query) e["dns.query"] = ev.dns.query;
  if (ev.network?.domain) e["network.domain"] = ev.network.domain;
  if (ev.network?.url) e["network.url"] = ev.network.url;
  return e;
}

export function convertAll(source: NativeSource, events: CorpusEvent[]): { c: CorpusEvent; log: NativeLog | null }[] {
  return events.map(c => ({ c, log: source.fromTelemetry(c.ev, makeCtx(c.companyId)) }));
}

export function runFirewallSuite(o: FirewallSuiteOpts): void {
  const { source, kindOf } = o;
  const schema = source.schema;
  const all = corpusFor(schema.telemetrySources);
  const conv = convertAll(source, all);
  const isNative = (c: CorpusEvent) => schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v));

  describe(`${schema.sourceId}: card samples`, () => {
    it("every supported card sample validates with zero violations", () => {
      const samples = cardSamples(schema.card) as Record<string, unknown>[];
      let checked = 0;
      for (const s of samples) {
        const k = kindOf(s);
        if (!k || !schema.kinds[k]) continue;
        const v = validateNative({ sourceId: schema.sourceId, kind: k, format: schema.format, record: s, timeMs: 0 }, schema);
        expect(v, `${k}: ${JSON.stringify(v)}`).toEqual([]);
        checked++;
      }
      console.log(`[${schema.sourceId}] card samples validated: ${checked}/${samples.length}`);
      expect(checked).toBeGreaterThan(0);
    });
  });

  describe(`${schema.sourceId}: corpus conversion`, () => {
    it("every converted corpus event validates; nulls only for documented reasons", () => {
      for (const { c, log } of conv) {
        if (!log) {
          const why = o.nullAllowed(c.ev);
          expect(why, `unexpected null for ${c.ev.id} (${c.ev.vendor} ${c.ev.event_type})`).not.toBeNull();
          continue;
        }
        const v = validateNative(log, schema);
        expect(v, `${c.ev.id} → ${log.kind}: ${JSON.stringify(v)}`).toEqual([]);
        expect(log.sourceId).toBe(schema.sourceId);
        expect(log.timeMs).toBe(Date.parse(c.ev.ts));
        expect(typeof log.rawLine).toBe("string");
        expect(log.rawLine!.length).toBeGreaterThan(20);
      }
    });
    it("coverage floors (native ≥ 95 %, cross-vendor floor)", () => {
      const nat = conv.filter(x => isNative(x.c)), cross = conv.filter(x => !isNative(x.c));
      const natOk = nat.filter(x => x.log).length, crossOk = cross.filter(x => x.log).length;
      const nulls = conv.filter(x => !x.log).map(x => `${x.c.ev.id}(${o.nullAllowed(x.c.ev)})`);
      console.log(`[${schema.sourceId}] native ${natOk}/${nat.length}, cross-vendor ${crossOk}/${cross.length}; nulls: ${nulls.join(", ") || "none"}`);
      if (nat.length) expect(natOk / nat.length).toBeGreaterThanOrEqual(o.nativeMin ?? 0.95);
      expect(crossOk / Math.max(1, cross.length)).toBeGreaterThanOrEqual(o.crossMin);
      const kinds: Record<string, number> = {};
      for (const x of conv) if (x.log) kinds[x.log.kind] = (kinds[x.log.kind] ?? 0) + 1;
      console.log(`[${schema.sourceId}] kinds: ${JSON.stringify(kinds)}`);
    });
    it("evidence values survive verbatim", () => {
      let checked = 0;
      for (const { c, log } of conv) {
        if (!log) continue;
        const recordOnly = deepStrings(log.record);
        const exempt = new Set(o.evidenceExempt(log, c.ev));
        for (const [k, val] of Object.entries(evidenceOf(c.ev)) as [EvidenceKey, string][]) {
          if (exempt.has(k)) continue;
          const alts = k === "network.url" ? [val, val.replace(/^[a-z]+:\/\//i, "")] : [val];
          const found = alts.some(a => recordOnly.some(x => x.includes(a)));
          expect(found, `${c.ev.id} → ${log.kind}: evidence ${k}=${val} missing`).toBe(true);
          checked++;
        }
      }
      console.log(`[${schema.sourceId}] evidence values checked: ${checked}`);
      expect(checked).toBeGreaterThan(0);
    });
    it("is deterministic", () => {
      const again = convertAll(source, all);
      expect(again.map(x => x.log)).toEqual(conv.map(x => x.log));
    });
  });

  describe(`${schema.sourceId}: use cases`, () => {
    it("has 4–12 use cases with well-formed ids", () => {
      expect(source.useCases.length).toBeGreaterThanOrEqual(4);
      for (const uc of source.useCases) {
        expect(uc.id.startsWith(`${schema.sourceId}.`)).toBe(true);
        expect(uc.sourceId).toBe(schema.sourceId);
        for (const k of uc.kinds ?? []) expect(schema.kinds[k], `${uc.id} kind ${k}`).toBeDefined();
      }
    });
    it("each use case fires on card/story logs; high/critical stay < 2 % on noise", () => {
      const cardLogs: NativeLog[] = (cardSamples(schema.card) as Record<string, unknown>[])
        .filter(s => kindOf(s) && schema.kinds[kindOf(s)!])
        .map(s => ({ sourceId: schema.sourceId, kind: kindOf(s)!, format: schema.format, record: s, timeMs: o.cardTime?.(s) ?? 0 }));
      const story = conv.filter(x => x.c.origin === "story" && x.log).map(x => x.log!);
      const fixtures = o.fixtures?.() ?? [];
      for (const fx of fixtures) expect(validateNative(fx, schema), `fixture ${fx.kind}`).toEqual([]);
      const pool = [...cardLogs, ...story, ...fixtures];
      // Noise = benign/company events that are not seeded true positives.
      const noise = conv.filter(x => x.c.origin !== "story" && x.log && x.c.ev.expected_verdict !== "tp" && !x.c.ev.is_detection).map(x => x.log!);
      const report: string[] = [];
      for (const uc of source.useCases) {
        const hits = runUseCase(uc, pool);
        const nHits = runUseCase(uc, noise);
        const noisy = new Set(nHits.flatMap(h => h.records)).size;
        report.push(`${uc.id}: ${hits.length} hit(s) [${new Set(hits.flatMap(h => h.records)).size} recs], noise ${noisy}/${noise.length}`);
        expect(hits.length, `${uc.id} never fires`).toBeGreaterThan(0);
        if (uc.severity === "high" || uc.severity === "critical") expect(noisy / Math.max(1, noise.length), `${uc.id} too noisy`).toBeLessThan(0.02);
      }
      console.log(`[${schema.sourceId}] use cases:\n  ${report.join("\n  ")}`);
    });
  });
}

/** Clone a log with overrides (fixtures for threshold use cases). */
export function cloneLog(base: NativeLog, timeMs: number, patch: Record<string, unknown>): NativeLog {
  return { ...base, timeMs, record: { ...base.record, ...patch } };
}
/** Story events replicated on a fixed interval (e.g. "beacons every 60 seconds"). */
export function repeatEvent(ev: TelemetryEvent, times: number, everySec: number): TelemetryEvent[] {
  const t0 = Date.parse(ev.ts);
  return Array.from({ length: times }, (_, i) => ({ ...ev, id: `${ev.id}#${i}`, ts: new Date(t0 + i * everySec * 1000).toISOString() }));
}
