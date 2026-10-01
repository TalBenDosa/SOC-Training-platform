/**
 * Test helpers for the crowdstrike / sentinelone module tests (not a test file itself).
 */
import { cardSamples, type CorpusEvent } from "../testing/corpus";
import { validateNative, type Violation } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog, NativeSource } from "../types";
import { edrFacts } from "./edr-normalize";

export function sampleLogs(source: NativeSource, kindOf: (r: Record<string, unknown>) => string | null) {
  const logs: NativeLog[] = [];
  const skipped: { index: number; kind: string | null }[] = [];
  cardSamples(source.schema.card).forEach((r, i) => {
    const rec = r as Record<string, unknown>;
    const k = kindOf(rec);
    if (!k || !source.schema.kinds[k]) { skipped.push({ index: i, kind: k }); return; }
    logs.push({ sourceId: source.schema.sourceId, kind: k, format: source.schema.format, record: rec, timeMs: 1_790_669_000_000 + i * 1000 });
  });
  return { logs, skipped };
}

export const violationsOf = (log: NativeLog, source: NativeSource): Violation[] => validateNative(log, source.schema);

export function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v)) { for (const x of v) deepStrings(x, out); return out; }
  if (typeof v === "object") { for (const x of Object.values(v as Record<string, unknown>)) deepStrings(x, out); return out; }
  out.push(String(v));
  return out;
}
export const contains = (record: unknown, value: string) => deepStrings(record).some(s => s.includes(value));

export interface Converted { c: CorpusEvent; log: NativeLog | null; error?: string; supported: boolean }
export function convertAll(source: NativeSource, events: CorpusEvent[]): Converted[] {
  return events.map(c => {
    const supported = edrFacts(c.ev).kind !== "unsupported";
    try { return { c, log: source.fromTelemetry(c.ev, makeCtx(c.companyId)), supported }; }
    catch (e) { return { c, log: null, error: String(e), supported }; }
  });
}

export function isNoise(c: CorpusEvent): boolean {
  if (c.origin === "story") return false;
  if (c.ev.expected_verdict === "tp") return false;
  return c.ev.severity !== "high" && c.ev.severity !== "critical";
}
