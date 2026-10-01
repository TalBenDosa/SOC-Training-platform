/**
 * Test helpers shared by the windows_dns / infoblox / sysmon / linux_auditd /
 * servicenow module tests (not a test file itself).
 */
import { cardSamples, type CorpusEvent } from "../testing/corpus";
import { validateNative, type Violation } from "../validate";
import { makeCtx } from "../ctx";
import type { NativeLog, NativeSource } from "../types";

/** Card samples, with top-level arrays (multi-record samples) flattened to one record each. */
export function flatSamples(card: string): Record<string, unknown>[] {
  return cardSamples(card).flatMap(x => (Array.isArray(x) ? x : [x])).filter(x => x && typeof x === "object") as Record<string, unknown>[];
}

/** Card samples as NativeLogs (kind from kindOf); unsupported kinds are returned in `skipped`. */
export function sampleLogs(source: NativeSource, kindOf: (r: Record<string, unknown>) => string | null, timeOf: (r: Record<string, unknown>, i: number) => number = (_, i) => i * 1000) {
  const logs: NativeLog[] = [];
  const skipped: { index: number; reason: string }[] = [];
  flatSamples(source.schema.card).forEach((r, i) => {
    const k = kindOf(r);
    if (!k || !source.schema.kinds[k]) { skipped.push({ index: i, reason: `kindOf=${k}` }); return; }
    logs.push({ sourceId: source.schema.sourceId, kind: k, format: source.schema.format, record: r, timeMs: timeOf(r, i) });
  });
  return { logs, skipped };
}

export function violationsOf(log: NativeLog, source: NativeSource): Violation[] {
  return validateNative(log, source.schema);
}

/** Every string (and number, stringified) value in a record. */
export function deepStrings(v: unknown, out: string[] = []): string[] {
  if (v === null || v === undefined) return out;
  if (Array.isArray(v)) { for (const x of v) deepStrings(x, out); return out; }
  if (typeof v === "object") { for (const x of Object.values(v as Record<string, unknown>)) deepStrings(x, out); return out; }
  out.push(String(v));
  return out;
}
export function contains(record: unknown, value: string): boolean {
  return deepStrings(record).some(s => s.includes(value));
}

export interface Converted { c: CorpusEvent; log: NativeLog | null; error?: string }
export function convertAll(source: NativeSource, events: CorpusEvent[]): Converted[] {
  return events.map(c => {
    try { return { c, log: source.fromTelemetry(c.ev, makeCtx(c.companyId)) }; }
    catch (e) { return { c, log: null, error: String(e) }; }
  });
}

/** Noise = benign/company events that are not themselves authored attacks (tp / high / critical). */
export function isNoise(c: CorpusEvent): boolean {
  if (c.origin === "story") return false;
  if (c.ev.expected_verdict === "tp") return false;
  return c.ev.severity !== "high" && c.ev.severity !== "critical";
}
