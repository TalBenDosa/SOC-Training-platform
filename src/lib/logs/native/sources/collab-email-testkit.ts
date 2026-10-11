/**
 * Test-only helpers shared by the m365 / google_workspace / defender_o365 /
 * proofpoint test files (no vitest import here — plain functions).
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { NativeLog, NativeSource, UseCase } from "../types";
import { makeCtx } from "../ctx";
import { corpusFor, type CorpusEvent } from "../testing/corpus";
import { runUseCase } from "../engine";
import { deepStrings } from "./collab-email-shared";

export interface Converted { ce: CorpusEvent; log: NativeLog | null }

export function convertAll(src: NativeSource, events: CorpusEvent[] = corpusFor(src.schema.telemetrySources)): Converted[] {
  return events.map(ce => ({ ce, log: src.fromTelemetry(ce.ev, makeCtx(ce.companyId)) }));
}

export function isNativeVendor(src: NativeSource, ev: TelemetryEvent): boolean {
  const v = (ev.vendor ?? "").toLowerCase();
  return src.schema.vendorMatch.some(m => v.includes(m));
}

/**
 * Planted detections / training false-positives inside the benign & company
 * streams. They are DESIGNED to fire alerts, so they are excluded from the
 * "noise" population used for the < 2 % false-positive-rate check. Events that
 * carry an `it_verify_result` (either value) are IT-verification exercises: an
 * admin-type change the platform deliberately surfaces as an alert so the
 * student checks it with IT — also excluded.
 */
export function isPlanted(ev: TelemetryEvent): boolean {
  return ev.expected_verdict === "tp" || ev.expected_verdict === "fp" || !!ev.is_detection || !!ev.mitre_technique ||
    ev.it_verify_result !== undefined;
}

/**
 * Mail events whose authored data already carries an email-security product verdict
 * (ThreatTypes / Verdict / threat.category = Malware|Phish, e.g. a quarantined invoice.exe):
 * real detections even when they sit in the company stream — not "noise".
 */
export function hasMailVerdict(ev: TelemetryEvent): boolean {
  const r = ev.raw ?? {};
  return /malware|phish/i.test(String(r["data.office365.ThreatTypes"] ?? r["data.office365.Verdict"] ?? r["ThreatTypes"] ?? r["threat.category"] ?? ""));
}

/** Every string leaf of the record (and of optional companion records). */
export function strings(...records: unknown[]): string[] {
  return records.flatMap(r => deepStrings(r));
}
export const present = (hay: string[], needle: string) => hay.some(s => s.includes(needle));

/** Per-use-case hit counts (records fired) over a log set. */
export function hitCounts(useCases: UseCase[], logs: NativeLog[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const uc of useCases) out[uc.id] = runUseCase(uc, logs).reduce((n, h) => n + h.records.length, 0);
  return out;
}

/** Records (indexes) that any high/critical use case fires on. */
export function highFired(useCases: UseCase[], logs: NativeLog[]): Set<number> {
  const s = new Set<number>();
  for (const uc of useCases) {
    if (uc.severity !== "high" && uc.severity !== "critical") continue;
    for (const h of runUseCase(uc, logs)) h.records.forEach(i => s.add(i));
  }
  return s;
}
