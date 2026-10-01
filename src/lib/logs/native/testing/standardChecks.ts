/**
 * The standard checks every native source module must pass (SOURCE-MODULE-BRIEF):
 * card samples validate, corpus events convert cleanly, evidence survives, output is
 * deterministic, and use cases fire on attack logs while staying quiet on noise.
 * Returns plain numbers so each module's test can assert its own floors.
 */
import type { NativeLog, NativeSource } from "../types";
import { validateNative, type Violation } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples, type CorpusEvent } from "./corpus";

export interface StandardReport {
  cardChecked: number; cardSkipped: number; cardViolations: { i: number; v: Violation[] }[];
  nativeTotal: number; nativeConverted: number; crossTotal: number; crossConverted: number;
  violations: { id: string; v: Violation[] }[];
  evidenceMissing: { id: string; value: string }[];
  nondeterministic: string[];
  useCaseHits: Record<string, { attack: number; noise: number; severity: string }>;
  noiseCount: number;
}

const flat = (v: unknown): string => JSON.stringify(v ?? "");

/** Evidence values a reader would quote, present on the authored event. */
function evidenceOf(c: CorpusEvent): string[] {
  const e = c.ev;
  const out = [e.src_ip, e.dst_ip, e.user_email?.split("@")[0], e.process?.cmdline, e.process?.hash?.sha256, e.file?.sha256, e.dns?.query, e.cloud?.api_call]
    .filter((x): x is string => typeof x === "string" && x.length > 2);
  return [...new Set(out)];
}

export function standardChecks(source: NativeSource, kindOf: (r: Record<string, unknown>) => string | null,
  opts: { cards: string[]; isNoise?: (c: CorpusEvent) => boolean; evidence?: (c: CorpusEvent) => string[] }): StandardReport {
  const schema = source.schema;
  const rep: StandardReport = { cardChecked: 0, cardSkipped: 0, cardViolations: [], nativeTotal: 0, nativeConverted: 0, crossTotal: 0, crossConverted: 0,
    violations: [], evidenceMissing: [], nondeterministic: [], useCaseHits: {}, noiseCount: 0 };

  // 1. card samples
  const cardLogs: NativeLog[] = [];
  opts.cards.flatMap(c => cardSamples(c)).forEach((s, i) => {
    if (!s || typeof s !== "object" || Array.isArray(s)) { rep.cardSkipped++; return; }
    const record = s as Record<string, unknown>;
    const kind = kindOf(record);
    if (!kind || !schema.kinds[kind]) { rep.cardSkipped++; return; }
    const log: NativeLog = { sourceId: schema.sourceId, kind, format: schema.format, record, timeMs: i * 1000 };
    rep.cardChecked++;
    const v = validateNative(log, schema);
    if (v.length) rep.cardViolations.push({ i, v });
    cardLogs.push(log);
  });

  // 2–4. corpus conversion, evidence, determinism
  const attack: NativeLog[] = [];
  const noise: NativeLog[] = [];
  const isNoise = opts.isNoise ?? ((c: CorpusEvent) => c.origin !== "story" && !c.ev.expected_verdict && !c.ev.is_detection && !c.ev.mitre_technique);
  for (const c of corpusFor(schema.telemetrySources)) {
    const native = schema.vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v));
    if (native) rep.nativeTotal++; else rep.crossTotal++;
    const ctx = makeCtx(c.companyId);
    let log: NativeLog | null = null;
    try { log = source.fromTelemetry(c.ev, ctx); } catch { log = null; }
    if (!log) continue;
    if (native) rep.nativeConverted++; else rep.crossConverted++;
    const v = validateNative(log, schema);
    if (v.length) rep.violations.push({ id: c.ev.id, v });
    const again = source.fromTelemetry(c.ev, makeCtx(c.companyId));
    if (flat(again) !== flat(log)) rep.nondeterministic.push(c.ev.id);
    const hay = flat(log.record) + (log.rawLine ?? "");
    for (const val of (opts.evidence ?? evidenceOf)(c)) if (!hay.includes(JSON.stringify(val).slice(1, -1)) && !hay.includes(val)) rep.evidenceMissing.push({ id: c.ev.id, value: val });
    if (c.origin === "story") attack.push(log);
    else if (isNoise(c)) noise.push(log);
  }
  rep.noiseCount = noise.length;

  // 5. use cases
  for (const uc of source.useCases) {
    rep.useCaseHits[uc.id] = {
      attack: runUseCase(uc, [...cardLogs, ...attack]).length,
      noise: runUseCase(uc, noise).reduce((n, h) => n + h.records.length, 0),
      severity: uc.severity,
    };
  }
  return rep;
}
