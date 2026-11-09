/**
 * Test helpers shared by the database and UEBA module tests (mssql_audit, guardium, mysql_audit,
 * exabeam, securonix): every authored row of the module's product, from the live corpus (stories,
 * benign pool, company pools) AND the scenarios page (SCENARIOS, scenario packs included), with its
 * ground truth; and the generic checks every one of these modules must pass.
 */
import { expect } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { corpusFor, type CorpusEvent } from "../testing/corpus";
import { makeCtx } from "../ctx";
import { validateNative } from "../validate";
import { nativeView, nativeStoryRenderer } from "../index";
import type { NativeLog, NativeSource } from "../types";
import { deepStrings } from "./_dnsHostItsm.testkit";

export interface Row { c: CorpusEvent; attack: boolean; scenario?: string }

const attackOf = (e: TelemetryEvent, origin: CorpusEvent["origin"]): boolean => {
  if (e.expected_verdict === "fp" || e.expected_verdict === "informational" || e.is_baseline || e.fp_explanation) return false;
  if (e.expected_verdict === "tp" || e.expected_verdict === "escalate") return true;
  return origin === "story" && !!e.mitre_technique;
};

let scenarioCache: { slug: string; events: TelemetryEvent[] }[] | null = null;
function scenarios() {
  if (scenarioCache) return scenarioCache;
  scenarioCache = [];
  for (const sc of SCENARIOS) { try { scenarioCache.push({ slug: sc.slug, events: sc.build().events ?? [] }); } catch { /* a broken build is another test's failure */ } }
  return scenarioCache;
}

/** Every authored row of the vendor (case-insensitive substring of TelemetryEvent.vendor). */
export function vendorRows(source: NativeSource, vendor: RegExp): Row[] {
  const out: Row[] = [];
  for (const c of corpusFor(source.schema.telemetrySources)) if (vendor.test(c.ev.vendor ?? "")) out.push({ c, attack: attackOf(c.ev, c.origin) });
  for (const s of scenarios()) for (const ev of s.events) {
    if (!source.schema.telemetrySources.includes(ev.source) || !vendor.test(ev.vendor ?? "")) continue;
    out.push({ c: { ev, origin: "story", companyId: "nexacorp", storyId: s.slug }, attack: attackOf(ev, "story"), scenario: s.slug });
  }
  return out;
}

export const render = (source: NativeSource, r: Row): NativeLog | null => source.fromTelemetry(r.c.ev, makeCtx(r.c.companyId));

const keySet = (v: unknown, p = ""): string[] => {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return [p];
  return Object.entries(v as Record<string, unknown>).flatMap(([k, x]) => keySet(x, p ? `${p}.${k}` : k));
};

/** The checks every database / UEBA module passes on every row of its product. */
export function commonChecks(source: NativeSource, rows: Row[], opts: { timeFields: (log: NativeLog) => number[]; nullOk?: (r: Row) => boolean }) {
  // 1. Every row renders, validates, and is stamped with the row's own time.
  for (const r of rows) {
    const log = render(source, r);
    if (!log) { expect(opts.nullOk?.(r), `${r.c.ev.id} rendered null`).toBe(true); continue; }
    expect(validateNative(log, source.schema), r.c.ev.id).toEqual([]);
    expect(log.timeMs, r.c.ev.id).toBe(Date.parse(r.c.ev.ts));
    for (const t of opts.timeFields(log)) expect(Math.abs(t - log.timeMs), `${r.c.ev.id} time field`).toBeLessThanOrEqual(999);
    expect(JSON.stringify(log.record) + (log.rawLine ?? ""), r.c.ev.id).not.toMatch(/undefined|NaN|\[object Object\]/);
    // Determinism.
    expect(render(source, r), r.c.ev.id).toEqual(log);
  }
  // 2. Every surface routes the row to this module: the live feed (nativeView) and the scenario page (nativeStoryRenderer).
  for (const r of rows) {
    if (r.scenario) {
      const s = scenarios().find(x => x.slug === r.scenario)!;
      const v = nativeStoryRenderer(s.events)(r.c.ev);
      if (v || !opts.nullOk?.(r)) expect(v?.log.sourceId, `${r.scenario}:${r.c.ev.id}`).toBe(source.schema.sourceId);
    } else {
      const v = nativeView(r.c.ev, r.c.companyId);
      if (v || !opts.nullOk?.(r)) expect(v?.log.sourceId, r.c.ev.id).toBe(source.schema.sourceId);
    }
  }
  // 3. R4: a re-timed row prints the new time (the feed and the team timeline re-time every row).
  for (const r of rows) {
    const moved = withRebasedTime(r.c.ev, "2026-11-09T09:30:15.000Z");
    const log = source.fromTelemetry(moved, makeCtx(r.c.companyId));
    if (!log) continue;
    expect(log.timeMs).toBe(Date.parse("2026-11-09T09:30:15.000Z"));
    for (const t of opts.timeFields(log)) expect(Math.abs(t - log.timeMs), `${r.c.ev.id} re-timed`).toBeLessThanOrEqual(999);
  }
  // 4. R2: one kind, one shape - attack and routine rows of a kind print the same keys.
  const shapes = new Map<string, Map<string, string[]>>();
  for (const r of rows) {
    const log = render(source, r);
    if (!log) continue;
    const keys = keySet(log.record).sort().join(",");
    const m = shapes.get(log.kind) ?? shapes.set(log.kind, new Map()).get(log.kind)!;
    (m.get(keys) ?? m.set(keys, []).get(keys)!).push(`${r.attack ? "attack" : "benign"}:${r.c.ev.id}`);
  }
  return shapes;
}

/** R9: the record never carries the authored conclusion or a verdict field. */
export function noLeak(log: NativeLog, ev: TelemetryEvent) {
  const text = JSON.stringify(log.record) + (log.rawLine ?? "");
  if (ev.description && ev.description.length >= 40) expect(text, ev.id).not.toContain(ev.description.slice(0, 40));
  expect(text, ev.id).not.toMatch(/expected_verdict|is_malicious|attack_stage|ground_truth|fp_explanation/);
}

/** Evidence values a student quotes: each present one appears verbatim in the record. */
export function expectEvidence(log: NativeLog, values: (string | undefined)[], id: string) {
  const all = deepStrings(log.record).join("\n") + (log.rawLine ?? "");
  for (const v of values) if (v) expect(all, `${id}: ${v}`).toContain(v);
}
