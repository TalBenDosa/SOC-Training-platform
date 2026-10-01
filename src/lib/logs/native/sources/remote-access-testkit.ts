/**
 * Test-only helpers shared by the remote-access / proxy module tests
 * (globalprotect, anyconnect, fortigate_sslvpn, zscaler_zpa, cloudflare_access, zscaler_zia).
 * Not imported by runtime code.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { expect } from "vitest";
import type { NativeLog, NativeSource, UseCase } from "../types";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { makeCtx } from "../ctx";
import { corpusFor, cardSamples, type CorpusEvent } from "../testing/corpus";
import { deepStrings } from "./remote-access-shared";

/** Card json samples, arrays flattened to records. */
export function cardRecords(card: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const s of cardSamples(card)) {
    if (Array.isArray(s)) for (const x of s) out.push(x as Record<string, unknown>);
    else if (s && typeof s === "object") out.push(s as Record<string, unknown>);
  }
  return out;
}

/** Lines of the first fenced block with the given info string (e.g. "ndjson") or the plain ``` block after a heading. */
export function fencedBlocks(card: string, info: string): string[] {
  const md = readFileSync(join(process.cwd(), "docs", "log-schemas", card), "utf8");
  const re = new RegExp("```" + info + "\\s*\\n([\\s\\S]*?)```", "g");
  return [...md.matchAll(re)].map(m => m[1]);
}

/** Every line of a card (for raw wire lines shown outside json blocks). */
export function cardLines(card: string): string[] {
  return readFileSync(join(process.cwd(), "docs", "log-schemas", card), "utf8").split(/\r?\n/);
}

export interface Converted { c: CorpusEvent; log: NativeLog | null }

export function convertCorpus(src: NativeSource): Converted[] {
  return corpusFor(src.schema.telemetrySources).map(c => ({ c, log: src.fromTelemetry(c.ev, makeCtx(c.companyId)) }));
}

export function isNative(src: NativeSource, c: CorpusEvent): boolean {
  const v = (c.ev.vendor ?? "").toLowerCase();
  return src.schema.vendorMatch.some(m => v.includes(m));
}

/** Validate every converted log; return the list of failures (empty = clean). */
export function violations(src: NativeSource, conv: Converted[]): string[] {
  const bad: string[] = [];
  for (const { c, log } of conv) {
    if (!log) continue;
    const v = validateNative(log, src.schema);
    if (v.length) bad.push(`${c.ev.id}: ${v.map(x => `${x.problem}:${x.path}`).join(", ")}`);
  }
  return bad;
}

export function coverage(src: NativeSource, conv: Converted[]) {
  const nat = conv.filter(x => isNative(src, x.c));
  const cross = conv.filter(x => !isNative(src, x.c));
  const ok = (a: Converted[]) => a.filter(x => x.log).length;
  return { native: { total: nat.length, ok: ok(nat) }, cross: { total: cross.length, ok: ok(cross) }, nulls: conv.filter(x => !x.log).map(x => `${x.c.ev.vendor}/${x.c.ev.event_type}/${x.c.ev.id}`) };
}

/** Does `needle` occur in any string of the record (or the raw line)? */
export function present(log: NativeLog, needle: string): boolean {
  const hay = deepStrings(log.record);
  if (log.rawLine) hay.push(log.rawLine);
  return hay.some(s => s.includes(needle));
}

/** Runs every use case; returns per-use-case hit counts on attack logs and noise logs. */
export function ucReport(src: NativeSource, attack: NativeLog[], noise: NativeLog[]) {
  const rows: { uc: UseCase; attackHits: number; noiseRecords: number; noiseRate: number }[] = [];
  for (const uc of src.useCases) {
    const a = runUseCase(uc, attack);
    const n = runUseCase(uc, noise);
    const noiseRecords = new Set(n.flatMap(h => h.records)).size;
    rows.push({ uc, attackHits: a.length, noiseRecords, noiseRate: noise.length ? noiseRecords / noise.length : 0 });
  }
  // eslint-disable-next-line no-console
  console.log(`[${src.schema.sourceId}] use cases:\n` + rows.map(r => `  ${r.uc.id.padEnd(58)} ${r.uc.severity.padEnd(8)} attackHits=${r.attackHits} noiseRecords=${r.noiseRecords}/${noise.length}`).join("\n"));
  return rows;
}

export function assertUseCases(src: NativeSource, attack: NativeLog[], noise: NativeLog[]) {
  const rows = ucReport(src, attack, noise);
  for (const r of rows) {
    expect(r.attackHits, `${r.uc.id} never fires on card/story logs`).toBeGreaterThan(0);
    if (r.uc.severity === "high" || r.uc.severity === "critical") expect(r.noiseRate, `${r.uc.id} noisy`).toBeLessThan(0.02);
    expect(r.uc.id.startsWith(`${src.schema.sourceId}.`)).toBe(true);
    expect(r.uc.sourceId).toBe(src.schema.sourceId);
  }
  expect(src.useCases.length).toBeGreaterThanOrEqual(4);
}

/**
 * Converted noise events: benign / company-profile origin, EXCLUDING the attacks
 * deliberately planted in the noise feed (expected_verdict tp/escalate) — those
 * are supposed to fire.
 */
export function noiseLogs(conv: Converted[]): NativeLog[] {
  return conv.filter(x => x.log && x.c.origin !== "story" && x.c.ev.expected_verdict !== "tp" && x.c.ev.expected_verdict !== "escalate").map(x => x.log as NativeLog);
}
export function storyLogs(conv: Converted[]): NativeLog[] {
  return conv.filter(x => x.log && (x.c.origin === "story" || x.c.ev.expected_verdict === "tp" || x.c.ev.expected_verdict === "escalate")).map(x => x.log as NativeLog);
}

/** Clone a card record n times with a time step and per-copy mutation (builds a burst from a card sample). */
export function burst<T extends Record<string, unknown>>(rec: T, n: number, mutate: (r: T, i: number) => T): T[] {
  return Array.from({ length: n }, (_, i) => mutate(JSON.parse(JSON.stringify(rec)) as T, i));
}
