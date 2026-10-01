/**
 * Test-only access to the platform's existing log corpus and to the schema-card
 * samples. Used by every source module's tests:
 *   - corpusFor(): every authored TelemetryEvent of given telemetry sources, so a
 *     converter is proven on ALL real platform events of its category;
 *   - cardSamples(): the parsed ```json blocks of a docs/log-schemas card, so the
 *     module's schema is proven against the researched native samples.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { TelemetryEvent } from "@/lib/sim/types";
import { ATTACK_STORIES } from "@/app/(app)/dashboard/attackStories";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";

export interface CorpusEvent { ev: TelemetryEvent; origin: "story" | "benign" | "company"; companyId: string; storyId?: string }

let cache: CorpusEvent[] | null = null;
export function corpus(): CorpusEvent[] {
  if (cache) return cache;
  const out: CorpusEvent[] = [];
  for (const s of ATTACK_STORIES) for (const ev of s.events) out.push({ ev, origin: "story", companyId: s.companies?.[0] ?? "nexacorp", storyId: s.id });
  for (const ev of BENIGN_EVENTS) out.push({ ev, origin: "benign", companyId: "nexacorp" });
  for (const [companyId, evs] of Object.entries(COMPANY_EVENTS)) for (const ev of evs) out.push({ ev, origin: "company", companyId });
  cache = out;
  return out;
}

/** Corpus events whose TelemetryEvent.source is one of `sources` (optionally a vendor substring filter). */
export function corpusFor(sources: string[], vendorMatch?: string[]): CorpusEvent[] {
  return corpus().filter(c => sources.includes(c.ev.source) &&
    (!vendorMatch || vendorMatch.some(v => (c.ev.vendor ?? "").toLowerCase().includes(v))));
}

const CARDS = join(process.cwd(), "docs", "log-schemas");
/** Parsed ```json blocks of a card (blocks that are not a single JSON value are skipped). */
export function cardSamples(card: string): unknown[] {
  const md = readFileSync(join(CARDS, card), "utf8");
  const out: unknown[] = [];
  for (const m of md.matchAll(/```json\s*\n([\s\S]*?)```/g)) {
    try { out.push(JSON.parse(m[1])); } catch { /* annotated block */ }
  }
  return out;
}
