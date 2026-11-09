/**
 * A solo Live Feed shift played in code (tests only): the same pool (feedPool.ts), story pick and
 * adaptation (attackStories.ts), noise deck (noiseDeck.ts), story clock and noise quota (storyFeed.ts),
 * enrichment and SIEM mirror (useLiveEvents.ts) the dashboard uses, on the hook's cadence: a 15-row
 * backfill, a 90 s tick of 1-2 ordinary rows, the first phase after 2-3 min, a phase every 2-4 min,
 * and five minutes after the last phase. Math.random is seeded for the duration of a shift.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "./benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { companyFeedPool, feedCompanyProfile, feedStoryEvents } from "./feedPool";
import { ATTACK_STORIES, instantiateStory, pickStoryForCompany, type AttackStory } from "./attackStories";
import { applyStack, fitsStack, nativeView, storyHonoursLocks } from "@/lib/logs/native";
import { enrichEvent, injectAdvancedFidelityNoise, type LiveEvent } from "./liveEventEnrich";
import { backfillTimes, benignTimes, siemMirror } from "./useLiveEvents";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { NoiseDeck } from "./noiseDeck";
import { newStoryClock, noiseQuota, noiseTimes, phaseSize, placePhase } from "./storyFeed";
import { isAttackEvent } from "./groundTruth";

export type RowKind = "noise" | "story";
export interface ShiftRow {
  kind: RowKind;
  /** A SIEM mirror of the row before it. */
  mirror: boolean;
  /** Index of the story event (story rows and their mirrors). */
  storyIdx?: number;
  attack: boolean;
  event: LiveEvent;
  authoredTs?: string;
  /** Story rows: the placed row before enrichment (what useLiveEvents keeps as the incident's `injected`). */
  placed?: TelemetryEvent;
}
export interface Shift { company: string; difficulty: "easy" | "medium" | "hard"; seed: number; story: AttackStory; rows: ShiftRow[] }

export const COMPANIES = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"] as const;
export const DIFFICULTIES = ["easy", "medium", "hard"] as const;
const SIM = { BENIGN_EVENTS, COMPANY_EVENTS };
const T0 = Date.parse("2026-11-09T09:00:00Z");

function lcg(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 4294967296; };
}

export function playShift(company: string, difficulty: "easy" | "medium" | "hard", seed: number, storyId?: string): Shift {
  const realRandom = Math.random;
  Math.random = lcg(seed * 7919 + company.length * 31 + difficulty.length);
  const realNow = Date.now;
  let clock = T0;
  Date.now = () => clock;
  try {
    const edr = feedCompanyProfile(company).architecture?.edr;
    const cpool = companyFeedPool(SIM, company);
    const picked = storyId
      ? ATTACK_STORIES.find(s => s.id === storyId)!
      : pickStoryForCompany(company, difficulty, st => storyHonoursLocks(instantiateStory(st, cpool, edr, company).events, company));
    const st0 = instantiateStory(picked, cpool, edr, company);
    const story: AttackStory = { ...st0, events: feedStoryEvents(st0.events, company).map(e => applyStack(e, company, {})) };
    const pool = cpool.filter(e => fitsStack(e, company, {})).map(e => applyStack(e, company, {}));
    const adv = story.complexity === "advanced";
    let gi = 15;
    const enrich = (e: TelemetryEvent): LiveEvent => { const le = enrichEvent(e, gi++); if (adv || e.tier === "advanced") injectAdvancedFidelityNoise(le.raw, le); return le; };
    const rows: ShiftRow[] = [];
    const pushNoise = (e: TelemetryEvent) => {
      const le = enrich(e); rows.push({ kind: "noise", mirror: false, attack: false, event: le });
      const m = siemMirror(le, gi++); if (m) rows.push({ kind: "noise", mirror: true, attack: false, event: m });
      return m ? 2 : 1;
    };
    const deck = new NoiseDeck(pool);
    const bf = deck.backfill(15);
    const bft = backfillTimes(bf.length, T0);
    bf.forEach((e, i) => pushNoise(withRebasedTime(e, new Date(bft[i]).toISOString())));
    const sc = newStoryClock();
    let cursor = 0, noiseSince = 0, lastPhaseAt: number | null = null, doneAt = Infinity;
    let nextTick = T0 + 90_000, nextPhase = T0 + 120_000 + Math.floor(Math.random() * 60_000);
    while (clock < doneAt + 300_000 && clock < T0 + 4 * 3600_000) {
      clock = Math.min(nextTick, cursor < story.events.length ? nextPhase : Infinity);
      if (clock === nextTick) {
        nextTick += 90_000;
        const bs = Math.floor(Math.random() * 2) + 1;
        for (let i = 0; i < bs; i++) {
          const ch = deck.next(); if (!ch) continue;
          const [t] = benignTimes([ch.source], clock);
          const k = pushNoise({ ...withRebasedTime(ch, new Date(t).toISOString()), id: `${ch.id}_${clock}_${i}` });
          if (lastPhaseAt !== null) noiseSince += k;
        }
        continue;
      }
      const n = phaseSize(story.events, cursor);
      const placed = placePhase(sc, story.events.slice(cursor, cursor + n), clock).rows;
      let attackRows = 0;
      placed.forEach((e, i) => {
        const inj = { ...e, id: `atk_${story.events[cursor + i].id}_${clock}_${i}` };
        const le = enrich(inj);
        const attack = isAttackEvent(le);
        rows.push({ kind: "story", mirror: false, storyIdx: cursor + i, attack, event: le, authoredTs: story.events[cursor + i].ts, placed: inj });
        const m = siemMirror(le, gi++);
        if (m) rows.push({ kind: "story", mirror: true, storyIdx: cursor + i, attack, event: m });
        if (attack) attackRows += m ? 2 : 1;
      });
      const owed = noiseQuota(attackRows, noiseSince);
      const lead = placed.some(isAttackEvent) ? placed.filter(isAttackEvent) : placed;
      // Never before the first attack row: noise owed for the attack shows while it runs (R8 counts the
      // incident's window from its first row), so a phase newer than a minute does not push it earlier.
      const leadTimes = lead.map(e => Date.parse(e.ts ?? "")).filter(Number.isFinite);
      const firstShown = leadTimes.length ? Math.min(...leadTimes) : clock - 60_000;
      const from = Math.max(lastPhaseAt ?? firstShown, clock - 240_000);
      const nt = noiseTimes(owed, from, clock - 5_000);
      for (let k = 0; k < owed; k++) { const ch = deck.next(); if (!ch) break; pushNoise({ ...withRebasedTime(ch, new Date(nt[k]).toISOString()), id: `${ch.id}_${clock}_q${k}` }); }
      if (attackRows > 0 || lastPhaseAt !== null) { noiseSince = 0; lastPhaseAt = clock; }
      cursor += n;
      if (cursor >= story.events.length) doneAt = clock; else nextPhase = clock + 120_000 + Math.floor(Math.random() * 120_000);
    }
    return { company, difficulty, seed, story, rows };
  } finally {
    Math.random = realRandom;
    Date.now = realNow;
  }
}

/** The row as the feed renders it (the native record), or null when the source has no native module. */
export function nativeOf(row: ShiftRow, company: string) {
  try { return nativeView(row.event, company, {}); } catch { return null; }
}
