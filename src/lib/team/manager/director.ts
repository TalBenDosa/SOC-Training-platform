/**
 * The SOC-Manager incident director: given the live session state, decide whether a decision
 * card should fire now, and build it. Pure, so the route and the tests share it.
 *
 * Pacing (research: NIST 800-84 "keep participants occupied but not overwhelmed"; 4-6 manager
 * injects per round): one open card at a time, at least CARD_SPACING_MS between cards, a
 * budget per difficulty, and nothing before the team's first escalation (before that the
 * manager has nothing to manage).
 */
import { shuffleWithSeed } from "@/lib/rooms/shuffle";
import type { MgrState } from "./state";
import { CARDS, CARD_BY_ID, difficultyAllows, type CardDef, type Ctx, type Delta, type Indicators, type Rank } from "./cards";

export const CARD_BUDGET = { easy: 2, medium: 4, hard: 6 } as const;
export const CARD_SPACING_MS = 180_000;

export function pickCard(s: MgrState): { def: CardDef; ctx: Ctx } | null {
  if (!s.manager) return null;                                         // nobody to answer
  if (s.firstEscalationMs == null) return null;                        // nothing to manage yet
  if (s.cards.length >= CARD_BUDGET[s.difficulty]) return null;
  if (s.cards.some(c => !c.answered && !c.expired)) return null;       // one at a time
  const last = s.cards.reduce((m, c) => Math.max(m, c.atMs), 0);
  if (last && s.nowMs - last < CARD_SPACING_MS) return null;
  const done = new Set(s.cards.map(c => c.card));
  const lastAudience = s.cards.length ? CARD_BY_ID.get(s.cards[s.cards.length - 1].card)?.audience : undefined;
  const eligible: { def: CardDef; ctx: Ctx }[] = [];
  for (const def of CARDS) {
    if (done.has(def.id) || !difficultyAllows(def, s.difficulty)) continue;
    const ctx = def.when(s);
    if (ctx) eligible.push({ def, ctx });
  }
  if (!eligible.length) return null;
  // Highest priority; on a tie prefer the other audience than the last card (variety).
  eligible.sort((a, b) => b.def.priority - a.def.priority
    || Number(a.def.audience === lastAudience) - Number(b.def.audience === lastAudience));
  return eligible[0];
}

export interface CardPublicBody {
  audience: "external" | "internal";
  pillar: string;
  from: { name: string; role: string };
  channel: string;
  text: string;
  options: { id: string; label: string }[];
  deadline_s: number;
  /** The containment request a card is about (decided under Escalations): links the two. */
  about?: { target: string };
}
export interface CardAnswerKey {
  card: string;
  ranks: Record<string, Rank>;
  notes: Record<string, string>;
  deltas: Record<string, Delta>;
  best: string;
  timeout_delta: Delta;
  objective: string;
  context: Ctx;
  /** Option id → the critical error that choice is (only flagged options). */
  critical?: Record<string, string>;
}

/** Build the public body and the server-only answer key. Option ids and order are seeded per session. */
export function materialize(def: CardDef, ctx: Ctx, s: MgrState, seed: string): { body: CardPublicBody; answer: CardAnswerKey } {
  const b = def.build(ctx, s);
  const shuffled = shuffleWithSeed(b.options, `${seed}:${def.id}`);
  const ids = shuffleWithSeed(["o1", "o2", "o3", "o4", "o5"].slice(0, shuffled.length), `${seed}:${def.id}:ids`);
  const ranks: Record<string, Rank> = {}, notes: Record<string, string> = {}, deltas: Record<string, Delta> = {}, critical: Record<string, string> = {};
  let best = "";
  const options = shuffled.map((o, i) => {
    const id = ids[i];
    ranks[id] = o.rank; notes[id] = o.note; deltas[id] = o.delta ?? {};
    if (o.critical) critical[id] = o.critical;
    if (o.rank === "great") best = id;
    return { id, label: o.label };
  });
  return {
    body: { audience: def.audience, pillar: def.pillar, from: b.from, channel: b.channel, text: b.text, options, deadline_s: b.deadlineS,
      ...((def.id === "isolate_or_wait" || def.id === "owner_veto") && ctx.target ? { about: { target: ctx.target } } : {}) },
    answer: { card: def.id, ranks, notes, deltas, best, timeout_delta: b.timeoutDelta, objective: b.objective, context: ctx, ...(Object.keys(critical).length ? { critical } : {}) },
  };
}

// ── Consequence indicators and card scores ───────────────────────────────────

export const INDICATOR_START = 3;
export const INDICATOR_MAX = 5;
const clampInd = (v: number) => Math.max(0, Math.min(INDICATOR_MAX, v));

/** Indicators after the decided/expired cards, in firing order (start 3 each, 0-5). */
export function indicatorsAfter(cards: { answer: CardAnswerKey; option: string | null }[]): Indicators {
  const ind: Indicators = { continuity: INDICATOR_START, trust: INDICATOR_START, capacity: INDICATOR_START, regulatory: INDICATOR_START };
  for (const c of cards) {
    const d = c.option ? c.answer.deltas[c.option] ?? {} : c.answer.timeout_delta;
    for (const k of Object.keys(ind) as (keyof Indicators)[]) ind[k] = clampInd(ind[k] + (d[k] ?? 0));
  }
  return ind;
}

/** Confidence-calibrated 0-12 score of one decision (overconfident weak calls score lowest). */
export const CARD_SCORE: Record<Rank, Record<"low" | "medium" | "high", number>> = {
  great: { low: 10, medium: 11, high: 12 },
  good: { low: 8, medium: 8, high: 8 },
  okay: { low: 5, medium: 4, high: 3 },
  weak: { low: 2, medium: 1, high: 0 },
};
export function cardScore(rank: Rank | undefined, confidence: string | undefined): number {
  if (!rank) return 0;                                                 // not decided in time
  const c = confidence === "low" || confidence === "high" ? confidence : "medium";
  return CARD_SCORE[rank][c];
}
