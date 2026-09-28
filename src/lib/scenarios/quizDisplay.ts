/**
 * Scenario quiz presentation helpers (team-exercise findings #4 and #15).
 *
 * #4 — the radio/checkbox `value` attributes were the answer ids themselves
 * ("chain", "lsass", "renamed_rclone", "all"): readable in the DOM and, being
 * descriptive, a hint. The page now renders opaque per-load tokens and maps them
 * back to the real option ids only when the answers are submitted. Grading is
 * unchanged — the server still receives, and compares, real option ids.
 *
 * #15 — explanations are authored against the authored option order ("same
 * severity (b) and same vendor (c)…"), but options are shuffled for display
 * (shuffleSeeded). The display order is expressed as `order[display] = original`
 * so the shared room helper `remapOptionLetters` can rewrite the letters to the
 * ones the learner actually saw.
 *
 * Pure; unit-tested in quizDisplay.test.ts.
 */
import type { ScenarioQuestion } from "@/lib/sim/types";
import { shuffleSeeded } from "@/lib/lessons/shuffle";
import { remapOptionLetters } from "@/lib/rooms/shuffle";

type Option = { value: string; label: string };

/** The options in display order — the single place the scenario shuffle happens. */
export function displayedOptions(q: Pick<ScenarioQuestion, "id" | "prompt" | "options">): Option[] {
  return q.options ? shuffleSeeded(q.options, q.id ?? q.prompt) : [];
}

/** `order[displayIndex] = authoredIndex` for the question's displayed options. */
export function optionDisplayOrderFor(q: Pick<ScenarioQuestion, "id" | "prompt" | "options">): number[] {
  const authored = q.options ?? [];
  return displayedOptions(q).map(o => authored.findIndex(a => a.value === o.value));
}

/** "A", "B", … — the letter shown next to the option at `displayIndex`. */
export function optionLetter(displayIndex: number): string {
  return String.fromCharCode(65 + displayIndex);
}

/** Rewrite authored option letters in an explanation to the displayed ones. */
export function remapExplanation(
  text: string | null | undefined,
  q: Pick<ScenarioQuestion, "id" | "prompt" | "options"> | undefined,
): string | null {
  if (!text) return text ?? null;
  if (!q) return text;
  return remapOptionLetters(text, optionDisplayOrderFor(q));
}

// ─── Opaque option tokens ─────────────────────────────────────────────────────

export interface OptionTokenMap {
  /** questionId → (real option value → token). */
  toToken: Map<string, Map<string, string>>;
  /** questionId → (token → real option value). */
  fromToken: Map<string, Map<string, string>>;
}

function randomToken(rand: () => number): string {
  let s = "";
  for (let i = 0; i < 10; i++) s += Math.floor(rand() * 36).toString(36);
  return `o_${s}`;
}

/**
 * A fresh token for every option of every question. Tokens are unique within a
 * question and carry no information about the option. `rand` is injectable for
 * tests; the page uses crypto randomness when available.
 */
export function buildOptionTokens(
  questions: readonly Pick<ScenarioQuestion, "id" | "options">[],
  rand: () => number = Math.random,
): OptionTokenMap {
  const toToken = new Map<string, Map<string, string>>();
  const fromToken = new Map<string, Map<string, string>>();
  for (const q of questions) {
    const to = new Map<string, string>();
    const from = new Map<string, string>();
    for (const o of q.options ?? []) {
      let t = randomToken(rand);
      while (from.has(t)) t = randomToken(rand);
      to.set(o.value, t);
      from.set(t, o.value);
    }
    toToken.set(q.id, to);
    fromToken.set(q.id, from);
  }
  return { toToken, fromToken };
}

/** Crypto-backed [0,1) source for token generation (falls back to Math.random). */
export function cryptoRandom(): number {
  try {
    const buf = new Uint32Array(1);
    globalThis.crypto.getRandomValues(buf);
    return buf[0] / 4294967296;
  } catch {
    return Math.random();
  }
}

/**
 * Token-keyed answers → real option ids, for the grade request. Unknown tokens
 * are dropped (never forwarded), so the server sees exactly what it did before.
 */
export function decodeAnswers(
  answers: Record<string, string | string[]>,
  map: OptionTokenMap,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [qid, a] of Object.entries(answers)) {
    const from = map.fromToken.get(qid);
    if (!from) continue;
    if (Array.isArray(a)) {
      out[qid] = a.map(t => from.get(t)).filter((v): v is string => v !== undefined);
    } else {
      const v = from.get(a);
      if (v !== undefined) out[qid] = v;
    }
  }
  return out;
}
