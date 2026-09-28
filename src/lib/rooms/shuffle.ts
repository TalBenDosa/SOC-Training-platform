/**
 * Display-time answer shuffling for Room tasks (feedback FB-002).
 *
 * The problem: authors put the correct option in slot 1 or 2 far more often than
 * slot 3 or 4, so a learner could pass by position instead of by reading. The fix
 * is presentation-only — the SERVER still grades by ORIGINAL option index
 * (`selectedIndex` / `questionIndex`, src/lib/rooms/grading.ts). The client
 * shuffles what it shows, maps the chosen DISPLAY index back to the ORIGINAL index
 * before submitting, and maps any reveal (correct index, original) back to display.
 *
 * Stable per load, fresh per reload: the seed is random per page load
 * (`newShuffleSeed`) combined with the task/question id, so options never jump
 * while the learner is answering, but a reload gives a new order — position can't
 * be memorised across attempts either.
 *
 * Options that talk about OTHER options stay put:
 *  - "All of the above" / "None of the above" / "Both of the above" / "Neither …"
 *    are PINNED to their authored slot; only the remaining options move.
 *  - An option that names other options by letter or number ("Both A and B",
 *    "A and C", "Options 1 and 2") would become wrong once letters move, so a
 *    question containing one is NOT shuffled at all.
 *
 * Pure and dependency-free: imported by client components (TaskPlayer) and by
 * the room page's server-side board scrambler alike.
 */

/** FNV-1a — small, fast, well-distributed for short strings. */
export function hashSeed(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** mulberry32 — a compact seeded PRNG returning floats in [0, 1). */
export function seededRandom(seed: number): () => number {
  let a = seed | 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** A fresh random seed — call once per page load / component mount. */
export function newShuffleSeed(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

/** "All of the above", "None of these", "Both of the above", "Neither of the above"… */
const PINNED_RE =
  /^\s*(?:all|none|both|neither)\b[^.]{0,20}?\b(?:above|these|the options|of them|listed|previous)\b/i;

/** Options that name other options by position: "Both A and B", "A and C", "A, B and D",
 *  "A & B", "Options 1 and 2". Case-SENSITIVE letters so ordinary prose ("a and b") and
 *  tokens like "C2" don't trip it — erring on the side of not shuffling is harmless. */
const LETTER_REF_RE = /(?:^|[\s(])[A-F](?:\s*,\s*[A-F])*\s*(?:and|&|or)\s+[A-F](?=$|[\s).,:;])/;
const NUMBER_REF_RE = /\boptions?\s+\d+\s*(?:,\s*\d+\s*)*(?:and|&|or)\s*\d+\b/i;

export function isPinnedOption(label: string): boolean {
  return PINNED_RE.test(label);
}

export function referencesOtherOptions(label: string): boolean {
  return LETTER_REF_RE.test(label) || NUMBER_REF_RE.test(label);
}

/**
 * Display order for an option list: `order[displayIndex] = originalIndex`.
 * Deterministic for a given (options, seed). Pinned options keep their slot;
 * a question with a position-referencing option is returned in authored order.
 */
export function optionDisplayOrder(options: readonly string[], seed: string): number[] {
  const identity = options.map((_, i) => i);
  if (options.length < 2 || options.some(referencesOtherOptions)) return identity;

  const movable = identity.filter(i => !isPinnedOption(options[i]));
  if (movable.length < 2) return identity;

  // Fold the option texts into the seed: callers pass near-identical seeds
  // ("…:q1", "…:q2"), and near-identical FNV inputs correlate. Mixing in the
  // content decorrelates them without costing determinism.
  const rand = seededRandom(hashSeed(`${seed}\u0001${options.join("\u0001")}`));
  const shuffled = movable.slice();
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }

  const order = identity.slice();
  movable.forEach((slot, k) => { order[slot] = shuffled[k]; });
  return order;
}

/** Display index → original (server) index. */
export function toOriginalIndex(order: readonly number[], displayIndex: number): number {
  return order[displayIndex] ?? -1;
}

/** Original (server) index → display index, or -1 when unknown. */
export function toDisplayIndex(order: readonly number[], originalIndex: number): number {
  return order.indexOf(originalIndex);
}

/**
 * Rewrite option-letter references in an authored explanation ("Option c is
 * wrong", "Options A and D", "(b) is the trap") so they name the letters the
 * learner actually SAW. Authors wrote explanations against the authored order;
 * once options are shuffled those letters would point at the wrong buttons
 * (review of FB-002). Only letters that exist in this question are touched, and
 * the original case is kept. Review mode shows authored order, so it passes the
 * identity order and nothing changes.
 */
export function remapOptionLetters(text: string, order: readonly number[]): string {
  if (!text || order.every((o, i) => o === i)) return text;
  const map = (ch: string): string => {
    const lower = ch.toLowerCase();
    const orig = lower.charCodeAt(0) - 97;
    if (orig < 0 || orig >= order.length) return ch;
    const disp = order.indexOf(orig);
    if (disp < 0) return ch;
    const out = String.fromCharCode(97 + disp);
    return ch === lower ? out : out.toUpperCase();
  };
  return text
    // "option c", "Options A, B and D", "options a & c"
    .replace(/\b([Oo]ptions?)\s+([a-fA-F](?:\s*(?:,|and|&|or)\s*[a-fA-F])*)\b/g,
      (_m, word: string, list: string) => `${word} ${list.replace(/\b[a-fA-F]\b/g, map)}`)
    // "(b)" / "(C)" used as an option label
    .replace(/\(([a-fA-F])\)/g, (_m, ch: string) => `(${map(ch)})`)
    // "Answer B" / "answer b"
    .replace(/\b([Aa]nswer)\s+([a-fA-F])\b/g, (_m, word: string, ch: string) => `${word} ${map(ch)}`);
}

/** Convenience: the option list in display order, each carrying its original index. */
export function displayOptions(
  options: readonly string[],
  seed: string,
): { label: string; srcIdx: number; displayIdx: number }[] {
  return optionDisplayOrder(options, seed).map((srcIdx, displayIdx) => ({
    label: options[srcIdx],
    srcIdx,
    displayIdx,
  }));
}

/** Seeded Fisher–Yates over a copy of any list (e.g. analyst-choice verdict cards). */
export function shuffleWithSeed<T>(items: readonly T[], seed: string): T[] {
  const out = items.slice();
  const rand = seededRandom(hashSeed(seed));
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}

// ─── Matching / ordering boards ────────────────────────────────────────────────

/** How many positions already hold their answer item. */
export function countFixedPoints<K>(presented: readonly K[], answer: readonly K[]): number {
  let n = 0;
  for (let i = 0; i < presented.length; i++) if (presented[i] === answer[i]) n++;
  return n;
}

/**
 * Guarantees a matching/ordering board is NOT presented in (or near) its answer
 * order. The server shuffles these boards randomly, but a random permutation of
 * 4 items is the answer 1 time in 24 — and static rooms are rendered once at
 * build, so that unlucky order would be baked in for every learner.
 *
 * Accepts the current order when it is not the identity and at most half the
 * items sit in their answer slot; otherwise reshuffles (bounded), falling back to
 * a rotation of the answer order (zero items in place).
 */
export function scrambleAwayFromAnswer<T, K>(
  items: readonly T[],
  answer: readonly K[],
  keyOf: (item: T) => K,
  rand: () => number = Math.random,
): T[] {
  const n = items.length;
  if (n < 2 || answer.length !== n) return items.slice();
  const limit = Math.floor(n / 2);
  const ok = (arr: readonly T[]) => {
    const fp = countFixedPoints(arr.map(keyOf), answer);
    return fp < n && fp <= limit;
  };
  if (ok(items)) return items.slice();

  let cur = items.slice();
  for (let attempt = 0; attempt < 100; attempt++) {
    for (let i = n - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [cur[i], cur[j]] = [cur[j], cur[i]];
    }
    if (ok(cur)) return cur;
    cur = cur.slice();
  }
  // Fallback: rotate the answer order by one — no item remains in its slot.
  const byKey = new Map(items.map(it => [keyOf(it), it] as const));
  const rotated = answer.map((_, i) => byKey.get(answer[(i + 1) % n]));
  return rotated.every((x): x is T => x !== undefined) ? rotated : items.slice();
}
