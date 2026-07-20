/**
 * Deterministic option shuffling for multiple-choice questions.
 *
 * The problem this solves is positional bias. Measured across the platform's
 * 92 lesson quiz questions, the correct answer sat at:
 *
 *     "b" — 72   "c" — 17   "a" — 3   "d" — 0
 *
 * So a learner who always picked the second option scored 78% without reading
 * a single question, and the fourth option was never once correct. This is not
 * an authoring mistake anyone made on purpose — writers reach for the second
 * slot, and the skew is invisible until you count the whole corpus.
 *
 * Fixing it in the data would mean permuting 92 questions by hand and would do
 * nothing for the next lesson someone writes. Shuffling at render time fixes
 * every question, forever, including AI-generated ones.
 *
 * Deterministic rather than random, seeded by the question text:
 *   - a given question always renders in the same order, so a learner who
 *     revisits it is not disoriented;
 *   - options do not jump under the cursor when React re-renders on selection;
 *   - screenshots, support conversations and bug reports stay reproducible.
 *
 * This is presentation only. Callers MUST grade by comparing the option's
 * `value` to the question's `answer`, never by position — which is what the
 * lesson Quiz already does.
 */

/** FNV-1a — small, fast, well-distributed for short strings. */
function hashString(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** mulberry32 — a compact seeded PRNG with a decent period for this use. */
function seededRandom(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Fisher-Yates over a COPY, driven by a PRNG seeded from `seed`.
 * The input array is never mutated — callers often hold it in props.
 */
export function shuffleSeeded<T>(items: readonly T[], seed: string): T[] {
  const out = items.slice();
  const rand = seededRandom(hashString(seed));
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [out[i], out[j]] = [out[j], out[i]];
  }
  return out;
}
