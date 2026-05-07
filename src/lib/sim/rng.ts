/**
 * Deterministic seeded RNG so generated logs are stable across renders.
 * Mulberry32 — small, fast, good distribution for non-crypto use.
 */
export function rng(seed: number) {
  let s = seed >>> 0;
  return function next() {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function hashString(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  }
  return h >>> 0;
}

export const pick = <T,>(r: () => number, arr: readonly T[]): T => arr[Math.floor(r() * arr.length)];
export const pickN = <T,>(r: () => number, arr: readonly T[], n: number): T[] => {
  const c = [...arr];
  const out: T[] = [];
  for (let i = 0; i < n && c.length; i++) out.push(c.splice(Math.floor(r() * c.length), 1)[0]);
  return out;
};
export const intBetween = (r: () => number, a: number, b: number) => Math.floor(r() * (b - a + 1)) + a;
