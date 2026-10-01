/**
 * Is a hex digest an obvious hand-typed placeholder ("A1B2C3D4E5F6789012345678…",
 * "abcdef0123456789…", "deadbeef…" repeated)? Real digests are uniform random hex:
 * a 6-long ascending run, an 8-char block repeated, or a heavily skewed character
 * mix essentially never happens by chance (< 1e-4 per digest).
 */
const RUNS = "0123456789abcdef";
export function isSyntheticHex(h) {
  const s = String(h).toLowerCase();
  if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(s)) return false;
  for (let i = 0; i + 6 <= RUNS.length; i++) {
    const run = RUNS.slice(i, i + 6);
    if (s.includes(run) || s.includes([...run].reverse().join(""))) return true;
  }
  if (/^(?:[a-f]\d){4}/.test(s) || /^(?:\d[a-f]){4}/.test(s)) return true;          // a1b2c3d4… / 1a2b3c4d…
  for (let i = 0; i + 16 <= s.length; i++) { const b = s.slice(i, i + 8); if (s.indexOf(b, i + 8) !== -1) return true; }
  const counts = {}; for (const c of s) counts[c] = (counts[c] ?? 0) + 1;
  const distinct = Object.keys(counts).length, max = Math.max(...Object.values(counts));
  if (distinct < (s.length >= 64 ? 10 : 8) || max / s.length > 0.25) return true;
  if (/(dead|beef|cafe|babe|f00d|c0de|face|feed)/.test(s) && /(dead|beef|cafe|babe|f00d|c0de|face|feed).*(dead|beef|cafe|babe|f00d|c0de|face|feed)/.test(s)) return true;
  return false;
}
