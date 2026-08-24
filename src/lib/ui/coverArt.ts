/**
 * Deterministic "cover art" for library cards (Scenarios / Learning Rooms /
 * College Materials). Every item gets a distinctive, eye-catching hero without
 * anyone sourcing an image: a curated gradient + motif is chosen from a stable
 * hash of the item's seed (slug/id), so the same item always looks the same and
 * a wall of cards reads as an intentional, colourful gallery.
 *
 * Colours are returned as raw hex and applied via inline `style` — Tailwind
 * can't tree-shake class names built at runtime, so dynamic gradients must not
 * go through utility classes.
 */

export type CoverArt = {
  /** CSS `background` value: a layered radial highlight over a diagonal gradient. */
  background: string;
  /** Accent hex — used for the motif tint and glows. */
  accent: string;
  /** Decorative overlay motif. */
  pattern: "grid" | "dots" | "rings" | "diagonals";
  /** Degrees to rotate the oversized background icon, for variety. */
  iconRotate: number;
};

// Curated two-stop palettes — rich but legible under a dark scrim, on-brand.
const PALETTES: Array<[string, string]> = [
  ["#06b6d4", "#4f46e5"], // teal → indigo
  ["#7c3aed", "#db2777"], // violet → fuchsia
  ["#f59e0b", "#e11d48"], // amber → rose
  ["#10b981", "#0ea5e9"], // emerald → sky
  ["#4f46e5", "#38bdf8"], // indigo → sky
  ["#f43f5e", "#fb923c"], // rose → orange
  ["#a855f7", "#22d3ee"], // purple → cyan
  ["#3b82f6", "#10b981"], // blue → emerald
  ["#ec4899", "#8b5cf6"], // pink → violet
  ["#0ea5e9", "#14b8a6"], // sky → teal
];

const PATTERNS: CoverArt["pattern"][] = ["grid", "dots", "rings", "diagonals"];

/** Stable 32-bit string hash (FNV-1a-ish) — same seed → same art across renders. */
function hash(seed: string): number {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

export function coverArt(seed: string): CoverArt {
  const h = hash(seed || "seed");
  const [c1, c2] = PALETTES[h % PALETTES.length];
  const pattern = PATTERNS[(h >> 8) % PATTERNS.length];
  const angle = 110 + ((h >> 4) % 5) * 15; // 110–170deg
  const iconRotate = -18 + ((h >> 12) % 5) * 9; // -18..18
  const background =
    `radial-gradient(120% 120% at 22% 18%, ${c1}dd 0%, transparent 55%),` +
    `radial-gradient(120% 120% at 85% 90%, ${c2}cc 0%, transparent 55%),` +
    `linear-gradient(${angle}deg, ${c1} 0%, ${c2} 100%)`;
  return { background, accent: c1, pattern, iconRotate };
}

/** A faint SVG-data-URI overlay for the chosen motif (white, low opacity). */
export function patternOverlay(pattern: CoverArt["pattern"]): string {
  const svg = {
    grid: `<path d='M0 20H40M20 0V40' stroke='white' stroke-width='1'/>`,
    dots: `<circle cx='6' cy='6' r='1.6' fill='white'/>`,
    rings: `<circle cx='20' cy='20' r='14' fill='none' stroke='white' stroke-width='1.4'/>`,
    diagonals: `<path d='M-4 12L12 -4M0 40L40 0M28 44L44 28' stroke='white' stroke-width='1.2'/>`,
  }[pattern];
  const tile = pattern === "dots" ? 12 : 40;
  const doc = `<svg xmlns='http://www.w3.org/2000/svg' width='${tile}' height='${tile}' viewBox='0 0 ${tile} ${tile}'>${svg}</svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(doc)}")`;
}
