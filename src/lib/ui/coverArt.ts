/**
 * Generated "cover art" for library cards (Scenarios / Learning Rooms / College
 * Materials). Every item gets an eye-catching hero without anyone sourcing an
 * image — but to avoid the "same concept, different colour" feel, the art is a
 * real little SVG SCENE picked from several genuinely different composition
 * families (isometric cubes, radar, network graph, waves, hex grid, data bars,
 * orbits, perspective grid). Both the family and its layout are chosen from a
 * stable hash of the item's seed, so the same item always looks the same and a
 * wall of cards reads as a diverse, intentional gallery.
 */

export type CoverArt = {
  /** `url("data:image/svg+xml,…")` — set as the hero's background-image. */
  dataUri: string;
  /** Accent hex (the lighter of the two palette colours). */
  accent: string;
  /** Which scene family was chosen (for debugging / analytics). */
  family: string;
};

// Curated two-stop palettes — vivid but tasteful.
const PALETTES: Array<[string, string]> = [
  ["#0ea5e9", "#4f46e5"], // sky → indigo
  ["#7c3aed", "#db2777"], // violet → fuchsia
  ["#f59e0b", "#e11d48"], // amber → rose
  ["#10b981", "#0ea5e9"], // emerald → sky
  ["#6366f1", "#38bdf8"], // indigo → sky
  ["#f43f5e", "#fb923c"], // rose → orange
  ["#a855f7", "#22d3ee"], // purple → cyan
  ["#3b82f6", "#22d3ee"], // blue → cyan
  ["#ec4899", "#8b5cf6"], // pink → violet
  ["#14b8a6", "#84cc16"], // teal → lime
];

/** Stable 32-bit hash → also the PRNG seed. */
function hash(seed: string): number {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) { h ^= seed.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
/** Tiny deterministic PRNG (mulberry32) so scene layouts vary but are stable. */
function rng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const W = 400, H = 225; // 16:9 canvas

// ── Scene families. Each returns SVG markup drawn over the gradient base. ──────
type Scene = (r: () => number, c1: string, c2: string) => string;
const pick = <T,>(r: () => number, arr: T[]) => arr[Math.floor(r() * arr.length)];
const n = (x: number) => Math.round(x * 10) / 10;

const cubes: Scene = (r, c1, c2) => {
  let s = "";
  const count = 7 + Math.floor(r() * 6);
  for (let i = 0; i < count; i++) {
    const x = n(30 + r() * 340), y = n(30 + r() * 165), u = n(14 + r() * 20);
    const top = `${x},${y} ${x + u},${y - u * 0.5} ${x + 2 * u},${y} ${x + u},${y + u * 0.5}`;
    const left = `${x},${y} ${x + u},${y + u * 0.5} ${x + u},${y + u * 1.7} ${x},${y + u * 1.2}`;
    const right = `${x + 2 * u},${y} ${x + u},${y + u * 0.5} ${x + u},${y + u * 1.7} ${x + 2 * u},${y + u * 1.2}`;
    s += `<polygon points='${top}' fill='#fff' opacity='0.9'/><polygon points='${left}' fill='#000' opacity='0.28'/><polygon points='${right}' fill='#000' opacity='0.14'/>`;
  }
  return s;
};

const radar: Scene = (r) => {
  const cx = n(120 + r() * 160), cy = n(90 + r() * 60);
  let s = "";
  for (let i = 1; i <= 4; i++) s += `<circle cx='${cx}' cy='${cy}' r='${i * 26}' fill='none' stroke='#fff' stroke-width='1.3' opacity='${0.5 - i * 0.07}'/>`;
  const a = r() * Math.PI * 2;
  s += `<path d='M${cx} ${cy} L${n(cx + Math.cos(a) * 104)} ${n(cy + Math.sin(a) * 104)} A104 104 0 0 1 ${n(cx + Math.cos(a + 0.6) * 104)} ${n(cy + Math.sin(a + 0.6) * 104)} Z' fill='#fff' opacity='0.16'/>`;
  s += `<line x1='${cx - 108}' y1='${cy}' x2='${cx + 108}' y2='${cy}' stroke='#fff' stroke-width='0.8' opacity='0.25'/><line x1='${cx}' y1='${cy - 108}' x2='${cx}' y2='${cy + 108}' stroke='#fff' stroke-width='0.8' opacity='0.25'/>`;
  for (let i = 0; i < 4; i++) s += `<circle cx='${n(cx + (r() - 0.5) * 180)}' cy='${n(cy + (r() - 0.5) * 130)}' r='3' fill='#fff' opacity='0.9'/>`;
  return s;
};

const network: Scene = (r) => {
  const pts = Array.from({ length: 8 + Math.floor(r() * 4) }, () => [n(30 + r() * 340), n(25 + r() * 175)]);
  let s = "";
  for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
    if (r() > 0.72) s += `<line x1='${pts[i][0]}' y1='${pts[i][1]}' x2='${pts[j][0]}' y2='${pts[j][1]}' stroke='#fff' stroke-width='1' opacity='0.28'/>`;
  }
  for (const [x, y] of pts) s += `<circle cx='${x}' cy='${y}' r='${n(3 + r() * 5)}' fill='#fff' opacity='0.92'/>`;
  return s;
};

const waves: Scene = (r) => {
  let s = "";
  for (let i = 0; i < 5; i++) {
    const y = 60 + i * 34 + r() * 12;
    const k = 20 + r() * 26;
    s += `<path d='M0 ${n(y)} C 100 ${n(y - k)}, 300 ${n(y + k)}, 400 ${n(y)} L400 225 L0 225 Z' fill='#fff' opacity='${0.05 + i * 0.03}'/>`;
  }
  return s;
};

const hexgrid: Scene = (r, c1) => {
  let s = "";
  const R = 20, dx = R * 1.5, dy = R * Math.sqrt(3);
  for (let col = 0; col < 10; col++) for (let row = 0; row < 5; row++) {
    const cx = col * dx + 20, cy = row * dy + (col % 2 ? dy / 2 : 0) + 20;
    const pts = Array.from({ length: 6 }, (_, k) => `${n(cx + R * Math.cos((k * 60 - 30) * Math.PI / 180))},${n(cy + R * Math.sin((k * 60 - 30) * Math.PI / 180))}`).join(" ");
    const fill = r() > 0.78;
    s += `<polygon points='${pts}' fill='${fill ? "#fff" : "none"}' fill-opacity='0.85' stroke='#fff' stroke-width='0.8' opacity='${fill ? 0.9 : 0.22}'/>`;
  }
  return s;
};

const bars: Scene = (r) => {
  let s = "";
  const count = 14, bw = 18;
  for (let i = 0; i < count; i++) {
    const h = 30 + r() * 150;
    s += `<rect x='${n(14 + i * (bw + 8))}' y='${n(H - 20 - h)}' width='${bw}' height='${n(h)}' rx='3' fill='#fff' opacity='${0.35 + r() * 0.5}'/>`;
  }
  return s;
};

const orbits: Scene = (r) => {
  const cx = n(140 + r() * 120), cy = n(90 + r() * 50);
  let s = `<circle cx='${cx}' cy='${cy}' r='10' fill='#fff' opacity='0.95'/>`;
  for (let i = 1; i <= 3; i++) {
    const rx = 40 + i * 34, ry = (40 + i * 34) * (0.4 + r() * 0.2), rot = n(r() * 180);
    s += `<ellipse cx='${cx}' cy='${cy}' rx='${n(rx)}' ry='${n(ry)}' fill='none' stroke='#fff' stroke-width='1.1' opacity='0.3' transform='rotate(${rot} ${cx} ${cy})'/>`;
    const a = r() * Math.PI * 2;
    s += `<circle cx='${n(cx + Math.cos(a) * rx)}' cy='${n(cy + Math.sin(a) * ry)}' r='4' fill='#fff' opacity='0.9' transform='rotate(${rot} ${cx} ${cy})'/>`;
  }
  return s;
};

const perspective: Scene = (r) => {
  const vx = n(120 + r() * 160), vy = 96;
  let s = "";
  for (let i = -6; i <= 6; i++) s += `<line x1='${n(vx + i * 16)}' y1='${vy}' x2='${n(vx + i * 90)}' y2='225' stroke='#fff' stroke-width='0.9' opacity='0.25'/>`;
  for (let i = 1; i <= 7; i++) { const y = vy + i * i * 2.4; s += `<line x1='0' y1='${n(y)}' x2='400' y2='${n(y)}' stroke='#fff' stroke-width='0.9' opacity='${0.28 - i * 0.03}'/>`; }
  s += `<circle cx='${vx}' cy='${vy}' r='26' fill='#fff' opacity='0.18'/>`;
  return s;
};

const FAMILIES: Array<[string, Scene]> = [
  ["cubes", cubes], ["radar", radar], ["network", network], ["waves", waves],
  ["hexgrid", hexgrid], ["bars", bars], ["orbits", orbits], ["perspective", perspective],
];

export function coverArt(seed: string, familyOffset = 0): CoverArt {
  const h = hash(seed || "seed");
  const r = rng(h);
  // NB: unsigned shifts (>>>). A signed `>>` on a hash ≥ 2^31 yields a negative
  // number, and `negative % len` is negative in JS → an out-of-range index.
  // familyOffset lets a list rotate the scene family by card position so a page
  // never clusters on one composition; the palette still comes from the hash.
  const [c1, c2] = PALETTES[h % PALETTES.length];
  const [family, scene] = FAMILIES[(((h >>> 5) + familyOffset) % FAMILIES.length + FAMILIES.length) % FAMILIES.length];
  const angle = 110 + ((h >>> 3) % 5) * 15;
  const svg =
    `<svg xmlns='http://www.w3.org/2000/svg' width='${W}' height='${H}' viewBox='0 0 ${W} ${H}'>` +
    `<defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1' gradientTransform='rotate(${angle - 135} .5 .5)'>` +
    `<stop offset='0' stop-color='${c1}'/><stop offset='1' stop-color='${c2}'/></linearGradient></defs>` +
    `<rect width='${W}' height='${H}' fill='url(#g)'/>` +
    `<g>${scene(r, c1, c2)}</g>` +
    // gentle vignette so the type badge and title edge stay legible
    `<rect width='${W}' height='${H}' fill='url(#g)' opacity='0'/>` +
    `<rect width='${W}' height='90' y='${H - 90}' fill='#000' opacity='0.20'/>` +
    `</svg>`;
  // Parentheses from transform="rotate(...)" / arc commands are NOT escaped by
  // encodeURIComponent and would prematurely close the CSS `url(...)`, blanking
  // the hero — so escape them too.
  const encoded = encodeURIComponent(svg).replace(/\(/g, "%28").replace(/\)/g, "%29");
  const dataUri = `url("data:image/svg+xml,${encoded}")`;
  return { dataUri, accent: c2, family };
}
