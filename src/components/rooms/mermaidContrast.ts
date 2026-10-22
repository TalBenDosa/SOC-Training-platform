/**
 * Readable node labels in a Mermaid diagram on the dark lesson theme.
 *
 * The theme draws every label in light text (primaryTextColor). A diagram that paints a node
 * with its own fill (`style D fill:#fff3cd`, `classDef warn fill:#f8d7da`) and no text colour
 * kept that light text, so a pale yellow or pink box showed white-on-cream text nobody could
 * read (learner report 2026-10-22, Discovery & Enumeration lesson). Any style / classDef line
 * that sets a fill without a `color` gets the text colour that contrasts with that fill.
 */
const DARK_TEXT = "#0f172a";
const LIGHT_TEXT = "#e2e8f0";

function hexToRgb(hex: string): [number, number, number] | null {
  let h = hex.replace(/^#/, "");
  if (h.length === 3 || h.length === 4) h = h.slice(0, 3).split("").map(c => c + c).join("");
  if (h.length !== 6 && h.length !== 8) return null;
  const n = parseInt(h.slice(0, 6), 16);
  return Number.isFinite(n) ? [(n >> 16) & 255, (n >> 8) & 255, n & 255] : null;
}

/** WCAG relative luminance (0 = black, 1 = white). */
function luminance([r, g, b]: [number, number, number]): number {
  const lin = (c: number) => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** The label colour that reads on a node filled with `fill` (a #hex colour). */
export function textColorFor(fill: string): string | null {
  const rgb = hexToRgb(fill);
  if (!rgb) return null;
  // The point where dark and light text have equal contrast against the fill.
  return luminance(rgb) > 0.179 ? DARK_TEXT : LIGHT_TEXT;
}

/** The chart with a contrasting `color:` added to every style / classDef that sets a fill without one. */
export function withReadableLabels(chart: string): string {
  return chart.replace(/^(\s*(?:style|classDef)\s+\S+\s+)([^\n]*)$/gm, (line, head: string, props: string) => {
    if (/(^|[,;\s])color\s*:/i.test(props)) return line;
    const fill = /(?:^|[,;\s])fill\s*:\s*(#[0-9a-fA-F]{3,8})\b/.exec(props)?.[1];
    const color = fill ? textColorFor(fill) : null;
    if (!color) return line;
    const trimmed = props.replace(/[;\s]+$/, "");
    return `${head}${trimmed},color:${color}`;
  });
}
