/**
 * Per-organization themes (white label): the app's colours are CSS variables, so a customer's
 * design can recolour the whole app without touching a component.
 *
 * Tokens (RGB channels, "r g b", so Tailwind's /<alpha> modifiers keep working):
 *  --cyber-50 … --cyber-900   the accent scale (Tailwind `cyber-*`, glows, focus rings)
 *  --bg, --bg-elevated, --bg-panel, --bg-hover   surfaces (Tailwind `bg-bg*`)
 *  --border, --border-strong                     lines (Tailwind `border-border*`)
 * The defaults below are HACK THE SOC's own palette and are also declared in globals.css :root,
 * so the platform looks exactly as before; a theme overrides only the tokens it sets.
 * Isomorphic: no server or React imports.
 */

/** What a customer's design can set (each optional, #rrggbb). */
export interface Theme {
  /** Main accent colour: the whole cyber-50…900 scale is generated from it. */
  accent?: string;
  /** Page background; panels, hover and borders are derived from it. */
  background?: string;
}

export const ACCENT_STEPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900] as const;

/** HACK THE SOC's palette as token values (must match globals.css :root). */
export const DEFAULT_TOKENS: Record<string, string> = {
  "--cyber-50": "236 254 255",
  "--cyber-100": "207 250 254",
  "--cyber-200": "165 243 252",
  "--cyber-300": "103 232 249",
  "--cyber-400": "34 211 238",
  "--cyber-500": "6 182 212",
  "--cyber-600": "8 145 178",
  "--cyber-700": "14 116 144",
  "--cyber-800": "21 94 117",
  "--cyber-900": "22 78 99",
  "--bg": "7 11 20",
  "--bg-elevated": "11 18 32",
  "--bg-panel": "15 23 42",
  "--bg-hover": "19 28 47",
  "--border": "30 41 59",
  "--border-strong": "51 65 85",
};

const HEX = /^#[0-9a-fA-F]{6}$/;

/** A validated theme from stored branding JSON (null when nothing usable is set). */
export function parseTheme(raw: unknown): Theme | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const t: Theme = {};
  if (typeof r.accent === "string" && HEX.test(r.accent)) t.accent = r.accent.toLowerCase();
  if (typeof r.background === "string" && HEX.test(r.background)) t.background = r.background.toLowerCase();
  return t.accent || t.background ? t : null;
}

function hexToRgb(hex: string): [number, number, number] {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function rgbToHsl([r, g, b]: [number, number, number]): [number, number, number] {
  const R = r / 255, G = g / 255, B = b / 255;
  const max = Math.max(R, G, B), min = Math.min(R, G, B), l = (max + min) / 2;
  if (max === min) return [0, 0, l];
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  const h = max === R ? (G - B) / d + (G < B ? 6 : 0) : max === G ? (B - R) / d + 2 : (R - G) / d + 4;
  return [h / 6, s, l];
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  if (s === 0) { const v = Math.round(l * 255); return [v, v, v]; }
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s, p = 2 * l - q;
  const f = (t: number) => {
    if (t < 0) t += 1; if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  return [Math.round(f(h + 1 / 3) * 255), Math.round(f(h) * 255), Math.round(f(h - 1 / 3) * 255)];
}

const ch = (c: [number, number, number]) => c.join(" ");

/** Lightness per accent step, modelled on the default cyan scale (400 = the brand colour). */
const ACCENT_LIGHTNESS: Record<number, number> = { 50: 0.96, 100: 0.91, 200: 0.83, 300: 0.70, 400: 0.53, 500: 0.43, 600: 0.36, 700: 0.31, 800: 0.27, 900: 0.24 };

/** CSS variables for a theme: only the tokens the theme changes. */
export function themeVars(theme: Theme | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!theme) return out;
  if (theme.accent) {
    const [h, s] = rgbToHsl(hexToRgb(theme.accent));
    for (const step of ACCENT_STEPS) {
      out[`--cyber-${step}`] = step === 400 ? ch(hexToRgb(theme.accent)) : ch(hslToRgb(h, Math.min(1, s), ACCENT_LIGHTNESS[step]));
    }
  }
  if (theme.background) {
    const [h, s, l] = rgbToHsl(hexToRgb(theme.background));
    const at = (dl: number) => ch(hslToRgb(h, s, Math.min(1, l + dl)));
    out["--bg"] = ch(hexToRgb(theme.background));
    out["--bg-elevated"] = at(0.03);
    out["--bg-panel"] = at(0.06);
    out["--bg-hover"] = at(0.08);
    out["--border"] = at(0.13);
    out["--border-strong"] = at(0.21);
  }
  return out;
}

/** The same variables as a CSS declaration block (for a server-rendered <style>). */
export function themeCss(theme: Theme | null | undefined): string {
  const vars = themeVars(theme);
  const body = Object.entries(vars).map(([k, v]) => `${k}:${v}`).join(";");
  return body ? `:root{${body}}` : "";
}
