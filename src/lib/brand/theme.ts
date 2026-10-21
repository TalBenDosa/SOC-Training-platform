/**
 * Per-organization themes (white label): every visual decision in the app (colours, font,
 * corner radius, button style) is a CSS variable, so a customer's design restyles the whole
 * app without touching a component. Components only ever use the tokens below (Tailwind
 * `cyber-*`, `bg-bg*`, `border-border*`, `text-on-accent`, `font-sans`, `rounded-*`,
 * `shadow-glow`); nothing hard-codes the platform's look.
 *
 * Tokens:
 *  --cyber-50 … --cyber-900   the accent scale, RGB channels "r g b" (so /<alpha> works)
 *  --bg, --bg-elevated, --bg-panel, --bg-hover   surfaces
 *  --border, --border-strong                     lines
 *  --on-accent                text on an accent-filled control (primary buttons, badges)
 *  --font-sans                the UI font (one of FONTS, loaded by src/app/layout.tsx)
 *  --radius-sm … --radius-2xl corner radius scale (Tailwind rounded-sm … rounded-2xl)
 *  --glow-alpha               strength of the accent glow on buttons and focus (0 = flat)
 * The defaults are HACK THE SOC's own look and are also declared in globals.css :root (a test
 * keeps the two equal), so the platform looks exactly as before; a theme overrides only what
 * it sets. Isomorphic: no server or React imports.
 */

export const FONTS = {
  inter: { label: "Inter", cssVar: "--font-inter" },
  heebo: { label: "Heebo", cssVar: "--font-heebo" },
  rubik: { label: "Rubik", cssVar: "--font-rubik" },
  assistant: { label: "Assistant", cssVar: "--font-assistant" },
} as const;
export type FontKey = keyof typeof FONTS;

export const RADII = {
  sharp: { label: "Sharp", scale: ["0.0625rem", "0.125rem", "0.1875rem", "0.25rem", "0.375rem", "0.5rem"] },
  default: { label: "Standard", scale: ["0.125rem", "0.25rem", "0.375rem", "0.5rem", "0.75rem", "1rem"] },
  round: { label: "Rounded", scale: ["0.25rem", "0.375rem", "0.5rem", "0.75rem", "1rem", "1.5rem"] },
} as const;
export type RadiusKey = keyof typeof RADII;
const RADIUS_STEPS = ["sm", "DEFAULT", "md", "lg", "xl", "2xl"] as const;
const radiusVar = (step: (typeof RADIUS_STEPS)[number]) => (step === "DEFAULT" ? "--radius" : `--radius-${step}`);

export const BUTTON_STYLES = {
  glow: { label: "Glow", glowAlpha: "0.45" },
  flat: { label: "Flat", glowAlpha: "0" },
} as const;
export type ButtonStyleKey = keyof typeof BUTTON_STYLES;

/** What a customer's design can set (each optional). */
export interface Theme {
  /** Main accent colour, #rrggbb: the whole cyber-50…900 scale is generated from it. */
  accent?: string;
  /** Page background, #rrggbb (dark): panels, hover and borders are derived from it. */
  background?: string;
  font?: FontKey;
  radius?: RadiusKey;
  buttons?: ButtonStyleKey;
}

export const ACCENT_STEPS = [50, 100, 200, 300, 400, 500, 600, 700, 800, 900] as const;

/** Text on the accent when nothing else is set: the platform's background (dark on cyan). */
const DARK_INK = "7 11 20";
const LIGHT_INK = "255 255 255";

/** HACK THE SOC's look as token values (must match globals.css :root). */
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
  "--on-accent": DARK_INK,
  "--font-sans": "var(--font-inter)",
  ...Object.fromEntries(RADIUS_STEPS.map((s, i) => [radiusVar(s), RADII.default.scale[i]])),
  "--glow-alpha": BUTTON_STYLES.glow.glowAlpha,
};

/** Ready-made themes the super-admin picks with one click (each passes the contrast checks). */
export const THEME_PRESETS: { id: string; name: string; theme: Theme }[] = [
  { id: "cyber", name: "Cyber (default)", theme: {} },
  { id: "navy", name: "Navy Shield", theme: { accent: "#3b9ae1", background: "#0c1626" } },
  { id: "emerald", name: "Emerald", theme: { accent: "#2dd4bf", background: "#071412" } },
  { id: "royal", name: "Royal", theme: { accent: "#a78bfa", background: "#0f0b1e" } },
  { id: "gold", name: "Gold", theme: { accent: "#f5b83d", background: "#12100b" } },
  { id: "graphite", name: "Graphite", theme: { accent: "#cbd5e1", background: "#0d0f12", buttons: "flat" } },
];

const HEX = /^#[0-9a-fA-F]{6}$/;
const oneOf = <T extends string>(v: unknown, keys: Record<T, unknown>): T | undefined =>
  typeof v === "string" && Object.prototype.hasOwnProperty.call(keys, v) ? (v as T) : undefined;

/** A validated theme from stored branding JSON (null when nothing usable is set). */
export function parseTheme(raw: unknown): Theme | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const t: Theme = {};
  if (typeof r.accent === "string" && HEX.test(r.accent)) t.accent = r.accent.toLowerCase();
  if (typeof r.background === "string" && HEX.test(r.background) && isDarkEnough(r.background)) t.background = r.background.toLowerCase();
  const font = oneOf(r.font, FONTS);
  if (font && font !== "inter") t.font = font;
  const radius = oneOf(r.radius, RADII);
  if (radius && radius !== "default") t.radius = radius;
  const buttons = oneOf(r.buttons, BUTTON_STYLES);
  if (buttons && buttons !== "glow") t.buttons = buttons;
  return Object.keys(t).length ? t : null;
}

type RGB = [number, number, number];

function hexToRgb(hex: string): RGB {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function rgbToHsl([r, g, b]: RGB): RGB {
  const R = r / 255, G = g / 255, B = b / 255;
  const max = Math.max(R, G, B), min = Math.min(R, G, B), l = (max + min) / 2;
  if (max === min) return [0, 0, l];
  const d = max - min;
  const s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
  const h = max === R ? (G - B) / d + (G < B ? 6 : 0) : max === G ? (B - R) / d + 2 : (R - G) / d + 4;
  return [h / 6, s, l];
}

function hslToRgb(h: number, s: number, l: number): RGB {
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

const ch = (c: RGB) => c.join(" ");
const parseCh = (s: string): RGB => s.split(" ").map(Number) as RGB;

/** WCAG relative luminance. */
function luminance([r, g, b]: RGB): number {
  const lin = (c: number) => { const v = c / 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}

/** WCAG contrast ratio between two colours (1 … 21). */
export function contrastRatio(a: RGB | string, b: RGB | string): number {
  const A = luminance(typeof a === "string" ? hexToRgb(a) : a), B = luminance(typeof b === "string" ? hexToRgb(b) : b);
  return (Math.max(A, B) + 0.05) / (Math.min(A, B) + 0.05);
}

/** The app is dark-only for now: light text must stay readable on the background. */
export function isDarkEnough(hex: string): boolean {
  return contrastRatio(hexToRgb(hex), [226, 232, 240]) >= 7;
}

/** Lightness per accent step, modelled on the default cyan scale (400 = the brand colour). */
const ACCENT_LIGHTNESS: Record<number, number> = { 50: 0.96, 100: 0.91, 200: 0.83, 300: 0.70, 400: 0.53, 500: 0.43, 600: 0.36, 700: 0.31, 800: 0.27, 900: 0.24 };

function accentScale(accent: string): Record<string, string> {
  const [h, s] = rgbToHsl(hexToRgb(accent));
  const out: Record<string, string> = {};
  for (const step of ACCENT_STEPS) {
    out[`--cyber-${step}`] = step === 400 ? ch(hexToRgb(accent)) : ch(hslToRgb(h, Math.min(1, s), ACCENT_LIGHTNESS[step]));
  }
  return out;
}

/** Dark or white text, whichever reads better on both accent fills a primary control uses (500, hover 400). */
function onAccent(scale: Record<string, string>): string {
  const fills = [parseCh(scale["--cyber-500"]), parseCh(scale["--cyber-400"])];
  const worst = (ink: RGB) => Math.min(...fills.map(f => contrastRatio(ink, f)));
  return worst(parseCh(DARK_INK)) >= worst(parseCh(LIGHT_INK)) ? DARK_INK : LIGHT_INK;
}

/** CSS variables for a theme: only the tokens the theme changes. */
export function themeVars(theme: Theme | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!theme) return out;
  if (theme.accent) {
    const scale = accentScale(theme.accent);
    Object.assign(out, scale);
    out["--on-accent"] = onAccent(scale);
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
  if (theme.font) out["--font-sans"] = `var(${FONTS[theme.font].cssVar})`;
  if (theme.radius) RADIUS_STEPS.forEach((s, i) => { out[radiusVar(s)] = RADII[theme.radius!].scale[i]; });
  if (theme.buttons) out["--glow-alpha"] = BUTTON_STYLES[theme.buttons].glowAlpha;
  return out;
}

/** The same variables as a CSS declaration block (for a server-rendered <style>). */
export function themeCss(theme: Theme | null | undefined): string {
  const vars = themeVars(theme);
  const body = Object.entries(vars).map(([k, v]) => `${k}:${v}`).join(";");
  return body ? `:root{${body}}` : "";
}

/** A token's final value under a theme ("r g b" channels for colours). */
export function tokenValue(theme: Theme | null | undefined, name: string): string {
  return themeVars(theme)[name] ?? DEFAULT_TOKENS[name];
}

/** A colour token as [r, g, b] (canvas / PDF drawing, which can't read CSS variables). */
export function tokenRgb(theme: Theme | null | undefined, name: string): [number, number, number] {
  return parseCh(tokenValue(theme, name));
}

/** A colour token as an rgba() string for canvas. */
export function tokenRgba(theme: Theme | null | undefined, name: string, alpha: number): string {
  return `rgba(${tokenRgb(theme, name).join(",")},${alpha})`;
}

/** A colour token as #rrggbb (canvas, email and other places that can't read CSS variables). */
export function tokenHex(theme: Theme | null | undefined, name: string): string {
  return "#" + parseCh(tokenValue(theme, name)).map(c => c.toString(16).padStart(2, "0")).join("");
}

/**
 * Readability and meaning checks the super-admin sees before saving (never blocking, except
 * light backgrounds, which parseTheme already refuses).
 */
export function themeWarnings(theme: Theme | null | undefined): string[] {
  const w: string[] = [];
  if (!theme?.accent) return w;
  const bg = parseCh(tokenValue(theme, "--bg"));
  if (contrastRatio(hexToRgb(theme.accent), bg) < 3) w.push("The accent is hard to see on the background (contrast below 3:1). Pick a lighter accent.");
  const [h, s] = rgbToHsl(hexToRgb(theme.accent));
  const deg = h * 360;
  if (s > 0.35 && (deg < 18 || deg > 340)) w.push("A red accent can be confused with Critical / malicious markers.");
  if (s > 0.35 && deg > 85 && deg < 155) w.push("A green accent can be confused with benign / resolved markers.");
  return w;
}
