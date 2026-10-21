"use client";
/**
 * The theme part of a tenant config (src/lib/brand/theme.ts): ready-made presets, the two
 * colours, font, corner radius and button style, with readability warnings and a live
 * preview. The preview sets the same CSS variables on its own box that the real app sets on
 * the page, so what it shows is exactly what the organization's members will see.
 */
import { useState } from "react";
import { Wand2 } from "lucide-react";
import {
  BUTTON_STYLES, FONTS, RADII, THEME_PRESETS, contrastRatio, isDarkEnough, themeVars, themeWarnings,
  type ButtonStyleKey, type FontKey, type RadiusKey, type Theme,
} from "@/lib/brand/theme";

const DEFAULT_ACCENT = "#22d3ee";
const DEFAULT_BG = "#070b14";

const label = "mb-1.5 block text-xs font-semibold text-slate-400";
const select = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white focus:border-cyber-500/50 focus:outline-none";

/** The logo's most vivid colour, lifted so it reads on a dark background (null = none found). */
async function accentFromLogo(src: string): Promise<string | null> {
  const img = new Image();
  img.src = src;
  await img.decode();
  const c = document.createElement("canvas");
  c.width = c.height = 64;
  const ctx = c.getContext("2d");
  if (!ctx) return null;
  ctx.drawImage(img, 0, 0, 64, 64);
  const px = ctx.getImageData(0, 0, 64, 64).data;
  const buckets = new Map<number, { w: number; r: number; g: number; b: number }>();
  for (let i = 0; i < px.length; i += 4) {
    const [r, g, b, a] = [px[i], px[i + 1], px[i + 2], px[i + 3]];
    if (a < 128) continue;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    const sat = max === 0 ? 0 : (max - min) / max;
    if (sat < 0.25 || max < 50) continue; // greys, black and white say nothing about the brand
    const hue = Math.round((Math.atan2(Math.sqrt(3) * (g - b), 2 * r - g - b) * 180) / Math.PI / 15);
    const e = buckets.get(hue) ?? { w: 0, r: 0, g: 0, b: 0 };
    e.w += sat; e.r += r * sat; e.g += g * sat; e.b += b * sat;
    buckets.set(hue, e);
  }
  const best = [...buckets.values()].sort((x, y) => y.w - x.w)[0];
  if (!best) return null;
  let rgb = [best.r / best.w, best.g / best.w, best.b / best.w];
  // Lighten toward white until the accent clears 4.5:1 on the platform background.
  for (let k = 0; k < 12 && contrastRatio(rgb.map(Math.round) as [number, number, number], DEFAULT_BG) < 4.5; k++) {
    rgb = rgb.map(v => v + (255 - v) * 0.12);
  }
  return "#" + rgb.map(v => Math.round(v).toString(16).padStart(2, "0")).join("");
}

export function ThemeEditor({ theme, onChange, logoSrc, productName, logoHasName }: {
  theme: Theme;
  onChange: (t: Theme) => void;
  logoSrc: string | null;
  productName: string;
  logoHasName: boolean;
}) {
  const [suggestError, setSuggestError] = useState<string | null>(null);
  const set = (patch: Partial<Theme>) => onChange({ ...theme, ...patch });
  const warnings = themeWarnings(theme);
  const bgTooLight = !!theme.background && !isDarkEnough(theme.background);
  const activePreset = THEME_PRESETS.find(p =>
    (p.theme.accent ?? null) === (theme.accent ?? null) && (p.theme.background ?? null) === (theme.background ?? null));

  async function suggest() {
    setSuggestError(null);
    if (!logoSrc) { setSuggestError("Upload a logo first."); return; }
    try {
      const hex = await accentFromLogo(logoSrc);
      if (hex) set({ accent: hex });
      else setSuggestError("The logo has no clear colour to use. Pick one by hand.");
    } catch { setSuggestError("Couldn't read the logo. Pick a colour by hand."); }
  }

  return (
    <div className="space-y-4">
      {/* Presets */}
      <div>
        <p className={label}>Ready-made themes</p>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
          {THEME_PRESETS.map(p => {
            const a = p.theme.accent ?? DEFAULT_ACCENT, b = p.theme.background ?? DEFAULT_BG;
            const on = activePreset?.id === p.id;
            return (
              <button key={p.id} type="button" aria-pressed={on}
                onClick={() => onChange({ ...theme, accent: p.theme.accent, background: p.theme.background, buttons: p.theme.buttons ?? theme.buttons })}
                className={`flex items-center gap-2 rounded-md border px-2.5 py-2 text-left text-xs font-semibold transition ${on ? "border-cyber-400 text-white" : "border-border text-slate-300 hover:border-border-strong"}`}>
                <span className="flex h-6 w-10 shrink-0 overflow-hidden rounded border border-white/10" aria-hidden="true">
                  <span className="h-full w-1/2" style={{ background: b }} />
                  <span className="h-full w-1/2" style={{ background: a }} />
                </span>
                {p.name}
              </button>
            );
          })}
        </div>
      </div>

      {/* Custom */}
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className={label} htmlFor="th-accent">Accent colour</label>
          <div className="flex items-center gap-2">
            <input id="th-accent" type="color" className="h-10 w-14 cursor-pointer rounded-md border border-border bg-bg" value={theme.accent ?? DEFAULT_ACCENT} onChange={e => set({ accent: e.target.value })} />
            <code className="font-mono text-xs text-slate-300">{theme.accent ?? "default"}</code>
            <button type="button" onClick={suggest} className="ml-auto inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-[11px] font-semibold text-slate-300 hover:border-cyber-500/50 hover:text-white">
              <Wand2 className="h-3 w-3" aria-hidden="true" /> From logo
            </button>
          </div>
          {suggestError && <p className="mt-1 text-[11px] text-neon-amber" role="alert">{suggestError}</p>}
        </div>
        <div>
          <label className={label} htmlFor="th-bg">Background <span className="font-normal">(dark)</span></label>
          <div className="flex items-center gap-2">
            <input id="th-bg" type="color" className="h-10 w-14 cursor-pointer rounded-md border border-border bg-bg" value={theme.background ?? DEFAULT_BG} onChange={e => set({ background: e.target.value })} />
            <code className="font-mono text-xs text-slate-300">{theme.background ?? "default"}</code>
          </div>
          {bgTooLight && <p className="mt-1 text-[11px] text-neon-amber" role="alert">Too light: the app is dark-only, so pick a darker background.</p>}
        </div>
        <div>
          <label className={label} htmlFor="th-font">Font</label>
          <select id="th-font" className={select} value={theme.font ?? "inter"} onChange={e => set({ font: e.target.value as FontKey })}>
            {(Object.keys(FONTS) as FontKey[]).map(k => <option key={k} value={k}>{FONTS[k].label}{k === "inter" ? " (default)" : ""}</option>)}
          </select>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={label} htmlFor="th-radius">Corners</label>
            <select id="th-radius" className={select} value={theme.radius ?? "default"} onChange={e => set({ radius: e.target.value as RadiusKey })}>
              {(Object.keys(RADII) as RadiusKey[]).map(k => <option key={k} value={k}>{RADII[k].label}</option>)}
            </select>
          </div>
          <div>
            <label className={label} htmlFor="th-buttons">Buttons</label>
            <select id="th-buttons" className={select} value={theme.buttons ?? "glow"} onChange={e => set({ buttons: e.target.value as ButtonStyleKey })}>
              {(Object.keys(BUTTON_STYLES) as ButtonStyleKey[]).map(k => <option key={k} value={k}>{BUTTON_STYLES[k].label}</option>)}
            </select>
          </div>
        </div>
      </div>

      {warnings.length > 0 && (
        <ul className="space-y-1 rounded-md border border-neon-amber/30 bg-neon-amber/5 px-3 py-2 text-[11px] text-neon-amber">
          {warnings.map(w => <li key={w}>{w}</li>)}
        </ul>
      )}

      {/* Live preview: the theme's variables on this box only. */}
      <div>
        <p className={label}>Preview</p>
        <div style={themeVars(theme) as React.CSSProperties} className="overflow-hidden rounded-xl border border-border bg-bg font-sans">
          <div className="flex">
            <div className="w-40 shrink-0 border-r border-border bg-bg-elevated p-3">
              <div className="mb-3 flex items-center gap-2">
                {logoSrc
                  // eslint-disable-next-line @next/next/no-img-element -- same-origin / data URL preview
                  ? <img src={logoSrc} alt="" className="h-7 max-w-[90px] object-contain" />
                  : null}
                {!(logoSrc && logoHasName) && <span className="truncate text-xs font-bold text-white">{productName}</span>}
              </div>
              <div className="rounded-md bg-cyber-400/10 px-2 py-1.5 text-[11px] font-medium text-cyber-300">Learning Rooms</div>
              <div className="px-2 py-1.5 text-[11px] text-slate-300">SOC Dashboard</div>
              <div className="px-2 py-1.5 text-[11px] text-slate-300">Scenarios</div>
            </div>
            <div className="flex-1 space-y-3 p-4">
              <div className="rounded-lg border border-border bg-bg-panel p-3">
                <p className="text-sm font-semibold text-white">Phishing triage</p>
                <p className="mt-0.5 text-[11px] text-slate-400">Room 4 of 12 · 3 tasks left</p>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-bg-hover"><div className="h-full w-2/3 rounded-full bg-cyber-400" /></div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex h-8 items-center rounded-md bg-cyber-500 px-3 text-xs font-semibold text-on-accent shadow-glow">Continue</span>
                <span className="inline-flex h-8 items-center rounded-md border border-cyber-500/40 px-3 text-xs font-semibold text-cyber-300">Review</span>
                <span className="rounded bg-severity-critical/15 px-1.5 py-0.5 text-[10px] font-bold text-severity-critical">CRITICAL</span>
                <span className="rounded bg-neon-green/10 px-1.5 py-0.5 text-[10px] font-bold text-neon-green">BENIGN</span>
              </div>
            </div>
          </div>
        </div>
        <button type="button" onClick={() => onChange({})} className="mt-2 text-[11px] text-slate-400 underline underline-offset-2 hover:text-slate-200">Reset to the platform look</button>
      </div>
    </div>
  );
}
