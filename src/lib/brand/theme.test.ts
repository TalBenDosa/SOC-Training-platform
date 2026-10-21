import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ACCENT_STEPS, DEFAULT_TOKENS, THEME_PRESETS, contrastRatio, parseTheme, themeCss, themeVars, themeWarnings, tokenHex } from "./theme";
import { brandFromOrg, PLATFORM_BRAND } from "./brand";
import { sanitizeBranding } from "./sanitize";

describe("theme tokens", () => {
  it("globals.css :root declares exactly the default palette (the platform's look is unchanged)", () => {
    const css = readFileSync(join(process.cwd(), "src", "app", "globals.css"), "utf8");
    for (const [name, value] of Object.entries(DEFAULT_TOKENS)) {
      const m = new RegExp(`${name.replace(/[-]/g, "\\-")}:\\s*([^;]+);`).exec(css);
      expect(m?.[1].trim(), name).toBe(value);
    }
  });

  it("an accent colour becomes a full 50-900 scale, with 400 = the colour itself", () => {
    const vars = themeVars({ accent: "#f59e0b" });
    expect(Object.keys(vars)).toEqual([...ACCENT_STEPS.map(s => `--cyber-${s}`), "--on-accent"]);
    expect(vars["--cyber-400"]).toBe("245 158 11");
    // lighter steps are lighter than darker ones
    const sum = (v: string) => v.split(" ").map(Number).reduce((a, b) => a + b, 0);
    expect(sum(vars["--cyber-50"])).toBeGreaterThan(sum(vars["--cyber-400"]));
    expect(sum(vars["--cyber-400"])).toBeGreaterThan(sum(vars["--cyber-900"]));
  });

  it("a background colour sets the surfaces and borders", () => {
    const vars = themeVars({ background: "#101828" });
    expect(vars["--bg"]).toBe("16 24 40");
    expect(Object.keys(vars).sort()).toEqual(["--bg", "--bg-elevated", "--bg-hover", "--bg-panel", "--border", "--border-strong"]);
  });

  it("no theme, no variables (nothing overrides the platform)", () => {
    expect(themeVars(null)).toEqual({});
    expect(themeCss(undefined)).toBe("");
    expect(themeCss({ accent: "#f59e0b" }).startsWith(":root{--cyber-50:")).toBe(true);
  });

  it("only valid colours are accepted, from storage and from the super-admin", () => {
    expect(parseTheme({ accent: "#F59E0B", background: "red" })).toEqual({ accent: "#f59e0b" });
    expect(parseTheme({ accent: "url(x)" })).toBeNull();
    expect(parseTheme("nope")).toBeNull();
    const r = sanitizeBranding({ white_label: true, theme: { accent: "#f59e0b", evil: "x" } });
    expect("error" in r ? null : r.branding.theme).toEqual({ accent: "#f59e0b" });
  });

  it("a white-label org's brand carries its theme; the platform carries none", () => {
    expect(PLATFORM_BRAND.theme).toBeNull();
    const b = brandFromOrg({ id: "o1", name: "X", branding: { white_label: true, theme: { accent: "#f59e0b" } } });
    expect(b.theme).toEqual({ accent: "#f59e0b" });
    expect(brandFromOrg({ id: "o1", name: "X", branding: { white_label: false, theme: { accent: "#f59e0b" } } }).theme).toBeNull();
  });

  it("font, corners and button style are tokens too", () => {
    const v = themeVars({ font: "heebo", radius: "round", buttons: "flat" });
    expect(v["--font-sans"]).toBe("var(--font-heebo)");
    expect(v["--radius-lg"]).toBe("0.75rem");
    expect(v["--glow-alpha"]).toBe("0");
    // defaults are not stored
    expect(parseTheme({ font: "inter", radius: "default", buttons: "glow" })).toBeNull();
    expect(parseTheme({ font: "comic-sans" })).toBeNull();
  });

  it("text on the accent is dark on a light accent and white on a dark one", () => {
    expect(themeVars({ accent: "#f5b83d" })["--on-accent"]).toBe("7 11 20");
    expect(themeVars({ accent: "#1e3a8a" })["--on-accent"]).toBe("255 255 255");
  });

  it("a light background is refused (the app is dark-only), by parse and by the super-admin save", () => {
    expect(parseTheme({ background: "#ffffff" })).toBeNull();
    const r = sanitizeBranding({ white_label: true, theme: { background: "#f1f5f9" } });
    expect("error" in r).toBe(true);
  });

  it("every preset is readable: accent clears 3:1 on its background, no warnings", () => {
    for (const p of THEME_PRESETS) {
      expect(themeWarnings(p.theme), p.id).toEqual([]);
      if (p.theme.accent) expect(contrastRatio(p.theme.accent, tokenHex(p.theme, "--bg")), p.id).toBeGreaterThan(3);
    }
  });

  it("warns on accents that clash with severity meaning", () => {
    expect(themeWarnings({ accent: "#ef4444" }).join(" ")).toMatch(/Critical/);
    expect(themeWarnings({ accent: "#22c55e" }).join(" ")).toMatch(/benign/);
  });
});
