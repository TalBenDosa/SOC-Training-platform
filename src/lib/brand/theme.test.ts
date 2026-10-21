import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { ACCENT_STEPS, DEFAULT_TOKENS, parseTheme, themeCss, themeVars } from "./theme";
import { brandFromOrg, PLATFORM_BRAND } from "./brand";
import { sanitizeBranding } from "./sanitize";

describe("theme tokens", () => {
  it("globals.css :root declares exactly the default palette (the platform's look is unchanged)", () => {
    const css = readFileSync(join(process.cwd(), "src", "app", "globals.css"), "utf8");
    for (const [name, value] of Object.entries(DEFAULT_TOKENS)) {
      const m = new RegExp(`${name.replace(/[-]/g, "\\-")}:\\s*([0-9 ]+);`).exec(css);
      expect(m?.[1].trim(), name).toBe(value);
    }
  });

  it("an accent colour becomes a full 50-900 scale, with 400 = the colour itself", () => {
    const vars = themeVars({ accent: "#f59e0b" });
    expect(Object.keys(vars)).toEqual(ACCENT_STEPS.map(s => `--cyber-${s}`));
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
});
