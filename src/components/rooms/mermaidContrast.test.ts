import { describe, it, expect } from "vitest";
import { textColorFor, withReadableLabels } from "./mermaidContrast";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const rgb = (hex: string) => {
  let h = hex.replace("#", "");
  if (h.length === 3) h = h.split("").map(c => c + c).join("");
  const n = parseInt(h.slice(0, 6), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255].map(c => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4; });
};
const lum = (hex: string) => { const [r, g, b] = rgb(hex); return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
const contrast = (a: string, b: string) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

describe("mermaid label contrast", () => {
  it("a pale fill gets dark text, a dark fill light text", () => {
    expect(textColorFor("#fff3cd")).toBe("#0f172a");
    expect(textColorFor("#f8d7da")).toBe("#0f172a");
    expect(textColorFor("#3a2a06")).toBe("#e2e8f0");
    expect(textColorFor("#fff")).toBe("#0f172a");
  });

  it("adds a color only where a style or classDef sets a fill without one", () => {
    const chart = "flowchart TD\n  A --> B\n  style A fill:#fff3cd\n  style B fill:#3b0d16,color:#fecdd3\n  classDef warn fill:#f8d7da,stroke:#f43f5e;\n";
    const out = withReadableLabels(chart);
    expect(out).toContain("style A fill:#fff3cd,color:#0f172a");
    expect(out).toContain("style B fill:#3b0d16,color:#fecdd3");
    expect(out).toContain("classDef warn fill:#f8d7da,stroke:#f43f5e,color:#0f172a");
    expect(out).toContain("A --> B");
  });

  it("leaves a chart without styles untouched", () => {
    const chart = "sequenceDiagram\n  A->>B: hello\n";
    expect(withReadableLabels(chart)).toBe(chart);
  });
});

// Guard for authored content: a diagram node that sets both a fill and a text colour must keep them
// readable together (WCAG AA, 4.5:1). A fill without a colour is handled by withReadableLabels.
describe("lesson diagrams", () => {
  it("every authored node fill + text colour pair reads (4.5:1)", () => {
    const dir = join(process.cwd(), "src", "data");
    const bad: string[] = [];
    for (const f of readdirSync(dir).filter(n => n.endsWith(".ts"))) {
      const text = readFileSync(join(dir, f), "utf8");
      for (const m of text.matchAll(/(?:style|classDef) (\S+) ([^"\\`\n]*)/g)) {
        const fill = /fill:\s*(#[0-9a-fA-F]{3,6})\b/.exec(m[2])?.[1];
        const color = /color:\s*(#[0-9a-fA-F]{3,6})\b/.exec(m[2])?.[1];
        if (fill && color && contrast(fill, color) < 4.5) bad.push(`${f}: ${m[1]} ${fill} / ${color}`);
      }
    }
    expect(bad).toEqual([]);
  });
});
