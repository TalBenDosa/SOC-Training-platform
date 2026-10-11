import { describe, it, expect } from "vitest";
import { measureMetaCells, certificateFooter, type MeasureCtx } from "./renderCertificate";
import { ROOT_ORG_ID } from "@/lib/org/rootEnvironment";

/** Fake 2D context whose text width depends on the CURRENT font size — like a real canvas. */
function fakeCtx(): MeasureCtx {
  return {
    font: "10px sans",
    measureText(text: string) {
      const px = Number(/(\d+)px/.exec(this.font)?.[1] ?? 10);
      return { width: text.length * px * 0.6 };
    },
  };
}

const VALUE_FONT = `800 26px "Mono", monospace`;
const LABEL_FONT = `700 13px "Sans"`;

describe("measureMetaCells (#32 overlap)", () => {
  const cells = [
    { v: "1,500 XP", l: "MILESTONE" },
    { v: "28 Sep 2026", l: "ACHIEVED" },
    { v: "Incident Response", l: "TRACK" },
  ];

  it("measures EVERY value in the value font (not the label font left over from the previous cell)", () => {
    const ctx = fakeCtx();
    const widths = measureMetaCells(ctx, cells, VALUE_FONT, LABEL_FONT, 2);
    const valueW = (s: string) => s.length * 26 * 0.6;
    // Each cell is at least as wide as its value at 26px — the old code measured
    // cells 2 and 3 at 13px, so "28 Sep 2026" got half its real width.
    cells.forEach((c, i) => expect(widths[i]).toBeGreaterThanOrEqual(valueW(c.v)));
  });

  it("gives the same widths regardless of the font the context starts in", () => {
    const a = fakeCtx(); a.font = LABEL_FONT;
    const b = fakeCtx(); b.font = VALUE_FONT;
    expect(measureMetaCells(a, cells, VALUE_FONT, LABEL_FONT, 2)).toEqual(measureMetaCells(b, cells, VALUE_FONT, LABEL_FONT, 2));
  });

  it("uses the tracked label width when the label is wider than the value", () => {
    const ctx = fakeCtx();
    const [w] = measureMetaCells(ctx, [{ v: "1", l: "MILESTONE" }], VALUE_FONT, LABEL_FONT, 2);
    expect(w).toBeCloseTo(9 * 13 * 0.6 + 8 * 2);
  });
});

describe("certificateFooter", () => {
  it("prints the production domain, never the vercel alias", () => {
    const f = certificateFooter(null, null);
    expect(f).toContain("www.hackthesoc.app");
    expect(f).not.toMatch(/vercel\.app/);
  });
  it("names a real org as issuer, and the platform otherwise (never 'Individual')", () => {
    expect(certificateFooter("org-1", "Cyber College")).toContain("Issued by Cyber College");
    expect(certificateFooter("org-1", "Individual")).toContain("Issued by HACK THE SOC");
    expect(certificateFooter(ROOT_ORG_ID, "Whatever")).toContain("Issued by HACK THE SOC");
  });
});
