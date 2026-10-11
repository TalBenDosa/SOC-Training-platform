// QA phase 7, E-15: Latin text goes through jsPDF's font; anything its WinAnsi
// fonts can't carry (a Hebrew name) is drawn by canvas and placed as an image.
import { describe, it, expect, vi } from "vitest";
import { needsCanvas, pdfText } from "./pdfText";

describe("needsCanvas", () => {
  it.each([
    ["Jane O'Brien", false], ["José Müller", false], ["Issued by X  •  SOC  •  host…", false],
    ["טל בן דוסא", true], ["Dana כהן", true], ["Анна", true],
  ])("%s → %s", (s, want) => expect(needsCanvas(s)).toBe(want));
});

describe("pdfText", () => {
  const fakePdf = () => ({ setFont: vi.fn(), setFontSize: vi.fn(), setTextColor: vi.fn(), text: vi.fn(), addImage: vi.fn() });

  it("Latin → pdf.text at the baseline, centred", () => {
    const pdf = fakePdf();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    pdfText(pdf as any, "Jane Doe", 148.5, 88, { size: 28, bold: true, rgb: [255, 255, 255], align: "center" });
    expect(pdf.text).toHaveBeenCalledWith("Jane Doe", 148.5, 88, { align: "center" });
    expect(pdf.addImage).not.toHaveBeenCalled();
  });

  it("Hebrew → a canvas image centred on x, never pdf.text", () => {
    const ctx = { font: "", fillStyle: "", textBaseline: "", measureText: () => ({ width: 240 }), fillText: vi.fn() };
    const spy = vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(ctx as unknown as CanvasRenderingContext2D);
    vi.spyOn(HTMLCanvasElement.prototype, "toDataURL").mockReturnValue("data:image/png;base64,AA==");
    const pdf = fakePdf();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    pdfText(pdf as any, "טל בן דוסא", 148.5, 88, { size: 28, bold: true, rgb: [255, 255, 255], align: "center" });
    expect(pdf.text).not.toHaveBeenCalled();
    expect(ctx.fillText).toHaveBeenCalledWith("טל בן דוסא", 2, expect.any(Number));
    const [, , left, , w] = pdf.addImage.mock.calls[0];
    expect(left + w / 2).toBeCloseTo(148.5, 5);
    spy.mockRestore();
  });
});
