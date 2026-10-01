import type { jsPDF } from "jspdf";

/**
 * jsPDF's built-in fonts only carry WinAnsi (Latin-1 + a few typographic marks),
 * so a Hebrew (or any non-Latin) name printed as mojibake on the certificate —
 * QA phase 7, E-15. Strings outside that set are drawn by the browser's canvas,
 * which has the system's Hebrew fonts and does the bidi shaping, and placed as
 * an image at the same spot and size the text would have had.
 */
const WIN_ANSI = /^[\x20-\x7E\xA0-\xFF–—‘’“”•…€]*$/;

export function needsCanvas(text: string): boolean {
  return !WIN_ANSI.test(text);
}

export interface PdfTextStyle {
  size: number;                       // pt, as pdf.setFontSize
  rgb: [number, number, number];
  bold?: boolean;
  align?: "left" | "center";
}

const PT_TO_MM = 0.3528;
const PX_PER_MM = 12;                 // ~300 dpi — crisp when printed

/** Draw `text` with its baseline at (x, y) mm, like pdf.text(). */
export function pdfText(pdf: jsPDF, text: string, x: number, y: number, style: PdfTextStyle): void {
  if (!needsCanvas(text)) {
    pdf.setFont("helvetica", style.bold ? "bold" : "normal");
    pdf.setFontSize(style.size);
    pdf.setTextColor(...style.rgb);
    pdf.text(text, x, y, style.align === "center" ? { align: "center" } : undefined);
    return;
  }
  const fontPx = style.size * PT_TO_MM * PX_PER_MM;
  const font = `${style.bold ? "bold " : ""}${fontPx}px "Segoe UI", Arial, "Noto Sans Hebrew", sans-serif`;
  const canvas = document.createElement("canvas");
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("canvas unavailable");
  ctx.font = font;
  const wPx = Math.ceil(ctx.measureText(text).width) + 4;
  const hPx = Math.ceil(fontPx * 1.4);
  canvas.width = wPx;
  canvas.height = hPx;
  ctx.font = font;                    // resizing the canvas resets its state
  ctx.fillStyle = `rgb(${style.rgb.join(",")})`;
  ctx.textBaseline = "alphabetic";
  ctx.fillText(text, 2, fontPx * 1.1);
  const wMm = wPx / PX_PER_MM;
  const left = style.align === "center" ? x - wMm / 2 : x;
  pdf.addImage(canvas.toDataURL("image/png"), "PNG", left, y - (fontPx * 1.1) / PX_PER_MM, wMm, hPx / PX_PER_MM);
}
