/**
 * Turn whatever logo file a super-admin picks (any size, PNG / JPEG / WebP / SVG / GIF…) into a
 * stored-logo data URL the server accepts (LOGO_DATA_URL, at most LOGO_MAX_BYTES): drawn on a
 * canvas, scaled down to fit, encoded as WebP (PNG where the browser can't encode WebP).
 * An SVG is rasterised here, so only a raster image is ever stored and served. Browser-only.
 */
import { LOGO_MAX_BYTES } from "./brand";

const SIZES = [640, 512, 384, 256, 192];
const QUALITIES = [0.92, 0.85, 0.75, 0.65];

/** Bytes a base64 data URL decodes to. */
export function dataUrlBytes(d: string): number {
  return Math.floor((d.length - d.indexOf(",") - 1) * 3 / 4);
}

function loadImage(url: string): Promise<HTMLImageElement> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = () => reject(new Error("That file couldn't be read as an image."));
    img.src = url;
  });
}

export async function prepareLogo(file: File, maxBytes = LOGO_MAX_BYTES): Promise<string> {
  if (!file.type.startsWith("image/")) throw new Error("Choose an image file (PNG, JPEG, WebP or SVG).");
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    // An SVG without width/height reports 0: draw it at 512 px.
    const w = img.naturalWidth || 512, h = img.naturalHeight || 512;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("This browser can't process images.");
    for (const max of SIZES) {
      const scale = Math.min(1, max / Math.max(w, h));
      canvas.width = Math.max(1, Math.round(w * scale));
      canvas.height = Math.max(1, Math.round(h * scale));
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.imageSmoothingQuality = "high";
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      for (const q of QUALITIES) {
        const d = canvas.toDataURL("image/webp", q);
        if (!d.startsWith("data:image/webp")) break; // no WebP encoder (older Safari): fall back to PNG
        if (dataUrlBytes(d) <= maxBytes) return d;
      }
      const png = canvas.toDataURL("image/png");
      if (dataUrlBytes(png) <= maxBytes) return png;
    }
    throw new Error("Couldn't make this image small enough. Try a simpler logo.");
  } finally {
    URL.revokeObjectURL(url);
  }
}
