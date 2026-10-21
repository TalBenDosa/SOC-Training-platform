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

/**
 * The part of the image that is the logo: transparent margins (or a flat border in the corner
 * colour) are cut off, so a logo exported on a big empty canvas still fills the logo slot.
 * Returns the source rectangle in the image's own pixels.
 */
export function contentBox(px: Uint8ClampedArray, w: number, h: number): { x: number; y: number; w: number; h: number } {
  const transparentBg = px[3] < 16;
  const [r0, g0, b0] = [px[0], px[1], px[2]];
  const isContent = (i: number) => transparentBg
    ? px[i + 3] >= 16
    : px[i + 3] >= 16 && Math.abs(px[i] - r0) + Math.abs(px[i + 1] - g0) + Math.abs(px[i + 2] - b0) > 36;
  let minX = w, minY = h, maxX = -1, maxY = -1;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      if (!isContent((y * w + x) * 4)) continue;
      if (x < minX) minX = x; if (x > maxX) maxX = x;
      if (y < minY) minY = y; if (y > maxY) maxY = y;
    }
  }
  if (maxX < 0) return { x: 0, y: 0, w, h }; // nothing found: keep the whole image
  const pad = Math.round(Math.max(maxX - minX, maxY - minY) * 0.03);
  const x = Math.max(0, minX - pad), y = Math.max(0, minY - pad);
  return { x, y, w: Math.min(w, maxX + pad + 1) - x, h: Math.min(h, maxY + pad + 1) - y };
}

export async function prepareLogo(file: File, maxBytes = LOGO_MAX_BYTES): Promise<string> {
  if (!file.type.startsWith("image/")) throw new Error("Choose an image file (PNG, JPEG, WebP or SVG).");
  const url = URL.createObjectURL(file);
  try {
    const img = await loadImage(url);
    // An SVG without width/height reports 0: draw it at 512 px.
    const iw = img.naturalWidth || 512, ih = img.naturalHeight || 512;
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) throw new Error("This browser can't process images.");
    // Find the logo inside its margins on a working copy (at most 1024 px), in image pixels.
    const ws = Math.min(1, 1024 / Math.max(iw, ih));
    canvas.width = Math.max(1, Math.round(iw * ws));
    canvas.height = Math.max(1, Math.round(ih * ws));
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    const box = contentBox(ctx.getImageData(0, 0, canvas.width, canvas.height).data, canvas.width, canvas.height);
    const sx = box.x / ws, sy = box.y / ws, w = box.w / ws, h = box.h / ws;
    for (const max of SIZES) {
      const scale = Math.min(1, max / Math.max(w, h));
      canvas.width = Math.max(1, Math.round(w * scale));
      canvas.height = Math.max(1, Math.round(h * scale));
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      ctx.imageSmoothingQuality = "high";
      ctx.drawImage(img, sx, sy, w, h, 0, 0, canvas.width, canvas.height);
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
