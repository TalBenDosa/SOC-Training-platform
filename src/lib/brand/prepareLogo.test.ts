import { describe, it, expect } from "vitest";
import { contentBox } from "./prepareLogo";

/** A w×h RGBA image filled with `bg`, with a `fg` rectangle at (x, y, rw, rh). */
function image(w: number, h: number, bg: number[], fg: number[], x: number, y: number, rw: number, rh: number) {
  const px = new Uint8ClampedArray(w * h * 4);
  for (let j = 0; j < h; j++) for (let i = 0; i < w; i++) {
    const c = i >= x && i < x + rw && j >= y && j < y + rh ? fg : bg;
    px.set(c, (j * w + i) * 4);
  }
  return px;
}

describe("contentBox (logo margin trim)", () => {
  it("cuts a transparent margin down to the logo, with a small pad", () => {
    const b = contentBox(image(200, 200, [0, 0, 0, 0], [40, 120, 220, 255], 60, 70, 80, 50), 200, 200);
    expect(b.x).toBeLessThanOrEqual(60); expect(b.x).toBeGreaterThan(50);
    expect(b.y).toBeLessThanOrEqual(70); expect(b.y).toBeGreaterThan(60);
    expect(b.w).toBeGreaterThanOrEqual(80); expect(b.w).toBeLessThan(100);
    expect(b.h).toBeGreaterThanOrEqual(50); expect(b.h).toBeLessThan(70);
  });
  it("cuts a flat-colour border the same way", () => {
    const b = contentBox(image(100, 100, [44, 67, 102, 255], [255, 255, 255, 255], 30, 30, 40, 40), 100, 100);
    expect(b.w).toBeLessThan(50); expect(b.h).toBeLessThan(50);
  });
  it("keeps the whole image when there's nothing to cut or nothing drawn", () => {
    expect(contentBox(image(10, 10, [0, 0, 0, 0], [0, 0, 0, 0], 0, 0, 0, 0), 10, 10)).toEqual({ x: 0, y: 0, w: 10, h: 10 });
    expect(contentBox(image(10, 10, [9, 9, 9, 255], [200, 0, 0, 255], 0, 0, 10, 10), 10, 10)).toEqual({ x: 0, y: 0, w: 10, h: 10 });
  });
});
