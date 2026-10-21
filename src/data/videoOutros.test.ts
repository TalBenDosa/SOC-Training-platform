import { describe, it, expect } from "vitest";
import { hasPlatformOutro, videoSlug, VIDEOS_WITHOUT_OUTRO } from "./videoOutros";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

describe("video outros", () => {
  it("reads the slug from a lesson-video address", () => {
    expect(videoSlug("https://x.supabase.co/storage/v1/object/public/lesson-videos/sentinelone-console/sentinelone-console.mp4")).toBe("sentinelone-console");
    expect(videoSlug("/other/file.mp4")).toBeNull();
  });
  it("the 8 first-batch videos play to their end; the rest stop before the outro", () => {
    expect(hasPlatformOutro("https://x/lesson-videos/sentinelone-console/a.mp4")).toBe(false);
    expect(hasPlatformOutro("https://x/lesson-videos/osi-model/a.mp4")).toBe(true);
  });
  it("every listed video still exists (a stale entry would silently cut content)", () => {
    // Videos are linked from lessonVideos.ts and inline from lesson/room content files.
    const files: string[] = [];
    const walk = (d: string) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else if (p.endsWith(".ts") && !p.endsWith(".test.ts")) files.push(p); } };
    walk(join(process.cwd(), "src", "data"));
    const slugs = new Set<string>();
    for (const f of files) for (const m of readFileSync(f, "utf8").matchAll(/\/lesson-videos\/([^/?#"'`]+)\/[^"'`]+\.mp4/g)) slugs.add(m[1]);
    for (const s of VIDEOS_WITHOUT_OUTRO) expect(slugs.has(s), s).toBe(true);
  });
});
