/**
 * R5 (docs/LOG-REALISM-STANDARD.md) on the Live Feed's own data files: every public IPv4 address is
 * a documentation address (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), the kept Tor exit
 * 185.220.101.45, or a well-known service used as that service. The places and network owners the
 * old real addresses stood for live in src/lib/sim/docAddresses.ts.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(__dirname, "../../../..");
const DASH = path.join(ROOT, "src/app/(app)/dashboard");
const FILES = [
  path.join(DASH, "benignEvents.ts"), path.join(DASH, "attackStories.ts"),
  ...["ai-stories", "core-stories", "web-stories"].flatMap(d => readdirSync(path.join(DASH, d)).filter(f => f.endsWith(".ts") && !f.includes(".test.")).map(f => path.join(DASH, d, f))),
  path.join(ROOT, "src/lib/sim/companyProfiles.ts"), path.join(ROOT, "src/lib/sim/maliciousEmailHeaders.ts"),
];
const OK = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|0\.|255\.|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)/;
const SERVICE = /^(13\.107\.|20\.(190|60|73)\.|40\.(97|107|112)\.|52\.(96|101|112|113|114|120|230|84|85|200|28|216)\.|54\.(192|239|175)\.|3\.120\.|142\.250\.|172\.217\.|8\.8\.[48]\.[48]$|34\.(72|107)\.|104\.(1[6-9]|2[0-7])\.|1\.1\.1\.1$|140\.82\.|185\.199\.108\.|192\.30\.252\.|151\.101\.|23\.218\.|152\.199\.|93\.184\.|170\.114\.|31\.13\.|108\.174\.|91\.189\.91\.)/;
const NOT_ADDRESS = new Set(["1.1.0.0", "2.5.5.7", "2.5.5.9", "2.5.5.12", "24.1.2.198", "24.1.3.277", "23.1.2.11"]);

describe("Live Feed data files: R5 addresses", () => {
  it("no real third-party public address outside the allowed set", () => {
    const off: string[] = [];
    for (const f of FILES) {
      readFileSync(f, "utf8").split(/\r?\n/).forEach((line, i) => {
        for (const m of line.matchAll(/(?<![\d.\w])(\d{1,3}(?:\.\d{1,3}){3})(?![\d]|\.\d)/g)) {
          const ip = m[1];
          if (ip.split(".").some(x => Number(x) > 255) || OK.test(ip) || SERVICE.test(ip) || NOT_ADDRESS.has(ip) || ip === "185.220.101.45" || /\.0\.0$/.test(ip)) continue;
          if (new RegExp(`(version|Version|agent|Agent|/|v)\\s*["':=]?\\s*${ip.replace(/\./g, "\\.")}`).test(line)) continue;
          off.push(`${path.relative(ROOT, f)}:${i + 1} ${ip}`);
        }
      });
    }
    expect(off).toEqual([]);
  });
});
