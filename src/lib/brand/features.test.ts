import { describe, it, expect } from "vitest";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { ALL_FEATURES, FEATURES, FEATURE_KEYS, featureForPath, parseFeatures, sanitizeFeatures } from "./features";
import { brandFromOrg, cleanLink, parseLinks, PLATFORM_BRAND } from "./brand";
import { sanitizeBranding } from "./sanitize";

describe("tenant plan features", () => {
  it("missing = on: existing organizations keep everything", () => {
    expect(parseFeatures(undefined)).toEqual(ALL_FEATURES);
    expect(parseFeatures({ team_training: false }).team_training).toBe(false);
    expect(parseFeatures({ team_training: "no" }).team_training).toBe(true);
  });

  it("only switched-off known features are stored", () => {
    expect(sanitizeFeatures({ ...ALL_FEATURES })).toBeNull();
    expect(sanitizeFeatures({ live_soc: false, evil: false })).toEqual({ live_soc: false });
  });

  it("maps every gated route to its feature, and leaves the rest open", () => {
    expect(featureForPath("/dashboard")).toBe("live_soc");
    expect(featureForPath("/edr")).toBe("live_soc");
    expect(featureForPath("/team/abc")).toBe("team_training");
    expect(featureForPath("/teams")).toBeNull();
    expect(featureForPath("/progress")).toBeNull();
  });

  it("every feature route's layout enforces the plan on the server", () => {
    for (const k of FEATURE_KEYS) {
      for (const r of FEATURES[k].routes) {
        const f = join(process.cwd(), "src", "app", "(app)", r.slice(1), "layout.tsx");
        expect(existsSync(f), f).toBe(true);
        expect(readFileSync(f, "utf8"), f).toContain(`requireFeature("${k}")`);
      }
    }
  });
});

describe("tenant links", () => {
  it("https only; privacy falls back to the platform page", () => {
    expect(cleanLink("javascript:alert(1)")).toBeNull();
    expect(cleanLink("http://x.com/p")).toBeNull();
    expect(cleanLink("https://college.ac.il/privacy")).toBe("https://college.ac.il/privacy");
    expect(parseLinks({ terms: "https://c.ac.il/t" })).toEqual({ privacy: "/privacy", terms: "https://c.ac.il/t", help: null });
  });

  it("a white-label org carries its links; the platform has its own", () => {
    expect(PLATFORM_BRAND.links.privacy).toBe("/privacy");
    const b = brandFromOrg({ id: "o1", name: "X", branding: { white_label: true, links: { help: "https://h.example.com" } } });
    expect(b.links.help).toBe("https://h.example.com");
  });

  it("the super-admin save refuses a non-https link instead of dropping it", () => {
    const r = sanitizeBranding({ white_label: true, links: { help: "ftp://x" } });
    expect("error" in r).toBe(true);
  });
});
