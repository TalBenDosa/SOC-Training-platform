// @vitest-environment jsdom
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { rebrandDocument } from "./rebrandDocument";
import { brandFromOrg, PLATFORM_BRAND } from "./brand";

const deck = readFileSync(join(process.cwd(), "public", "lesson-decks", "active-directory-and-domain-controllers-explained.html"), "utf8");
const load = () => new DOMParser().parseFromString(deck, "text/html");
const wl = brandFromOrg({ id: "o1", name: "College", branding: { white_label: true, product_name: "College SOC", theme: { accent: "#f5b83d", background: "#12100b" } } });

describe("white-label slide decks", () => {
  it("no platform mark or name is left, on the cover or in any slide's corner", () => {
    const doc = load();
    expect(doc.querySelectorAll(".lockup-mini").length).toBeGreaterThan(10);
    rebrandDocument(doc, wl);
    expect(doc.body.textContent ?? "").not.toMatch(/HACK\s*THE\s*SOC/i);
    expect(doc.querySelectorAll(".lockup-mini svg.mark").length).toBe(0);
    expect(doc.querySelector(".lockup-mini")?.textContent).toBe("College SOC");
  });

  it("the deck takes the theme's colours", () => {
    const doc = load();
    rebrandDocument(doc, wl);
    expect(doc.documentElement.style.getPropertyValue("--cyan")).toBe("#f5b83d");
    expect(doc.documentElement.style.getPropertyValue("--bg")).toBe("#12100b");
  });

  it("the platform's own decks are untouched", () => {
    const doc = load();
    rebrandDocument(doc, PLATFORM_BRAND);
    expect(doc.querySelectorAll(".lockup-mini svg.mark").length).toBeGreaterThan(10);
  });
});
