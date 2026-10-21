/**
 * White label for same-origin HTML the app embeds (the lesson slide decks in /public): swap the
 * platform lockups (the cover's stacked logo AND the small mark in every slide's corner) for the
 * organization's logo / name, the platform name in text for the product name, and the deck's
 * colour variables for the tenant theme's. Runs in the parent page on the iframe's document
 * once it has loaded.
 */
import type { Brand } from "./brand";
import { tokenHex } from "./theme";

const PLATFORM_TEXT = /hack\s+the\s+soc/gi;

/** Every element that draws the platform logo: the labelled lockups and each slide's corner mark. */
const LOCKUPS = '[aria-label="Hack The SOC"], [aria-label="HACK THE SOC"], .lockup-stacked, .lockup-mini';

/** The decks' own palette variables → the theme tokens they mirror. */
const DECK_ACCENT: Record<string, string> = { "--cyan": "--cyber-400", "--cyan-2": "--cyber-200", "--cyan-ink": "--on-accent" };
const DECK_SURFACES: Record<string, string> = {
  "--bg": "--bg", "--bg-2": "--bg-elevated", "--panel": "--bg-panel", "--panel-2": "--bg-hover", "--line": "--border", "--line-2": "--border-strong",
};

/** The height the platform mark had, even on a slide that isn't showing (no layout box). */
function markHeight(el: HTMLElement, doc: Document): number {
  const mark = el.querySelector("svg");
  const drawn = mark?.getBoundingClientRect().height ?? 0;
  if (drawn > 0) return Math.round(drawn);
  const css = mark ? parseFloat(doc.defaultView?.getComputedStyle(mark).height ?? "") : NaN;
  return Number.isFinite(css) && css > 0 ? Math.round(css) : 38;
}

export function rebrandDocument(doc: Document, brand: Brand): void {
  if (!brand.whiteLabel) return;
  doc.querySelectorAll<HTMLElement>(LOCKUPS).forEach(el => {
    if (!el.isConnected) return; // inside a lockup already replaced
    const h = Math.max(16, markHeight(el, doc));
    if (el.hasAttribute("aria-label")) el.setAttribute("aria-label", brand.productName);
    el.replaceChildren();
    el.style.display = "inline-flex";
    el.style.alignItems = "center";
    el.style.gap = `${Math.round(h / 3)}px`;
    if (brand.logoSrc) {
      const img = doc.createElement("img");
      img.src = brand.logoSrc;
      img.alt = "";
      img.style.cssText = `height:${h}px;width:auto;max-width:${h * 5}px;object-fit:contain`;
      el.appendChild(img);
    }
    if (!(brand.logoSrc && brand.logoHasName)) {
      const name = doc.createElement("span");
      name.textContent = brand.productName;
      name.style.cssText = `font-weight:700;font-size:${Math.round(h * 0.55)}px;line-height:1;white-space:nowrap`;
      el.appendChild(name);
    }
  });
  const walker = doc.createTreeWalker(doc.body, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (n.nodeValue && PLATFORM_TEXT.test(n.nodeValue)) n.nodeValue = n.nodeValue.replace(PLATFORM_TEXT, brand.productName);
    PLATFORM_TEXT.lastIndex = 0;
  }
  doc.querySelectorAll<HTMLElement>("[aria-label], [title], [alt]").forEach(el => {
    for (const attr of ["aria-label", "title", "alt"]) {
      const v = el.getAttribute(attr);
      if (v && PLATFORM_TEXT.test(v)) el.setAttribute(attr, v.replace(PLATFORM_TEXT, brand.productName));
      PLATFORM_TEXT.lastIndex = 0;
    }
  });
  doc.querySelectorAll<HTMLMetaElement>("meta[content]").forEach(m => {
    if (PLATFORM_TEXT.test(m.content)) m.content = m.content.replace(PLATFORM_TEXT, brand.productName);
    PLATFORM_TEXT.lastIndex = 0;
  });
  doc.title = doc.title.replace(PLATFORM_TEXT, brand.productName);
  // The tenant's colours: the deck reads its palette from variables, so set them on its root.
  const theme = brand.theme;
  const root = doc.documentElement;
  if (theme?.accent) for (const [v, t] of Object.entries(DECK_ACCENT)) root.style.setProperty(v, tokenHex(theme, t));
  if (theme?.background) for (const [v, t] of Object.entries(DECK_SURFACES)) root.style.setProperty(v, tokenHex(theme, t));
}
