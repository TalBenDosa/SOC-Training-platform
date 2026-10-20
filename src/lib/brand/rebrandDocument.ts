/**
 * White label for same-origin HTML the app embeds (the lesson slide decks in /public): swap the
 * platform lockup for the organization's logo / name and the platform name in text for the
 * product name. Runs in the parent page on the iframe's document once it has loaded.
 */
import type { Brand } from "./brand";

const PLATFORM_TEXT = /hack\s+the\s+soc/gi;

export function rebrandDocument(doc: Document, brand: Brand): void {
  if (!brand.whiteLabel) return;
  doc.querySelectorAll<HTMLElement>('[aria-label="Hack The SOC"], [aria-label="HACK THE SOC"]').forEach(el => {
    // Keep the lockup's size: the logo takes the height the platform mark had.
    const mark = el.querySelector("svg");
    const h = Math.max(16, Math.round(mark?.getBoundingClientRect().height || 28));
    el.setAttribute("aria-label", brand.productName);
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
}
