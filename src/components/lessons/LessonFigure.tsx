import React from "react";

/**
 * A still image inside a lesson section — the escape hatch for the things a
 * Mermaid diagram genuinely cannot express: an annotated console mockup, a
 * packet/header layout, a log-line anatomy call-out.
 *
 * SHARED ON PURPOSE. There are two lesson readers — the modal on /learn and the
 * route at /learn/[slug]/[lesson] — and they have silently drifted before: the
 * `codeExample` field was rendered in one and dropped in the other, so the same
 * lesson taught different material depending on how you reached it (see the
 * comment in learn/page.tsx). An image field would drift the same way if each
 * reader hand-rolled its own <figure>, so both import this instead.
 *
 * `alt` is required, not optional. An image worth adding is an image worth
 * describing — for screen readers, and because being forced to write the alt
 * text is what stops a decorative image being added for its own sake.
 */
export interface LessonImage {
  /** Same-origin path under /public (e.g. "/lesson-images/edr/falcon.svg"),
   *  or a data: URI. CSP permits self/data/https for img-src (next.config). */
  src: string;
  alt: string;
  caption?: string;
  /** Source/licence line. Required by the content gate for anything we did not
   *  author ourselves, so a third-party asset can never ship uncredited. */
  credit?: string;
}

export function LessonFigure({ image }: { image: LessonImage }) {
  if (!image?.src) return null;
  return (
    <figure className="overflow-hidden rounded-lg border border-border bg-bg">
      {/* Plain <img>, not next/image: these are hand-authored SVGs of known,
          small size served from the same origin, so next/image's remote
          optimisation pipeline buys nothing and its required width/height
          props would just be one more thing to keep in sync per asset. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={image.src}
        alt={image.alt}
        loading="lazy"
        className="mx-auto max-h-[460px] w-full object-contain"
      />
      {(image.caption || image.credit) && (
        <figcaption className="border-t border-border px-3 py-2 text-center text-[11px] text-slate-400">
          {image.caption}
          {image.credit && (
            <span className="block text-[10px] text-slate-500">{image.credit}</span>
          )}
        </figcaption>
      )}
    </figure>
  );
}
