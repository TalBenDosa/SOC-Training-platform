"use client";

import React, { useEffect, useRef, useState } from "react";
import { Download, Expand, Loader2, Presentation } from "lucide-react";

/**
 * The lesson's slide deck (a branded PDF), shown INSIDE the lesson reader.
 *
 * The PDF lives in this project's public Supabase Storage bucket. It is pulled
 * over connect-src and handed to the browser's own PDF viewer as a same-origin
 * blob: URL in an iframe, the same pattern the College Materials viewer uses, so
 * the page CSP (frame-src 'self' blob:) needs no new origin. Phones and tablets
 * whose browsers cannot render a PDF inline (navigator.pdfViewerEnabled false)
 * get an open/download button instead of an empty frame.
 */
export interface LessonSlidesData {
  /** Absolute https URL in this project's Supabase Storage bucket. */
  src: string;
  pages: number;
}

export function LessonSlides({ slides, title }: { slides: LessonSlidesData; title: string }) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [inline, setInline] = useState(true);
  const frameRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const nav = navigator as Navigator & { pdfViewerEnabled?: boolean };
    if (nav.pdfViewerEnabled === false) { setInline(false); return; }
    let url: string | null = null;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(slides.src);
        if (!res.ok) throw new Error(String(res.status));
        const blob = new Blob([await res.arrayBuffer()], { type: "application/pdf" });
        url = URL.createObjectURL(blob);
        if (cancelled) { URL.revokeObjectURL(url); return; }
        setBlobUrl(url);
      } catch {
        if (!cancelled) setFailed(true);
      }
    })();
    return () => { cancelled = true; if (url) URL.revokeObjectURL(url); };
  }, [slides.src]);

  const fileName = `${title.replace(/[^\w\s-]/g, "").trim().replace(/\s+/g, "-").slice(0, 80) || "lesson"}-slides.pdf`;

  function fullScreen() {
    const el = frameRef.current;
    if (el?.requestFullscreen) el.requestFullscreen().catch(() => { /* not allowed */ });
  }

  return (
    <section aria-labelledby="lesson-slides-h" className="overflow-hidden rounded-xl border border-[#1e2d4a] bg-[#0d1322]">
      <div className="flex flex-wrap items-center gap-3 border-b border-[#1e2d4a] px-4 py-3">
        <Presentation className="h-4 w-4 shrink-0 text-cyan-400" aria-hidden="true" />
        <h3 id="lesson-slides-h" className="text-[13px] font-semibold text-white">
          Lesson slides <span className="font-normal text-slate-400">· {slides.pages} pages</span>
        </h3>
        <div className="ml-auto flex items-center gap-2">
          {inline && blobUrl && (
            <button
              type="button"
              onClick={fullScreen}
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#2a3555] px-2.5 py-1.5 text-[12px] font-medium text-slate-300 transition-colors hover:border-cyan-500/50 hover:text-cyan-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
            >
              <Expand className="h-3.5 w-3.5" aria-hidden="true" /> Full screen
            </button>
          )}
          <a
            href={blobUrl ?? slides.src}
            download={blobUrl ? fileName : undefined}
            target={blobUrl ? undefined : "_blank"}
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-[12px] font-semibold text-cyan-200 transition-colors hover:bg-cyan-500/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyan-400"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" /> {inline ? "Download PDF" : "Open slides (PDF)"}
          </a>
        </div>
      </div>

      {inline && (
        <div ref={frameRef} className="relative aspect-[16/10] w-full bg-[#020a18]">
          {blobUrl ? (
            <iframe
              src={`${blobUrl}#view=FitH&navpanes=0`}
              title={`${title}: lesson slides`}
              className="absolute inset-0 h-full w-full border-0"
            />
          ) : (
            <div className="absolute inset-0 flex items-center justify-center gap-2 text-[13px] text-slate-400" role="status">
              {failed
                ? <span>The slides could not be loaded. Use the button above to open them.</span>
                : <><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Loading slides…</>}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
