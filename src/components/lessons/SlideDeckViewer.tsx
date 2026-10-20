"use client";

import React, { useEffect, useRef, useState } from "react";
import { useBrand } from "@/lib/brand/BrandContext";
import { rebrandDocument } from "@/lib/brand/rebrandDocument";
import { createPortal } from "react-dom";
import { Expand, Loader2, X, Presentation } from "lucide-react";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";

/**
 * View-only, in-app viewer for a Learning Path slide deck.
 *
 * The deck is a self-contained HTML slideshow served same-origin from
 * /public/lesson-decks (so the page CSP's frame-src 'self' covers it). It is
 * shown directly in an <iframe> — navigation is page-by-page (arrow keys, click,
 * on-slide controls), not scrolling, and it paints instantly (no multi-MB
 * download). There is deliberately no download control: presentations are
 * view-only. `allow="fullscreen"` lets the deck's own full-screen work too.
 */
export interface SlideDeckRef {
  src: string;
  title: string;
  pages: number;
  /** Header label; lesson decks use the default. */
  kind?: string;
}

export function SlideDeckViewer({ deck, onClose }: { deck: SlideDeckRef; onClose: () => void }) {
  const [loaded, setLoaded] = useState(false);
  const brand = useBrand();
  const panelRef = useRef<HTMLDivElement>(null);
  const frameRef = useRef<HTMLIFrameElement>(null);
  useFocusTrap(true, panelRef);

  // Escape to close + lock the page scroll while the viewer is open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  // The deck navigates with arrow keys — move focus into the frame so they land
  // there as soon as it is ready, without the viewer stealing them.
  useEffect(() => { if (loaded) frameRef.current?.focus(); }, [loaded]);

  function fullScreen() {
    if (document.fullscreenElement) { document.exitFullscreen().catch(() => {}); return; }
    panelRef.current?.requestFullscreen?.().catch(() => {});
  }

  const node = (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`${deck.title}: slides`}
      onClick={onClose}
    >
      <div
        ref={panelRef}
        tabIndex={-1}
        className="flex h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-cyber-500/30 bg-[#030a18] shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center gap-3 border-b border-[#1e2d4a] bg-[#0d1322] px-4 py-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyber-500/40 bg-cyber-500/10 text-cyber-300">
            <Presentation className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-white">{deck.title}</p>
            <p className="text-[11px] text-slate-500">{deck.kind ?? "Lesson slides"} · {deck.pages} slides · arrow keys or click to move</p>
          </div>
          <button
            type="button"
            onClick={fullScreen}
            className="flex items-center gap-1.5 rounded-lg border border-[#2a3555] px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-cyber-500/50 hover:text-cyber-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
          >
            <Expand className="h-3.5 w-3.5" /> Full screen
          </button>
          <button
            onClick={onClose}
            aria-label="Close"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#2a3555] bg-[#0d1322] text-slate-400 transition hover:border-severity-high/50 hover:text-severity-high focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="relative flex-1 bg-[#030a18]">
          {!loaded && (
            <div className="absolute inset-0 flex items-center justify-center gap-2 text-sm text-slate-400" role="status">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading slides…
            </div>
          )}
          <iframe
            ref={frameRef}
            src={deck.src}
            title={`${deck.title}: slides`}
            onLoad={() => {
              // White label: the deck's platform lockup and name become the organization's
              // before the loading cover lifts (same-origin, so the parent can edit it).
              try { const d = frameRef.current?.contentDocument; if (d) rebrandDocument(d, brand); } catch { /* cross-origin: leave as is */ }
              setLoaded(true);
            }}
            allow="fullscreen"
            className="absolute inset-0 h-full w-full border-0"
          />
        </div>
      </div>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(node, document.body);
}
