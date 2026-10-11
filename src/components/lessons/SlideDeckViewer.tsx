"use client";

import React, { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Expand, Loader2, X, AlertTriangle, Presentation } from "lucide-react";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";

/**
 * View-only, in-app viewer for a Learning Path slide deck (a branded PDF).
 *
 * Mirrors the College Materials ResourceViewer: the PDF is pulled over
 * connect-src and shown as a same-origin blob: <iframe>, so the storage URL
 * never lands in the DOM and the page CSP (frame-src 'self' blob:) needs no new
 * origin. There is deliberately NO download control — presentations are
 * view-only. Phones/tablets whose browser cannot render a PDF inline see a
 * clear notice instead of an empty frame (we never hand out the raw URL).
 */
export interface SlideDeckRef {
  src: string;
  title: string;
  pages: number;
}

export function SlideDeckViewer({ deck, onClose }: { deck: SlideDeckRef; onClose: () => void }) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [canInline] = useState(() => {
    const nav = typeof navigator !== "undefined" ? (navigator as Navigator & { pdfViewerEnabled?: boolean }) : undefined;
    return nav?.pdfViewerEnabled !== false;
  });
  const panelRef = useRef<HTMLDivElement>(null);
  const blobRef = useRef<string | null>(null);
  useFocusTrap(true, panelRef);

  useEffect(() => {
    if (!canInline) return;
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(deck.src);
        if (!res.ok) throw new Error(String(res.status));
        const url = URL.createObjectURL(new Blob([await res.arrayBuffer()], { type: "application/pdf" }));
        if (cancelled) { URL.revokeObjectURL(url); return; }
        blobRef.current = url;
        setBlobUrl(url);
      } catch {
        if (!cancelled) setError("These slides couldn't be loaded. Close and open them again.");
      }
    })();
    return () => { cancelled = true; if (blobRef.current) { URL.revokeObjectURL(blobRef.current); blobRef.current = null; } };
  }, [deck.src, canInline]);

  // Escape to close + lock the page scroll while the viewer is open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  function fullScreen() {
    const el = panelRef.current;
    if (document.fullscreenElement) { document.exitFullscreen().catch(() => {}); return; }
    el?.requestFullscreen?.().catch(() => {});
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
        className="flex h-[92vh] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-cyber-500/30 bg-[#0b0f1e] shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex shrink-0 items-center gap-3 border-b border-[#1e2d4a] bg-[#0d1322] px-4 py-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyber-500/40 bg-cyber-500/10 text-cyber-300">
            <Presentation className="h-4 w-4" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-white">{deck.title}</p>
            <p className="text-[11px] text-slate-500">Lesson slides · {deck.pages} pages</p>
          </div>
          {canInline && blobUrl && (
            <button
              type="button"
              onClick={fullScreen}
              className="flex items-center gap-1.5 rounded-lg border border-[#2a3555] px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-cyber-500/50 hover:text-cyber-300 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
            >
              <Expand className="h-3.5 w-3.5" /> Full screen
            </button>
          )}
          <button
            onClick={onClose}
            aria-label="Close"
            className="flex h-8 w-8 items-center justify-center rounded-lg border border-[#2a3555] bg-[#0d1322] text-slate-400 transition hover:border-severity-high/50 hover:text-severity-high focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="relative flex-1 bg-[#020a18]">
          {!canInline ? (
            <ViewerNotice title="Open on a larger screen" body="Your browser can't display these slides inline. Open this lesson on a desktop browser to view the full presentation." />
          ) : error ? (
            <ViewerNotice title={error} icon />
          ) : blobUrl ? (
            <iframe src={`${blobUrl}#toolbar=0&navpanes=0`} title={`${deck.title}: slides`} className="absolute inset-0 h-full w-full border-0" />
          ) : (
            <div className="flex h-full items-center justify-center gap-2 text-sm text-slate-400" role="status">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading slides…
            </div>
          )}
        </div>
      </div>
    </div>
  );

  if (typeof document === "undefined") return null;
  return createPortal(node, document.body);
}

function ViewerNotice({ title, body, icon }: { title: string; body?: string; icon?: boolean }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      {icon && <AlertTriangle className="h-8 w-8 text-severity-high" />}
      <p className="text-sm font-semibold text-white">{title}</p>
      {body && <p className="max-w-sm text-xs text-slate-400">{body}</p>}
    </div>
  );
}
