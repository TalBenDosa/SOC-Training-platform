"use client";

import React, { useState } from "react";
import { Presentation, ArrowRight } from "lucide-react";
import { SlideDeckViewer } from "@/components/lessons/SlideDeckViewer";

/**
 * The lesson's slide deck (a branded PDF), surfaced INSIDE the lesson reader.
 *
 * View-only: clicking the card opens the deck in the shared in-app
 * SlideDeckViewer (a same-origin blob: iframe). There is no download — lesson
 * presentations are for viewing, not distribution. The full catalogue also
 * lives in College Materials (/resources).
 */
export interface LessonSlidesData {
  /** Absolute https URL in this project's Supabase Storage bucket. */
  src: string;
  pages: number;
}

export function LessonSlides({ slides, title }: { slides: LessonSlidesData; title: string }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        className="group flex w-full items-center gap-4 rounded-xl border border-border bg-gradient-to-br from-bg-panel to-bg-panel px-4 py-3.5 text-left transition-colors hover:border-cyber-500/50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400"
      >
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-lg border border-cyber-500/30 bg-cyber-500/10 text-cyber-300 shadow-[0_0_24px_-6px_rgb(var(--cyber-400)/0.5)] transition group-hover:bg-cyber-500/20">
          <Presentation className="h-5 w-5" />
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[14px] font-semibold text-white">Lesson slides</span>
          <span className="block text-[12px] text-slate-400">
            View this lesson as a presentation · {slides.pages} slides
          </span>
        </span>
        <span className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-cyber-500/40 bg-cyber-500/10 px-3 py-1.5 text-[12px] font-semibold text-cyber-200 transition group-hover:bg-cyber-500/20">
          View slides <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" />
        </span>
      </button>

      {open && (
        <SlideDeckViewer
          deck={{ src: slides.src, title, pages: slides.pages }}
          onClose={() => setOpen(false)}
        />
      )}
    </>
  );
}
